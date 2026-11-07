// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package gitopshealth tests how Argo CD and Flux see the health of
// Inkwall's kinds (#377): the Lua health checks of
// examples/argocd/argocd-cm-patch.yaml, run as Argo CD runs them, against
// examples/argocd/tests/<Kind>.yaml; and Flux's kstatus, which a
// Kustomization with wait: true waits on, against the same objects. A
// module of its own, so the operator's doesn't depend on a Lua VM.
package gitopshealth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	lua "github.com/yuin/gopher-lua"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/yaml"
)

const examples = "../../examples/argocd"

type testCase struct {
	Name   string         `json:"name"`
	Want   string         `json:"want"`
	Object map[string]any `json:"object"`
}

// healthChecks are the Lua scripts of the argocd-cm patch, by kind.
func healthChecks(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(examples, "argocd-cm-patch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range cm.Data {
		if kind, ok := strings.CutPrefix(k, "resource.customizations.health.waf.inkwall.dev_"); ok {
			out[kind] = v
		}
	}
	return out
}

func cases(t *testing.T, kind string) []testCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(examples, "tests", kind+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cs []testCase
	if err := yaml.Unmarshal(raw, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

// argoHealth runs a health check as Argo CD does: obj is the object, the
// script returns a table with status and message.
func argoHealth(t *testing.T, script string, obj map[string]any) (string, string) {
	t.Helper()
	L := lua.NewState()
	defer L.Close()
	L.SetGlobal("obj", toLua(L, obj))
	if err := L.DoString(script); err != nil {
		t.Fatalf("lua: %v", err)
	}
	ret, ok := L.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("the script returned %v, not a table", L.Get(-1))
	}
	return ret.RawGetString("status").String(), ret.RawGetString("message").String()
}

func toLua(L *lua.LState, v any) lua.LValue {
	switch v := v.(type) {
	case map[string]any:
		t := L.NewTable()
		for k, e := range v {
			t.RawSetString(k, toLua(L, e))
		}
		return t
	case []any:
		t := L.NewTable()
		for _, e := range v {
			t.Append(toLua(L, e))
		}
		return t
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	}
	return lua.LNil
}

// Each kind has a check, and each case gets the health it expects.
func TestArgoCDHealth(t *testing.T) {
	checks := healthChecks(t)
	for _, kind := range []string{"WAFPolicy", "WAFRuleSet", "ClusterWAFRuleSet", "InkwallConfig"} {
		script := checks[kind]
		if script == "" {
			t.Errorf("no health check for %s", kind)
			continue
		}
		for _, c := range cases(t, kind) {
			if got, msg := argoHealth(t, script, c.Object); got != c.Want {
				t.Errorf("%s, %s: %s (%q), want %s", kind, c.Name, got, msg, c.Want)
			}
		}
	}
}

// fluxExprs are the healthCheckExprs of examples/flux/kustomization.yaml,
// by kind.
func fluxExprs(t *testing.T) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../examples/flux/kustomization.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		Spec struct {
			HealthCheckExprs []struct {
				Kind    string `json:"kind"`
				Current string `json:"current"`
				Failed  string `json:"failed"`
			} `json:"healthCheckExprs"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, e := range k.Spec.HealthCheckExprs {
		out[e.Kind] = map[string]string{"current": e.Current, "failed": e.Failed}
	}
	return out
}

// eval evaluates a healthCheckExpr on an object: its top-level fields are
// the variables (an absent status is an empty one).
func eval(t *testing.T, expr string, obj map[string]any) bool {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("metadata", cel.DynType), cel.Variable("status", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatalf("%s: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := obj["status"].(map[string]any)
	if st == nil {
		st = map[string]any{}
	}
	if _, ok := st["conditions"]; !ok {
		st["conditions"] = []any{}
	}
	out, _, err := prg.Eval(map[string]any{"metadata": obj["metadata"], "status": st})
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	return out.Value() == true
}

// Flux, with the Kustomization's healthCheckExprs and wait: true: a
// WAFPolicy is current only when Ready for its generation, failed when
// Ready is False for a reason that doesn't resolve itself, and in progress
// otherwise; so Flux waits for policies to be Ready. Plain kstatus would
// count a policy without a status yet as current: hence the expressions.
func TestFluxHealth(t *testing.T) {
	exprs := fluxExprs(t)
	for _, kind := range []string{"WAFPolicy", "WAFRuleSet", "ClusterWAFRuleSet"} {
		e := exprs[kind]
		if e == nil {
			t.Errorf("no healthCheckExprs for %s", kind)
			continue
		}
		for _, c := range cases(t, kind) {
			obj := ints(c.Object).(map[string]any)
			got := "InProgress"
			switch {
			case eval(t, e["current"], obj):
				got = "Current"
			case eval(t, e["failed"], obj):
				got = "Failed"
			}
			want := map[string]string{"Healthy": "Current", "Degraded": "Failed", "Progressing": "InProgress", "Suspended": "InProgress"}[c.Want]
			if got != want {
				t.Errorf("%s, %s: %s, want %s", kind, c.Name, got, want)
			}
		}
	}
	// Plain kstatus, for comparison: a policy without a status is current.
	res, err := status.Compute(&unstructured.Unstructured{Object: map[string]any{"apiVersion": "waf.inkwall.dev/v1alpha1", "kind": "WAFPolicy",
		"metadata": map[string]any{"name": "x", "namespace": "shop", "generation": int64(1)}}})
	if err != nil || res.Status != status.CurrentStatus {
		t.Errorf("plain kstatus of a policy without a status: %v %v (the docs say Current)", res, err)
	}
}

// ints makes the whole numbers YAML decoded as float64 int64, as the API
// server's objects have them.
func ints(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range v {
			out[k] = ints(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = ints(e)
		}
		return out
	case float64:
		if v == float64(int64(v)) {
			return int64(v)
		}
	}
	return v
}
