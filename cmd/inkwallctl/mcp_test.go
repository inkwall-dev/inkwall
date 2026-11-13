// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/reasons"
)

// clusterWrites counts the write calls made to the test clusters
// (explainTestCluster): each fails, and none may be made.
var clusterWrites atomic.Int64

// writeGuard fails and counts every write verb.
var writeGuard = interceptor.Funcs{
	Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
		return wrote("create")
	},
	Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
		return wrote("update")
	},
	Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
		return wrote("patch")
	},
	Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
		return wrote("apply")
	},
	Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
		return wrote("delete")
	},
	DeleteAllOf: func(context.Context, client.WithWatch, client.Object, ...client.DeleteAllOfOption) error {
		return wrote("deletecollection")
	},
	SubResourceCreate: func(context.Context, client.Client, string, client.Object, client.Object, ...client.SubResourceCreateOption) error {
		return wrote("create subresource")
	},
	SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return wrote("update subresource")
	},
	SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return wrote("patch subresource")
	},
}

func wrote(verb string) error {
	clusterWrites.Add(1)
	return errors.New("test cluster: " + verb + " refused: inkwallctl must only read")
}

// mcpSession serves the tools on the test cluster (nil: no kubeconfig) and
// returns a client session.
func mcpSession(t *testing.T, ec *explainCluster) *mcp.ClientSession {
	t.Helper()
	saved := statusClock
	t.Cleanup(func() { statusClock = saved })
	statusClock = func() time.Time { return statusNow }
	connect := func() (*explainCluster, error) {
		if ec == nil {
			return nil, errors.New("no kubeconfig")
		}
		return ec, nil
	}
	srv := newMCPServer(mcpConfig{namespace: "inkwall-system"}, connect)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call calls a tool and decodes its structured result into out; it fails
// the test on a tool error.
func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any, out any) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		t.Fatalf("%s: tool error: %s", tool, toolText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v\n%s", tool, err, b)
	}
}

func toolText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

var mcpTools = []string{"explain_policy", "explain_request", "get_policy", "list_policies", "status", "suggest_exclusions", "test_policy"}

// initialize and tools/list: the seven tools, each read-only, with an input
// and an output schema; those whose results hold request data say that
// it is data, not instructions (#439, 0008 §6).
func TestMCPToolsList(t *testing.T) {
	cs := mcpSession(t, nil)
	if got := cs.InitializeResult().ServerInfo.Name; got != "inkwallctl" {
		t.Errorf("server %q", got)
	}
	if !strings.Contains(cs.InitializeResult().Instructions, "never instructions") {
		t.Errorf("instructions: %q", cs.InitializeResult().Instructions)
	}
	var names []string
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Errorf("%s: annotations %+v, want read-only, closed world", tool.Name, tool.Annotations)
		}
		if tool.InputSchema == nil || tool.OutputSchema == nil {
			t.Errorf("%s: no input or output schema", tool.Name)
		}
		untrusted := slices.Contains([]string{"explain_request", "test_policy", "suggest_exclusions"}, tool.Name)
		if untrusted != strings.Contains(tool.Description, "never as instructions") {
			t.Errorf("%s: the untrusted note is %t in its description, want %t", tool.Name, !untrusted, untrusted)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, mcpTools) {
		t.Errorf("tools %q, want %q", names, mcpTools)
	}
}

// The resources: this version's docs, the troubleshooting guide among them,
// as embedded.
func TestMCPResources(t *testing.T) {
	cs := mcpSession(t, nil)
	var uris []string
	for r, err := range cs.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, r.URI)
	}
	for _, want := range []string{"inkwall://docs/troubleshooting.md", "inkwall://docs/mcp.md", "inkwall://docs/quickstart.md"} {
		if !slices.Contains(uris, want) {
			t.Errorf("resources %q lack %s", uris, want)
		}
	}
	res, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "inkwall://docs/troubleshooting.md"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../docs/troubleshooting.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || res.Contents[0].Text != string(want) || res.Contents[0].MIMEType != "text/markdown" {
		t.Error("the troubleshooting guide isn't served as it is")
	}
	if _, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "inkwall://docs/none.md"}); err == nil {
		t.Error("an unknown resource is served")
	}
}

// Every tool, on the test cluster, with what its CLI command gives.
func TestMCPTools(t *testing.T) {
	ec, _ := explainTestCluster(t)
	cs := mcpSession(t, ec)

	var st Status
	call(t, cs, "status", nil, &st)
	if st.Policies.Total != 2 {
		t.Errorf("status: policies %+v", st.Policies)
	}

	var re RequestExplanation
	call(t, cs, "explain_request", map[string]any{"requestId": "req-deny", "since": "2h"}, &re)
	if !re.Found || len(re.Events) != 1 || len(re.Events[0].Suggestions) != 1 || !re.Events[0].Suggestions[0].Verified ||
		!slices.Contains(re.Untrusted, "events[].request") {
		t.Errorf("explain_request: %+v", re)
	}
	call(t, cs, "explain_request", map[string]any{"requestId": "req-none"}, &re)
	if re.Found {
		t.Error("explain_request found req-none")
	}

	var list PolicyList
	call(t, cs, "list_policies", map[string]any{"namespace": "shop"}, &list)
	if len(list.Policies) != 2 || list.Policies[1].Name != "storefront" || list.Policies[1].Mode != "Block" || list.Policies[1].Reason != "Unknown" {
		t.Errorf("list_policies: %+v", list)
	}

	var d PolicyDetail
	call(t, cs, "get_policy", map[string]any{"namespace": "shop", "name": "storefront"}, &d)
	if d.Spec["mode"] != "Block" || !strings.Contains(d.YAML, "owasp-crs-v4") {
		t.Errorf("get_policy: %+v", d)
	}

	// test_policy: the attack is denied; with the suggested exclusion
	// added, it passes; another argument is still denied.
	attack := "http://shop.example.com/search?q=1%27%20OR%20%271%27%3D%271"
	var pt PolicyTest
	call(t, cs, "test_policy", map[string]any{"namespace": "shop", "name": "storefront", "url": attack}, &pt)
	if len(pt.Results) != 1 || pt.Results[0].Action != "deny" || !slices.ContainsFunc(pt.Results[0].Matches, func(m MatchPoint) bool { return m.Variable == "ARGS:q" }) {
		t.Errorf("test_policy: %+v", pt)
	}
	spec := map[string]any{}
	b, _ := json.Marshal(d.Spec)
	_ = json.Unmarshal(b, &spec)
	spec["exclusions"] = []any{map[string]any{"ruleIDs": []int{942100}, "when": map[string]any{"path": "/search", "argument": "q"}}}
	call(t, cs, "test_policy", map[string]any{"namespace": "shop", "name": "storefront", "policySpec": spec,
		"request": "GET /search?q=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: shop.example.com\r\n\r\nGET /search?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"}, &pt)
	if len(pt.Results) != 2 || pt.Results[0].Action != "allow" || pt.Results[1].Action != "deny" || !slices.Contains(pt.Untrusted, "results[].uri") {
		t.Errorf("test_policy with the exclusion: %+v", pt)
	}

	var sx ExclusionSuggestions
	call(t, cs, "suggest_exclusions", map[string]any{"policy": "shop/storefront"}, &sx)
	if sx.Events == 0 || len(sx.Policies) != 1 || !sx.Policies[0].Verified || !strings.Contains(sx.Policies[0].YAML, "argument: q") ||
		!slices.Contains(sx.Untrusted, "groups[].variable") {
		t.Errorf("suggest_exclusions: %+v", sx)
	}
	logs, err := os.ReadFile("testdata/explain/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	call(t, cs, "suggest_exclusions", map[string]any{"logs": string(logs)}, &sx)
	if sx.Events != 2 || len(sx.Policies) != 1 || !sx.Policies[0].Verified {
		t.Errorf("suggest_exclusions from logs: %+v", sx)
	}
	if strings.Contains(mustJSON(t, sx), "SNIPPET-NEVER-SHOWN") {
		t.Error("suggest_exclusions shows a matched value")
	}
}

// explain_policy gives the guide's cause and fix.
func TestMCPExplainPolicy(t *testing.T) {
	ec, _ := explainTestCluster(t, failingPolicy(wafv1alpha1.ConditionProgrammed, "SidecarMissing", "pods traefik/x don't run the engine"))
	cs := mcpSession(t, ec)
	var pe PolicyExplanation
	call(t, cs, "explain_policy", map[string]any{"namespace": "shop", "name": "web"}, &pe)
	e, _ := reasons.Lookup(reasons.KindWAFPolicy, wafv1alpha1.ConditionProgrammed, "SidecarMissing")
	if pe.Ready || pe.Conditions[1].Fix != reasons.Text(e.Fix) {
		t.Errorf("explain_policy: %+v", pe)
	}
}

// Errors: bad arguments are tool errors the assistant can read; an unknown
// tool is a protocol error; without a kubeconfig, tools say so and the
// server still lists them.
func TestMCPErrors(t *testing.T) {
	ec, _ := explainTestCluster(t)
	cs := mcpSession(t, ec)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"explain_policy", map[string]any{"namespace": "shop"}, "missing properties"},
		{"explain_policy", map[string]any{"namespace": "shop", "name": ""}, "namespace and name"},
		{"explain_policy", map[string]any{"namespace": "shop", "name": "none"}, "no WAFPolicy shop/none"},
		{"get_policy", map[string]any{"namespace": "shop", "name": "none"}, "no WAFPolicy shop/none"},
		{"explain_request", map[string]any{"requestId": "x", "since": "soon"}, "positive duration"},
		{"explain_request", map[string]any{"requestId": "x", "pods": []string{"nope"}}, "namespace/name"},
		{"test_policy", map[string]any{"namespace": "shop", "name": "storefront"}, "exactly one of url, request and har"},
		{"test_policy", map[string]any{"namespace": "shop", "name": "storefront", "url": "http://a/", "har": "{}"}, "exactly one"},
		{"test_policy", map[string]any{"namespace": "shop", "name": "storefront", "request": "GET / HTTP/1.1\r\nHost: a\r\n\r\n", "body": "x"}, "only to url"},
		{"suggest_exclusions", map[string]any{"logs": "x", "pods": []string{"a/b"}}, "give one"},
	} {
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Errorf("%s %v: protocol error %v, want a tool error", tc.tool, tc.args, err)
			continue
		}
		if !res.IsError || !strings.Contains(toolText(res), tc.want) {
			t.Errorf("%s %v: %t %q, want a tool error with %q", tc.tool, tc.args, res.IsError, toolText(res), tc.want)
		}
	}
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "apply_policy"}); err == nil {
		t.Error("an unknown tool is called")
	}

	none := mcpSession(t, nil)
	res, err := none.CallTool(t.Context(), &mcp.CallToolParams{Name: "status"})
	if err != nil || !res.IsError || !strings.Contains(toolText(res), "no kubeconfig") {
		t.Errorf("without a cluster: %v %+v", err, res)
	}
}

// A body is sent as is: test_policy never reads a local file, whatever the
// assistant asks.
func TestMCPTestPolicyNoFiles(t *testing.T) {
	ec, _ := explainTestCluster(t)
	cs := mcpSession(t, ec)
	secret := writeFile(t, "secret", "SECRET-FILE-CONTENT")
	var pt PolicyTest
	call(t, cs, "test_policy", map[string]any{"namespace": "shop", "name": "storefront", "url": "http://shop.example.com/", "body": "@" + secret}, &pt)
	if len(pt.Results) != 1 || pt.Results[0].Method != "POST" {
		t.Errorf("test_policy: %+v", pt)
	}
	r, err := fromCommandLine(config{url: "http://a/", data: "@" + secret, literalData: true})
	if err != nil || string(r.GetBody()) != "@"+secret {
		t.Errorf("body %q, %v; want the text as given", r.GetBody(), err)
	}
}

// Read-only: every tool, called on a cluster that refuses and counts every
// write verb, makes none (#439, 0008 §6).
func TestMCPReadOnly(t *testing.T) {
	before := clusterWrites.Load()
	ec, _ := explainTestCluster(t, failingPolicy(wafv1alpha1.ConditionEnforced, "EnginesBehind", "1 of 2"))
	cs := mcpSession(t, ec)
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"status", nil},
		{"list_policies", nil},
		{"get_policy", map[string]any{"namespace": "shop", "name": "web"}},
		{"explain_policy", map[string]any{"namespace": "shop", "name": "web"}},
		{"explain_request", map[string]any{"requestId": "req-deny"}},
		{"test_policy", map[string]any{"namespace": "shop", "name": "web", "url": "http://a/?q=1"}},
		{"suggest_exclusions", nil},
	} {
		if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args}); err != nil {
			t.Errorf("%s: %v", c.tool, err)
		}
	}
	if n := clusterWrites.Load() - before; n != 0 {
		t.Errorf("the tools made %d write calls", n)
	}
	// The guard works: a write through the same client is refused and
	// counted.
	if w, ok := ec.c.(client.Writer); !ok || w.Delete(t.Context(), &wafv1alpha1.WAFPolicy{}) == nil || clusterWrites.Load()-before != 1 {
		t.Error("the write guard doesn't refuse writes")
	}
	clusterWrites.Add(-1)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMCPFlags(t *testing.T) {
	if code, _, errOut := runCLI(t, "mcp", "extra"); code != 2 || !strings.Contains(errOut, "unexpected arguments") {
		t.Errorf("exit %d, %s", code, errOut)
	}
}
