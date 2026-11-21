// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/flowcontrol"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

var updateGolden = flag.Bool("update", false, "rewrite the audit log's golden file (testdata/audit.golden)")

// auditTest is an Auditor whose log lines, without their time, go to out,
// and whose Events to rec.
func auditTest() (*Auditor, *bytes.Buffer, *events.FakeRecorder) {
	out := &bytes.Buffer{}
	h := slog.NewJSONHandler(out, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
	rec := events.NewFakeRecorder(10)
	return &Auditor{
		Log:      logr.FromSlogHandler(h).WithName("audit"),
		Recorder: rec,
		Operator: "system:serviceaccount:inkwall-system:inkwall-operator",
	}, out, rec
}

// admissionCtx is ctx with the admission request of op by user.
func admissionCtx(op admissionv1.Operation, kind string, user authenticationv1.UserInfo, dryRun bool) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op,
		Kind:      metav1.GroupVersionKind{Group: wafv1alpha1.GroupVersion.Group, Version: "v1alpha1", Kind: kind},
		UserInfo:  user,
		DryRun:    ptr(dryRun),
	}})
}

var alice = authenticationv1.UserInfo{
	Username: "alice",
	Groups:   []string{"system:authenticated", "platform"},
	// Never logged: extra fields may carry credentials.
	Extra: map[string]authenticationv1.ExtraValue{"token": {"s3cr3t-extra"}},
}

func policy(mode wafv1alpha1.PolicyMode, paths ...wafv1alpha1.PathPattern) *wafv1alpha1.WAFPolicy {
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "checkout", UID: "6f1c2a4e-0000-4000-8000-000000000001", Generation: 2, ResourceVersion: "4711"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "checkout"}},
			Mode:       mode,
		},
	}
	if len(paths) > 0 {
		p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: paths}
	}
	return p
}

// allow is a Validator that admits everything, or refuses with err.
type allow[T any] struct{ err error }

func (a allow[T]) ValidateCreate(context.Context, T) (admission.Warnings, error) { return nil, a.err }
func (a allow[T]) ValidateUpdate(context.Context, T, T) (admission.Warnings, error) {
	return nil, a.err
}
func (a allow[T]) ValidateDelete(context.Context, T) (admission.Warnings, error) { return nil, a.err }

// TestAuditGolden pins the log line's format: its field names are a
// stream users ship and parse (docs/audit-log.md).
func TestAuditGolden(t *testing.T) {
	a, out, rec := auditTest()
	v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{}, a}
	ctx := admissionCtx(admissionv1.Update, "WAFPolicy", alice, false)
	newP := policy(wafv1alpha1.PolicyBlock, "/healthz", "/static/*")
	newP.Generation = 3
	if _, err := v.ValidateUpdate(ctx, policy(wafv1alpha1.PolicyDetect, "/healthz"), newP); err != nil {
		t.Fatal(err)
	}
	sa := authenticationv1.UserInfo{Username: "system:serviceaccount:inkwall-system:inkwall-operator", Groups: []string{"system:serviceaccounts"}}
	if _, err := v.ValidateCreate(admissionCtx(admissionv1.Create, "WAFPolicy", sa, false), policy(wafv1alpha1.PolicyDetect)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ValidateDelete(admissionCtx(admissionv1.Delete, "WAFPolicy", alice, false), newP); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "s3cr3t-extra") {
		t.Errorf("userInfo.extra logged:\n%s", out)
	}
	golden := filepath.Join("testdata", "audit.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Errorf("the audit log lines changed (go test ./operator/webhook -run TestAuditGolden -update rewrites them, and docs/audit-log.md must follow):\n got:\n%s\nwant:\n%s", out, want)
	}
	for _, want := range []string{
		"Normal Changed Changed by alice: spec.mode, spec.skip.paths",
		"Normal Created Created by the operator: spec.mode, spec.targetRefs",
		"Normal Deleted Deleted by alice",
	} {
		if got := <-rec.Events; got != want {
			t.Errorf("Event %q, want %q", got, want)
		}
	}
}

// lines are the log lines in out, decoded.
func lines(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var l []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		l = append(l, m)
	}
	return l
}

func TestAuditSkips(t *testing.T) {
	refused := errors.New("refused")
	managed := guardFor(t, wafv1alpha1.ModeManaged)
	for _, tc := range []struct {
		name string
		do   func(*Auditor) error
	}{
		{"dry run", func(a *Auditor) error {
			v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{}, a}
			_, err := v.ValidateCreate(admissionCtx(admissionv1.Create, "WAFPolicy", alice, true), policy(wafv1alpha1.PolicyBlock))
			return err
		}},
		{"refused", func(a *Auditor) error {
			v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{refused}, a}
			if _, err := v.ValidateCreate(admissionCtx(admissionv1.Create, "WAFPolicy", alice, false), policy(wafv1alpha1.PolicyBlock)); !errors.Is(err, refused) {
				return fmt.Errorf("got %w", err)
			}
			if _, err := v.ValidateDelete(admissionCtx(admissionv1.Delete, "WAFPolicy", alice, false), policy(wafv1alpha1.PolicyBlock)); !errors.Is(err, refused) {
				return fmt.Errorf("got %w", err)
			}
			return nil
		}},
		{"metadata only", func(a *Auditor) error {
			v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{}, a}
			oldP, newP := policy(wafv1alpha1.PolicyBlock), policy(wafv1alpha1.PolicyBlock)
			newP.Labels = map[string]string{"team": "shop"}
			newP.Finalizers = []string{"waf.inkwall.dev/unwire"}
			newP.Annotations = map[string]string{"waf.inkwall.dev/wired": "x"}
			_, err := v.ValidateUpdate(admissionCtx(admissionv1.Update, "WAFPolicy", alice, false), oldP, newP)
			return err
		}},
		{"source guard", func(a *Auditor) error {
			// The real validator refuses alice's edit of a control plane
			// object in Managed mode: nothing is recorded.
			v := audited[*wafv1alpha1.WAFPolicy]{specValidator[*wafv1alpha1.WAFPolicy]{validateWAFPolicy, managed}, a}
			p := policy(wafv1alpha1.PolicyBlock)
			p.Labels = map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}
			if _, err := v.ValidateDelete(admissionCtx(admissionv1.Delete, "WAFPolicy", alice, false), p); err == nil {
				return errors.New("alice's delete admitted")
			}
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, rec := auditTest()
			before := totalChanges()
			if err := tc.do(a); err != nil {
				t.Fatal(err)
			}
			if out.Len() != 0 {
				t.Errorf("logged:\n%s", out)
			}
			if len(rec.Events) != 0 {
				t.Errorf("Event %q", <-rec.Events)
			}
			if after := totalChanges(); after != before {
				t.Errorf("counted: %v, then %v", before, after)
			}
		})
	}
}

// totalChanges sums inkwall_operator_policy_changes_total.
func totalChanges() float64 {
	var n float64
	for _, kind := range []string{"WAFPolicy", "WAFRuleSet", "ClusterWAFRuleSet", "WAFIPList", "InkwallConfig"} {
		for _, op := range []string{"create", "update", "delete"} {
			n += testutil.ToFloat64(policyChanges.WithLabelValues(kind, op))
		}
	}
	return n
}

func TestAuditMetric(t *testing.T) {
	a, _, _ := auditTest()
	v := audited[*wafv1alpha1.WAFIPList]{allow[*wafv1alpha1.WAFIPList]{}, a}
	c := policyChanges.WithLabelValues("WAFIPList", "update")
	before := testutil.ToFloat64(c)
	l := &wafv1alpha1.WAFIPList{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "office"}}
	l2 := l.DeepCopy()
	l2.Spec.Entries = []wafv1alpha1.IPListEntry{{CIDR: "203.0.113.0/24"}}
	if _, err := v.ValidateUpdate(admissionCtx(admissionv1.Update, "WAFIPList", alice, false), l, l2); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(c) - before; got != 1 {
		t.Errorf("inkwall_operator_policy_changes_total{kind=WAFIPList,operation=update} rose by %v, want 1", got)
	}
}

func TestAuditRedactsExportSinks(t *testing.T) {
	a, out, rec := auditTest()
	v := audited[*wafv1alpha1.InkwallConfig]{configValidator{}, a}
	oldCfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	newCfg := oldCfg.DeepCopy()
	newCfg.Spec.Events.Export = &wafv1alpha1.ExportSpec{Sinks: []wafv1alpha1.EventSink{
		{Name: "otlp", OTLP: &wafv1alpha1.OTLPSink{Endpoint: "https://collector.example.com:4318/v1/logs?api_key=otlp-query-secret"},
			HeadersSecretRef: &wafv1alpha1.LocalSecretReference{Name: "otlp-headers-secret-name"}},
		{Name: "intake", JSON: &wafv1alpha1.JSONSink{URL: "https://user:basic-pass@intake.example.com/receiver/v1/http/url-path-token"}},
		{Name: "sumo", JSON: &wafv1alpha1.JSONSink{URLSecretRef: &wafv1alpha1.SecretKeyReference{Name: "sumo-url-secret-name", Key: "url"}}},
	}}
	newCfg.Spec.ControlPlane = &wafv1alpha1.ControlPlane{
		Endpoint:            "grpcs://cp.example.com:443/path-token",
		EnrollmentSecretRef: wafv1alpha1.SecretReference{Namespace: "inkwall-system", Name: "enrollment-secret-name"},
	}
	if _, err := v.ValidateUpdate(admissionCtx(admissionv1.Update, "InkwallConfig", alice, false), oldCfg, newCfg); err != nil {
		t.Fatal(err)
	}
	log := out.String()
	for _, secret := range []string{"otlp-query-secret", "api_key", "otlp-headers-secret-name", "basic-pass", "user:", "url-path-token",
		"sumo-url-secret-name", "path-token", "enrollment-secret-name", "/v1/logs"} {
		if strings.Contains(log, secret) {
			t.Errorf("the log holds %q:\n%s", secret, log)
		}
	}
	for _, shown := range []string{`https://collector.example.com:4318`, `https://intake.example.com`, `grpcs://cp.example.com:443`, Redacted} {
		if !strings.Contains(log, strings.ReplaceAll(shown, "<", `\u003c`)) && !strings.Contains(log, shown) {
			t.Errorf("the log lacks %q:\n%s", shown, log)
		}
	}
	if e := <-rec.Events; strings.Contains(e, "secret-name") {
		t.Errorf("the Event holds a Secret's name: %q", e)
	}
}

func TestSummarize(t *testing.T) {
	j := func(s string) any {
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		name     string
		old, new string
		want     []Change
	}{
		{"scalars", `{"mode":"Detect","timeout":"1s"}`, `{"mode":"Block","timeout":"1s","failureMode":"Open"}`,
			[]Change{{Path: "spec.failureMode", New: "Open"}, {Path: "spec.mode", Old: "Detect", New: "Block"}}},
		{"nested and numbers", `{"a":{"b":{"n":9007199254740993}}}`, `{"a":{"b":{"n":1}}}`,
			[]Change{{Path: "spec.a.b.n", Old: "9007199254740993", New: "1"}}},
		{"map keys", `{"sel":{"app.kubernetes.io/name":"a"}}`, `{"sel":{"app.kubernetes.io/name":"b"}}`,
			[]Change{{Path: `spec.sel["app.kubernetes.io/name"]`, Old: "a", New: "b"}}},
		{"list", `{"paths":["/a","/b","/b"]}`, `{"paths":["/b","/c"]}`,
			[]Change{{Path: "spec.paths", Added: 1, Removed: 2, AddedItems: []string{`"/c"`}, RemovedItems: []string{`"/a"`, `"/b"`}}}},
		{"reordered", `{"paths":["/a","/b"]}`, `{"paths":["/b","/a"]}`, []Change{{Path: "spec.paths", Reordered: true}}},
		{"empty list is none", `{}`, `{"paths":[]}`, nil},
		{"create", `null`, `{"mode":"Block","paths":["/a"]}`,
			[]Change{{Path: "spec.mode", New: "Block"}, {Path: "spec.paths", Added: 1, AddedItems: []string{`"/a"`}}}},
		{"delete", `{"mode":"Block"}`, `null`, []Change{{Path: "spec.mode", Old: "Block"}}},
		{"secret names", `{"tokenSecretRef":{"name":"a"}}`, `{"tokenSecretRef":{"name":"b"}}`,
			[]Change{{Path: "spec.tokenSecretRef.name", Old: Redacted, New: Redacted}}},
		{"redacted list items", `{"items":[{"password":"x","name":"n"}]}`, `{"items":[{"password":"y","name":"n"}]}`,
			[]Change{{Path: "spec.items", Added: 1, Removed: 1, AddedItems: []string{`{"name":"n","password":"\u003credacted\u003e"}`}, RemovedItems: []string{`{"name":"n","password":"\u003credacted\u003e"}`}}}},
		{"urls", `{"url":"https://a.example/x?token=1"}`, `{"url":"not a url"}`,
			[]Change{{Path: "spec.url", Old: "https://a.example", New: Redacted}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, omitted, paths := Summarize(j(tc.old), j(tc.new))
			if omitted != 0 || len(paths) != len(tc.want) {
				t.Errorf("omitted %d, paths %q", omitted, paths)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(tc.want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestSummarizeBounds(t *testing.T) {
	long := strings.Repeat("é", 200)
	got, _, _ := Summarize(map[string]any{"seclang": "a"}, map[string]any{"seclang": long})
	if n := len(got[0].New); n > maxValue || !strings.HasSuffix(got[0].New, "…") || !strings.HasPrefix(long, strings.TrimSuffix(got[0].New, "…")) {
		t.Errorf("long value: %d bytes, %q", n, got[0].New)
	}

	var items []any
	for i := range 1000 {
		items = append(items, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
	}
	got, _, _ = Summarize(nil, map[string]any{"entries": items})
	if c := got[0]; c.Added != 1000 || len(c.AddedItems) != maxItems {
		t.Errorf("1000 items: added %d, shown %d", c.Added, len(c.AddedItems))
	}

	fields := map[string]any{}
	for i := range 500 {
		fields[fmt.Sprintf("field%03d", i)] = strings.Repeat("x", 100)
	}
	got, omitted, paths := Summarize(nil, fields)
	raw, _ := json.Marshal(got)
	if len(raw) > maxChanges || omitted == 0 || len(got)+omitted != 500 || len(paths) != 500 {
		t.Errorf("500 changes: %d bytes, %d shown, %d omitted, %d paths", len(raw), len(got), omitted, len(paths))
	}
	r := Record{Operation: "update", User: "alice", Paths: paths}
	if n := r.note(); !strings.HasSuffix(n, "and 492 more") || len(n) > 1000 {
		t.Errorf("note: %q", n)
	}
}

// TestAuditEventLimit: past the limit, changes are still logged, without
// an Event.
func TestAuditEventLimit(t *testing.T) {
	a, out, rec := auditTest()
	a.EventLimit = flowcontrol.NewTokenBucketRateLimiter(0.001, 1)
	v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{}, a}
	for range 3 {
		if _, err := v.ValidateCreate(admissionCtx(admissionv1.Create, "WAFPolicy", alice, false), policy(wafv1alpha1.PolicyBlock)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(lines(t, out)); n != 3 {
		t.Errorf("%d lines, want 3", n)
	}
	if n := len(rec.Events); n != 1 {
		t.Errorf("%d Events, want 1", n)
	}
}

func TestServiceAccount(t *testing.T) {
	for user, want := range map[string]string{
		"system:serviceaccount:argocd:argocd-application-controller": "argocd/argocd-application-controller",
		"alice":                         "",
		"system:serviceaccount:invalid": "",
	} {
		if got := serviceAccount(user); got != want {
			t.Errorf("%s: %q, want %q", user, got, want)
		}
	}
}
