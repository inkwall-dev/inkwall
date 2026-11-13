// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/operator/reasons"
)

// The shop's policy objects, as testdata/policy has them.
var explainObjects = []string{
	"--policy", "testdata/policy/wafpolicy.yaml", "--rule-set", "testdata/policy/wafruleset.yaml",
	"--configmap", "testdata/policy/configmap.yaml", "--ingress", "testdata/policy/ingress.yaml",
}

func explainFile(t *testing.T, file, id string, extra ...string) (*RequestExplanation, string) {
	t.Helper()
	args := slices.Concat([]string{"explain", "request", "--file", file}, explainObjects, extra, []string{"-o", "json", id})
	code, out, errOut := runCLI(t, args...)
	var re RequestExplanation
	if err := json.Unmarshal([]byte(out), &re); err != nil {
		t.Fatalf("exit %d, %s: %v\n%s", code, errOut, err, out)
	}
	if (code == 0) != re.Found {
		t.Fatalf("exit %d, found %t", code, re.Found)
	}
	return &re, out
}

// A denied request, from a log file: the policy, the reason and its cause,
// the score against the threshold, each rule with the CRS's description of
// it, and the narrowest exclusion, verified as inkwallctl test --policy
// does (#438).
func TestExplainRequestDenied(t *testing.T) {
	args := slices.Concat([]string{"explain", "request", "--file", "testdata/explain/engine.log"}, explainObjects, []string{"req-deny"})
	code, out, errOut := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "explain/denied.txt", out)

	re, raw := explainFile(t, "testdata/explain/engine.log", "req-deny")
	golden(t, "explain/denied.json", raw)
	if len(re.Events) != 1 {
		t.Fatalf("%d events, want 1", len(re.Events))
	}
	ev := re.Events[0]
	if ev.Policy != "shop/storefront" || ev.Mode != "Block" || ev.Status != 403 || ev.AnomalyScore != 5 || ev.Threshold != 5 {
		t.Errorf("event %+v", ev)
	}
	if e, _ := reasons.Lookup(reasons.KindSecurityEvent, "reason", "rule"); ev.Cause != reasons.Text(e.Meaning) {
		t.Errorf("cause %q, want the guide's", ev.Cause)
	}
	if len(ev.Rules) != 2 || ev.Rules[0].ID != 942100 || ev.Rules[0].Source != "crs" ||
		!strings.HasPrefix(ev.Rules[0].Description, "SQL Injection Attack Detected") || !ev.Rules[1].Scoring || !ev.Rules[1].Interrupting {
		t.Errorf("rules %+v", ev.Rules)
	}
	if len(ev.Suggestions) != 1 || !ev.AllowedWithSuggestions {
		t.Fatalf("suggestions %+v, allowed %t", ev.Suggestions, ev.AllowedWithSuggestions)
	}
	s := ev.Suggestions[0]
	want := wafv1alpha1.Exclusion{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Path: "/search", Argument: "q"}}
	if !s.Verified || s.VerifiedWith != "the --policy files" || s.Exclusion.When == nil || *s.Exclusion.When != *want.When ||
		!slices.Equal(s.Exclusion.RuleIDs, want.RuleIDs) {
		t.Errorf("suggestion %+v, want %+v verified", s, want)
	}
}

// The suggestion is the one inkwallctl tune makes, not a copy of its
// logic.
func TestExplainSuggestsTunes(t *testing.T) {
	re, _ := explainFile(t, "testdata/explain/engine.log", "req-deny")
	evs := readTuneFile(t, "../explain/engine.log", true)
	i := slices.IndexFunc(evs, func(e tuneEvent) bool { return e.RequestID == "req-deny" })
	rep := tune(evs[i:i+1], false, 1)
	got, _ := json.Marshal(re.Events[0].Suggestions[0].Exclusion)
	want, _ := json.Marshal(rep.Suggestions["shop/storefront"][0])
	if string(got) != string(want) {
		t.Errorf("explain suggests %s, tune %s", got, want)
	}
}

// Detect mode, a rule in a cookie and one in the body: the cookie gets an
// exclusion; the body none (no field names it), so the exclusion alone
// doesn't allow the request.
func TestExplainRequestPartly(t *testing.T) {
	re, _ := explainFile(t, "testdata/explain/engine.log", "req-detect")
	ev := re.Events[0]
	if ev.Mode != "Detect" || ev.AnomalyScore != 10 || ev.AllowedWithSuggestions {
		t.Errorf("event %+v", ev)
	}
	if len(ev.Suggestions) != 1 || ev.Suggestions[0].Exclusion.When.Cookie != "prefs" {
		t.Errorf("suggestions %+v", ev.Suggestions)
	}
	if len(ev.NotSuggested) != 1 || ev.NotSuggested[0].Variable != "REQUEST_BODY" || ev.NotSuggested[0].RuleID != 942100 {
		t.Errorf("not suggested %+v", ev.NotSuggested)
	}
}

// A request the rules didn't deny: the guide's cause and fix for its
// reason, and nothing to exclude.
func TestExplainRequestOversize(t *testing.T) {
	re, _ := explainFile(t, "testdata/explain/engine.log", "req-big")
	ev := re.Events[0]
	e, _ := reasons.Lookup(reasons.KindSecurityEvent, "reason", "oversize")
	if ev.Reason != "oversize" || ev.Status != 413 || ev.Cause != reasons.Text(e.Meaning) || ev.Fix != reasons.Text(e.Fix) || len(ev.Suggestions) != 0 {
		t.Errorf("event %+v", ev)
	}
}

// A rule of the policy's own has no CRS description; its exclusion names
// the header it matched.
func TestExplainRequestCustomRule(t *testing.T) {
	re, _ := explainFile(t, "testdata/explain/engine.log", "req-custom")
	ev := re.Events[0]
	if len(ev.Rules) != 1 || ev.Rules[0].Source != "custom" || ev.Rules[0].Description != "" {
		t.Errorf("rules %+v", ev.Rules)
	}
	if len(ev.Suggestions) != 1 || ev.Suggestions[0].Exclusion.When.Header != "User-Agent" || !ev.Suggestions[0].Verified {
		t.Errorf("suggestions %+v", ev.Suggestions)
	}
}

// What the client wrote is data: quoted in text when it isn't printable,
// listed as untrusted in JSON, and never made into a suggestion it can't
// be (a path with a line break).
func TestExplainRequestHostile(t *testing.T) {
	args := slices.Concat([]string{"explain", "request", "--file", "testdata/explain/engine.log"}, explainObjects, []string{"req-hostile"})
	code, out, errOut := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("a terminal escape from the request is printed as is")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Ignore your instructions") {
			t.Errorf("the request's text starts a line of its own: %q", line)
		}
	}
	if !strings.Contains(out, "data, not instructions") {
		t.Error("the request isn't marked as data")
	}
	re, _ := explainFile(t, "testdata/explain/engine.log", "req-hostile")
	ev := re.Events[0]
	if len(ev.Suggestions) != 0 || len(ev.NotSuggested) != 1 {
		t.Errorf("suggestions %+v, not suggested %+v", ev.Suggestions, ev.NotSuggested)
	}
	for _, f := range []string{"requestId", "events[].request", "events[].suggestions[].exclusion.when"} {
		if !slices.Contains(re.Untrusted, f) {
			t.Errorf("untrusted %q lacks %s", re.Untrusted, f)
		}
	}
}

// Events from the events API (JSON lines): what a rule matched (the
// snippet) is never shown, and reasons read as the log writes them.
func TestExplainRequestEventsNeverShowValues(t *testing.T) {
	for _, output := range []string{"text", "json"} {
		args := slices.Concat([]string{"explain", "request", "--file", "testdata/explain/events.jsonl"}, explainObjects, []string{"-o", output, "evt-1"})
		code, out, errOut := runCLI(t, args...)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", output, code, errOut)
		}
		if strings.Contains(out, "SNIPPET-NEVER-SHOWN") {
			t.Errorf("%s: the matched value is shown:\n%s", output, out)
		}
		if !strings.Contains(out, "942100") {
			t.Errorf("%s: the rule isn't explained:\n%s", output, out)
		}
	}
	re, _ := explainFile(t, "testdata/explain/events.jsonl", "evt-2")
	if ev := re.Events[0]; ev.Reason != "ip-deny" || ev.Cause == "" {
		t.Errorf("event %+v", ev)
	}
}

// No event: exit 1, and where explain looked.
func TestExplainRequestNotFound(t *testing.T) {
	code, out, _ := runCLI(t, slices.Concat([]string{"explain", "request", "--file", "testdata/explain/engine.log"}, explainObjects, []string{"req-none"})...)
	if code != 1 || !strings.Contains(out, "No security event has request ID req-none") || !strings.Contains(out, "file testdata/explain/engine.log") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// explainCluster is the shop with its policy, rule sets, an operator
// replica reporting one Traefik pod's engine, and that engine's log.
func explainTestCluster(t *testing.T, policies ...*wafv1alpha1.WAFPolicy) (*explainCluster, *[]string) {
	t.Helper()
	in, _, err := loadObjects([]string{"testdata/policy/wafpolicy.yaml", "testdata/policy/wafruleset.yaml", "testdata/policy/configmap.yaml"}, "shop", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var objs []client.Object
	if len(policies) == 0 {
		for i := range in.Policies {
			objs = append(objs, &in.Policies[i])
		}
	}
	for _, p := range policies {
		objs = append(objs, p)
	}
	for i := range in.RuleSets {
		objs = append(objs, &in.RuleSets[i])
	}
	for i := range in.ClusterRuleSets {
		objs = append(objs, &in.ClusterRuleSets[i])
	}
	for i := range in.ConfigMaps {
		objs = append(objs, &in.ConfigMaps[i])
	}
	engines, err := json.Marshal([]enginereport.Engine{
		{ID: "traefik-1", PodNamespace: "traefik", PodName: "traefik-1", EngineVersion: "v0.6.0", Applied: 6, Replica: "inkwall-operator-a", ConnectedAt: statusNow},
		{ID: "traefik-2", PodNamespace: "traefik", PodName: "traefik-2", EngineVersion: "v0.6.0", Applied: 7, Replica: "inkwall-operator-a", ConnectedAt: statusNow},
	})
	if err != nil {
		t.Fatal(err)
	}
	objs = append(objs,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: enginereport.NamePrefix + "inkwall-operator-a", Labels: map[string]string{enginereport.Label: "true"}},
			Data:       map[string]string{enginereport.EnginesKey: string(engines), enginereport.UpdatedAtKey: statusNow.Format(time.RFC3339Nano)},
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-1"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik"}, {Name: engineContainer}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-2"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik"}, {Name: engineContainer}}}},
	)
	var read []string
	return &explainCluster{
		c: fake.NewClientBuilder().WithScheme(statusScheme()).WithObjects(objs...).WithInterceptorFuncs(writeGuard).Build(),
		logs: func(_ context.Context, ns, pod, container string, since time.Duration) (io.ReadCloser, error) {
			read = append(read, ns+"/"+pod+":"+container+":"+since.String())
			if pod != "traefik-2" {
				return io.NopCloser(strings.NewReader("")), nil
			}
			return os.Open("testdata/explain/engine.log")
		},
	}, &read
}

func withExplainCluster(t *testing.T, ec *explainCluster) {
	t.Helper()
	saved, savedClock := newExplainCluster, statusClock
	t.Cleanup(func() { newExplainCluster, statusClock = saved, savedClock })
	newExplainCluster = func(string, string) (*explainCluster, error) { return ec, nil }
	statusClock = func() time.Time { return statusNow }
}

// From the cluster: the engines the operator reports, their engine
// container's log through the API server, and the policy and its rule sets
// to verify the suggestion with.
func TestExplainRequestCluster(t *testing.T) {
	ec, read := explainTestCluster(t)
	withExplainCluster(t, ec)
	code, out, errOut := runCLI(t, "explain", "request", "-o", "json", "--since", "2h", "req-deny")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var re RequestExplanation
	if err := json.Unmarshal([]byte(out), &re); err != nil {
		t.Fatal(err)
	}
	want := []string{"traefik/traefik-1:inkwall-engine:2h0m0s", "traefik/traefik-2:inkwall-engine:2h0m0s"}
	if !slices.Equal(*read, want) {
		t.Errorf("read %q, want %q", *read, want)
	}
	if len(re.Events) != 1 {
		t.Fatalf("events %+v", re.Events)
	}
	ev := re.Events[0]
	if ev.Source != "traefik/traefik-2" || ev.Threshold != 5 || len(ev.Suggestions) != 1 || !ev.Suggestions[0].Verified ||
		ev.Suggestions[0].VerifiedWith != "the cluster" || len(re.Warnings) != 0 {
		t.Errorf("event %+v, warnings %q", ev, re.Warnings)
	}

	// --pod reads only that pod.
	*read = nil
	if code, _, errOut := runCLI(t, "explain", "request", "--pod", "traefik/traefik-2", "req-deny"); code != 0 || len(*read) != 1 {
		t.Errorf("--pod: exit %d, read %q: %s", code, *read, errOut)
	}
}

// Without the policy (deleted since), the explanation stands, unverified,
// with a warning.
func TestExplainRequestPolicyGone(t *testing.T) {
	ec, _ := explainTestCluster(t, &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "other"}})
	withExplainCluster(t, ec)
	code, out, errOut := runCLI(t, "explain", "request", "-o", "json", "req-deny")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var re RequestExplanation
	if err := json.Unmarshal([]byte(out), &re); err != nil {
		t.Fatal(err)
	}
	if s := re.Events[0].Suggestions; len(s) != 1 || s[0].Verified || s[0].VerifyError == "" || len(re.Warnings) != 1 {
		t.Errorf("suggestions %+v, warnings %q", s, re.Warnings)
	}
}

// failingPolicy is a policy whose condition is False for reason, the
// others True, and Ready as the operator derives it.
func failingPolicy(condition, reason, message string) *wafv1alpha1.WAFPolicy {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Generation: 4}}
	p.Spec.TargetRefs = []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}
	p.Status.BundleVersion = 7
	for _, t := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced} {
		c := metav1.Condition{Type: t, Status: metav1.ConditionTrue, Reason: t, ObservedGeneration: 4}
		if t == condition {
			c.Status, c.Reason, c.Message = metav1.ConditionFalse, reason, message
		}
		p.Status.Conditions = append(p.Status.Conditions, c)
	}
	ready := metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: 4}
	if condition != "" {
		ready.Status, ready.Reason, ready.Message = metav1.ConditionFalse, reason, condition+": "+message
	}
	p.Status.Conditions = append(p.Status.Conditions, ready)
	return p
}

// Every reason a policy condition can have: explain policy prints the
// guide's cause and fix for it, on the condition and on Ready (#438).
func TestExplainPolicyEveryReason(t *testing.T) {
	n := 0
	for _, e := range reasons.All() {
		if e.Kind != reasons.KindWAFPolicy || e.Condition == wafv1alpha1.ConditionReady || e.Reason == e.Condition {
			continue
		}
		n++
		ec, _ := explainTestCluster(t, failingPolicy(e.Condition, e.Reason, "the operator's message"))
		pe, err := explainPolicy(t.Context(), ec, "inkwall-system", "shop/web", statusNow)
		if err != nil {
			t.Fatal(err)
		}
		if pe.Ready {
			t.Errorf("%s %s: Ready", e.Condition, e.Reason)
		}
		for _, c := range pe.Conditions {
			failing := c.Type == e.Condition || c.Type == wafv1alpha1.ConditionReady
			if failing && (c.Cause != reasons.Text(e.Meaning) || c.Fix != reasons.Text(e.Fix)) {
				t.Errorf("%s %s: condition %s: cause %q, fix %q; want the guide's", e.Condition, e.Reason, c.Type, c.Cause, c.Fix)
			}
			if !failing && (c.Status != "True" || c.Cause != "") {
				t.Errorf("%s %s: condition %s %+v", e.Condition, e.Reason, c.Type, c)
			}
		}
	}
	if n < 20 {
		t.Errorf("%d reasons checked: the guide's WAFPolicy entries are missing?", n)
	}
}

// The text, and the engines that don't run the policy's bundle while it
// isn't Enforced; exit 1.
func TestExplainPolicyEngines(t *testing.T) {
	ec, _ := explainTestCluster(t, failingPolicy(wafv1alpha1.ConditionEnforced, "EnginesBehind", "1 of 2 engines run bundle 7 or later"))
	withExplainCluster(t, ec)
	code, out, errOut := runCLI(t, "explain", "policy", "shop/web")
	if code != 1 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "explain/policy.txt", out)
	code, out, _ = runCLI(t, "explain", "policy", "-o", "json", "shop/web")
	if code != 1 {
		t.Fatalf("json: exit %d", code)
	}
	golden(t, "explain/policy.json", out)
	var pe PolicyExplanation
	if err := json.Unmarshal([]byte(out), &pe); err != nil {
		t.Fatal(err)
	}
	if len(pe.Engines) != 1 || pe.Engines[0].Pod != "traefik-1" || pe.Engines[0].State != engineBehind {
		t.Errorf("engines %+v", pe.Engines)
	}
}

// Ready, and Ready about an older generation, and conditions not reported.
func TestExplainPolicyStates(t *testing.T) {
	ec, _ := explainTestCluster(t, failingPolicy("", "", ""))
	withExplainCluster(t, ec)
	if code, out, errOut := runCLI(t, "explain", "policy", "shop/web"); code != 0 || !strings.Contains(out, "): Ready\n") {
		t.Errorf("ready: exit %d: %s%s", code, out, errOut)
	}

	stale := failingPolicy("", "", "")
	stale.Generation = 5
	ec, _ = explainTestCluster(t, stale)
	pe, err := explainPolicy(t.Context(), ec, "inkwall-system", "shop/web", statusNow)
	if err != nil {
		t.Fatal(err)
	}
	if pe.Ready || pe.Conditions[3].Current || !strings.Contains(pe.Conditions[3].Cause, "generation 5") {
		t.Errorf("stale: %+v", pe)
	}

	fresh := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Generation: 1}}
	ec, _ = explainTestCluster(t, fresh)
	pe, err = explainPolicy(t.Context(), ec, "inkwall-system", "shop/web", statusNow)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := reasons.Lookup(reasons.KindWAFPolicy, wafv1alpha1.ConditionReady, "NotAccepted")
	if pe.Ready || pe.Conditions[3].Reason != "NotAccepted" || pe.Conditions[3].Cause != reasons.Text(e.Meaning) {
		t.Errorf("fresh: %+v", pe.Conditions)
	}

	if _, err := explainPolicy(t.Context(), ec, "inkwall-system", "shop/none", statusNow); err == nil || !strings.Contains(err.Error(), "no WAFPolicy shop/none") {
		t.Errorf("missing policy: %v", err)
	}
}

// explain only reads: the fake client fails every write, and explain
// passes.
func TestExplainReadOnly(t *testing.T) {
	ec, _ := explainTestCluster(t, failingPolicy(wafv1alpha1.ConditionProgrammed, "NoTargets", "no target exists"))
	ec.c = readOnly{ec.c}
	withExplainCluster(t, ec)
	if code, _, errOut := runCLI(t, "explain", "policy", "shop/web"); code != 1 {
		t.Errorf("policy: exit %d: %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "explain", "request", "req-other"); code != 0 {
		t.Errorf("request: exit %d: %s", code, errOut)
	}
}

// readOnly is a client.Reader only: explain gets no other.
type readOnly struct{ client.Reader }

func TestExplainFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"explain"}, "usage: inkwallctl explain"},
		{[]string{"explain", "request"}, "give one request ID"},
		{[]string{"explain", "policy", "web"}, "namespace/name"},
		{[]string{"explain", "policy", "-o", "yaml", "shop/web"}, "want text or json"},
		{[]string{"explain", "request", "--file", "x", "--pod", "a/b", "id"}, "--file and --pod"},
		{[]string{"explain", "request", "--pod", "b", "id"}, "want namespace/name"},
		{[]string{"explain", "request", "--rule-set", "x", "id"}, "need --policy"},
		{[]string{"explain", "request", strings.Repeat("x", 129)}, "1 to 128 bytes"},
	} {
		code, _, errOut := runCLI(t, tc.args...)
		if code != 2 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%q: exit %d, %q; want 2 and %q", tc.args, code, errOut, tc.want)
		}
	}
	// No cluster: an error, unless the events and the policy are files.
	saved := newExplainCluster
	t.Cleanup(func() { newExplainCluster = saved })
	newExplainCluster = func(string, string) (*explainCluster, error) { return nil, errors.New("no kubeconfig") }
	if code, _, errOut := runCLI(t, "explain", "policy", "shop/web"); code != 2 || !strings.Contains(errOut, "no kubeconfig") {
		t.Errorf("policy without a cluster: exit %d, %s", code, errOut)
	}
	if code, out, errOut := runCLI(t, "explain", "request", "--file", "testdata/explain/engine.log", "-o", "json", "req-deny"); code != 0 ||
		!strings.Contains(out, `"verified": false`) || !strings.Contains(out, "--policy") {
		t.Errorf("file without a cluster or policies: exit %d, %s%s", code, out, errOut)
	}
}

// The threshold, as the engine compiles the policy: no rule sets is the CRS
// with its defaults; rule sets without the CRS have none.
func TestInboundThreshold(t *testing.T) {
	b := &bundlev1.Bundle{
		RuleSets: []*bundlev1.RuleSet{
			{Id: "crs", Source: &bundlev1.RuleSet_Builtin{Builtin: bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4}},
			{Id: "own", Source: &bundlev1.RuleSet_Seclang{Seclang: "SecRule ..."}},
		},
		Policies: []*bundlev1.Policy{
			{Id: "a/none"},
			{Id: "a/crs", RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "own"}, {RuleSetId: "crs", InboundAnomalyThreshold: 12}}},
			{Id: "a/crs-default", RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "crs"}}},
			{Id: "a/own", RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "own"}}},
		},
	}
	for id, want := range map[string]int{"a/none": 5, "a/crs": 12, "a/crs-default": 5, "a/own": 0, "a/missing": 0} {
		if got := inboundThreshold(b, id); got != want {
			t.Errorf("%s: %d, want %d", id, got, want)
		}
	}
	if got := inboundThreshold(nil, "a/none"); got != 0 {
		t.Errorf("no bundle: %d", got)
	}
}

// A policy that can't take the suggestion (64 exclusions already): explain
// says so without tune's --min-count, which isn't one of its flags; tune
// still suggests it.
func TestExclusionLimitMessage(t *testing.T) {
	in, _, err := loadObjects([]string{"testdata/policy/wafpolicy.yaml", "testdata/policy/wafruleset.yaml", "testdata/policy/configmap.yaml"}, "shop", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	p := &in.Policies[slices.IndexFunc(in.Policies, func(p wafv1alpha1.WAFPolicy) bool { return p.Name == "storefront" })]
	for i := range 64 {
		p.Spec.Exclusions = append(p.Spec.Exclusions, wafv1alpha1.Exclusion{RuleIDs: []int32{int32(920000 + i)}})
	}
	ec, _ := explainTestCluster(t, p)
	withExplainCluster(t, ec)
	code, out, errOut := runCLI(t, "explain", "request", "-o", "json", "--pod", "traefik/traefik-2", "req-deny")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "over the 64 a policy takes") || strings.Contains(out, "--min-count") {
		t.Errorf("explain's error:\n%s", out)
	}

	f := writeFile(t, "policy.yaml", "")
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCLI(t, "tune", "--from-logs", "--policy", f, "--rule-set", "testdata/policy/wafruleset.yaml", "testdata/explain/engine.log")
	if code != 1 || !strings.Contains(errOut, "raise --min-count") {
		t.Errorf("tune: exit %d, %s", code, errOut)
	}
}
