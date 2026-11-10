// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The Reporter writes a policy's status only when Enforced or Ready
// changes, not when engines come and go, and writes several at once.
func TestReporterWrites(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)

	const policies = 40
	var objs []client.Object
	for i := range policies {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p" + strconv.Itoa(i), Generation: 1}}
		p.Status.ObservedGeneration = 1
		p.Status.BundleVersion = 1
		for _, c := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed} {
			meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c, ObservedGeneration: 1})
		}
		objs = append(objs, p)
	}
	report := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + "a", Labels: map[string]string{EnginesLabel: "true"}}}
	setEngines := func(c client.Client, engines ...Engine) {
		t.Helper()
		data, _ := json.Marshal(engines)
		report.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := c.Update(ctx, report); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu                    sync.Mutex
		writes, running, most int
	)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(append(objs, report)...).
		WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			mu.Lock()
			writes++
			running++
			most = max(most, running)
			mu.Unlock()
			defer func() { mu.Lock(); running--; mu.Unlock() }()
			time.Sleep(10 * time.Millisecond)
			return c.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	r := &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: time.Minute, Store: NewStore()}

	step := func(what string, want int, engines ...Engine) {
		t.Helper()
		setEngines(c, engines...)
		writes = 0
		if err := r.report(ctx); err != nil {
			t.Fatal(err)
		}
		if got := writes; got != want {
			t.Errorf("%s: %d status writes, want %d", what, got, want)
		}
	}
	step("first engine", policies, Engine{ID: "e1", Applied: 1})
	if most < 2 || most > statusWriters {
		t.Errorf("%d writes at once, want 2 to %d", most, statusWriters)
	}
	step("same engines", 0, Engine{ID: "e1", Applied: 1})
	step("another engine, current", 0, Engine{ID: "e1", Applied: 1}, Engine{ID: "e2", Applied: 1})
	step("one engine gone", 0, Engine{ID: "e2", Applied: 1})
	step("an engine behind", policies, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3"})
	step("another engine behind", 0, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3"}, Engine{ID: "e4"})
	step("caught up", policies, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3", Applied: 1}, Engine{ID: "e4", Applied: 1})

	var p wafv1alpha1.WAFPolicy
	if err := c.Get(ctx, client.ObjectKey{Namespace: "web", Name: "p0"}, &p); err != nil {
		t.Fatal(err)
	}
	if cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionReady); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("Ready: %+v", cond)
	}
}

// A suspended bundle enforces nothing; and when inspection resumes, the
// policy's version in the bundle served counts before the builder writes
// it into the status (#263).
func TestEnforcedSuspended(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
	p.Status.BundleVersion = 3
	engines := []Engine{{ID: "e1", Applied: 3}}
	for _, tc := range []struct {
		name      string
		served    uint64
		suspended bool
		status    metav1.ConditionStatus
		reason    string
	}{
		{"enforced", 3, false, metav1.ConditionTrue, ReasonEnforced},
		{"suspended", 3, true, metav1.ConditionFalse, ReasonSuspended},
		{"resumed, status not written yet", 4, false, metav1.ConditionFalse, ReasonEnginesBehind},
		{"served bundle older than the status", 2, false, metav1.ConditionTrue, ReasonEnforced},
	} {
		conds, _ := enforcedConditions(p, tc.served, tc.suspended, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Status != tc.status || c.Reason != tc.reason {
			t.Errorf("%s: Enforced %+v, want %s %s", tc.name, c, tc.status, tc.reason)
		}
		if tc.suspended && !strings.Contains(c.Message, "InkwallConfig default") {
			t.Errorf("%s: message %q doesn't name the InkwallConfig", tc.name, c.Message)
		}
		// Nothing else reported: that is Ready's reason, unless inspection is
		// suspended (#291).
		want := "NotAccepted"
		if tc.suspended {
			want = ReasonSuspended
		}
		if r := meta.FindStatusCondition(conds, wafv1alpha1.ConditionReady); r == nil || r.Status != metav1.ConditionFalse || r.Reason != want {
			t.Errorf("%s: Ready %+v, want False %s", tc.name, r, want)
		}
	}
}

// An engine before 0.4.0 ignores spec.webSocket: a policy that sets it
// isn't Enforced while one is connected (#276).
func TestEnforcedOutdatedEngine(t *testing.T) {
	ws := &wafv1alpha1.WebSocketSpec{AllowedOrigins: []wafv1alpha1.WebSocketOrigin{"https://app.example.com"}}
	for _, tc := range []struct {
		name     string
		spec     *wafv1alpha1.WebSocketSpec
		versions []string
		status   metav1.ConditionStatus
		reason   string
	}{
		{"0.3.1 engine", ws, []string{"0.4.0", "0.3.1"}, metav1.ConditionFalse, ReasonEnginesOutdated},
		{"v-prefixed pre-release", ws, []string{"v0.4.0-rc.1", "v0.3.2-0.20261103000000-abcdef+dirty"}, metav1.ConditionFalse, ReasonEnginesOutdated},
		{"new engines", ws, []string{"0.4.0", "v0.4.1", "1.0.0", "0.4.0-rc.1"}, metav1.ConditionTrue, ReasonEnforced},
		{"development builds", ws, []string{"unknown", "(devel)", ""}, metav1.ConditionTrue, ReasonEnforced},
		{"policy without webSocket", nil, []string{"0.3.1"}, metav1.ConditionTrue, ReasonEnforced},
		{"empty webSocket", &wafv1alpha1.WebSocketSpec{}, []string{"0.3.1"}, metav1.ConditionTrue, ReasonEnforced},
		{"required headers only", &wafv1alpha1.WebSocketSpec{RequiredHeaders: []wafv1alpha1.HeaderName{"Authorization"}}, []string{"0.2.0"}, metav1.ConditionFalse, ReasonEnginesOutdated},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.WebSocket = tc.spec
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("traefik-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Status != tc.status || c.Reason != tc.reason {
			t.Errorf("%s: Enforced %+v, want %s %s", tc.name, c, tc.status, tc.reason)
			continue
		}
		if tc.reason == ReasonEnginesOutdated && (!strings.Contains(c.Message, "spec.webSocket") || !strings.Contains(c.Message, "edge/traefik-") || !strings.Contains(c.Message, "0.4.0 or later")) {
			t.Errorf("%s: message %q doesn't name the field, the engine and the version", tc.name, c.Message)
		}
	}
	// Responses too (#274): an engine before 0.4.0 inspects requests only.
	for _, tc := range []struct {
		name     string
		spec     *wafv1alpha1.ResponsesSpec
		versions []string
		reason   string
	}{
		{"responses, 0.3.1 engine", &wafv1alpha1.ResponsesSpec{Inspect: true}, []string{"0.4.0", "0.3.1"}, ReasonEnginesOutdated},
		{"responses, new engines", &wafv1alpha1.ResponsesSpec{Inspect: true}, []string{"0.4.0"}, ReasonEnforced},
		{"responses off", &wafv1alpha1.ResponsesSpec{}, []string{"0.3.1"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.Responses = tc.spec
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("envoy-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason || tc.reason == ReasonEnginesOutdated && !strings.Contains(c.Message, "spec.responses") {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
		}
	}

	// CRS settings (#352): an engine before 0.5.0 ignores them.
	crs := []wafv1alpha1.RuleSetBinding{{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"},
		CRS: &wafv1alpha1.CRSSettings{AllowedMethods: []wafv1alpha1.HTTPMethodToken{"GET", "PUT"}}}}
	for _, tc := range []struct {
		name     string
		ruleSets []wafv1alpha1.RuleSetBinding
		versions []string
		reason   string
	}{
		{"crs, 0.4.1 engine", crs, []string{"0.5.0", "0.4.1"}, ReasonEnginesOutdated},
		{"crs, new engines", crs, []string{"0.5.0", "v0.5.0-rc.1"}, ReasonEnforced},
		{"empty crs", []wafv1alpha1.RuleSetBinding{{CRS: &wafv1alpha1.CRSSettings{}}}, []string{"0.4.1"}, ReasonEnforced},
		{"no crs", []wafv1alpha1.RuleSetBinding{{ParanoiaLevel: ptr.To(int32(2))}}, []string{"0.4.1"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.RuleSets = tc.ruleSets
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("envoy-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason || tc.reason == ReasonEnginesOutdated && (!strings.Contains(c.Message, "spec.ruleSets[0].crs") || !strings.Contains(c.Message, "0.5.0 or later")) {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
		}
	}

	// A rule set placed before the CRS (#423): an engine before 0.6.0
	// loads it after the CRS, where its TX settings come too late.
	before := []wafv1alpha1.RuleSetBinding{
		{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "tune"}, Placement: wafv1alpha1.PlacementBeforeCRS},
	}
	for _, tc := range []struct {
		name     string
		ruleSets []wafv1alpha1.RuleSetBinding
		versions []string
		reason   string
	}{
		{"BeforeCRS, 0.5.0 engine", before, []string{"0.6.0", "0.5.0"}, ReasonEnginesOutdated},
		{"BeforeCRS, new engines", before, []string{"0.6.0", "v0.6.0-rc.1"}, ReasonEnforced},
		{"AfterCRS, 0.5.0 engine", []wafv1alpha1.RuleSetBinding{{Placement: wafv1alpha1.PlacementAfterCRS}}, []string{"0.5.0"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.RuleSets = tc.ruleSets
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("envoy-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason || tc.reason == ReasonEnginesOutdated && (!strings.Contains(c.Message, "spec.ruleSets[1].placement") || !strings.Contains(c.Message, "0.6.0 or later")) {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
		}
	}

	// IP lists (#358): an engine before 0.5.0 ignores them, so it wouldn't
	// deny what the deny list names.
	for _, tc := range []struct {
		name     string
		lists    *wafv1alpha1.IPListsSpec
		versions []string
		reason   string
	}{
		{"deny list, 0.4.1 engine", &wafv1alpha1.IPListsSpec{Deny: []wafv1alpha1.IPListName{"bad"}}, []string{"0.5.0", "0.4.1"}, ReasonEnginesOutdated},
		{"deny list, new engines", &wafv1alpha1.IPListsSpec{Deny: []wafv1alpha1.IPListName{"bad"}}, []string{"0.5.0"}, ReasonEnforced},
		{"empty", &wafv1alpha1.IPListsSpec{}, []string{"0.4.1"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.IPLists = tc.lists
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("envoy-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason || tc.reason == ReasonEnginesOutdated && !strings.Contains(c.Message, "spec.ipLists") {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
		}
	}

	// Cookie, header and argument name exclusions (#357): an engine before
	// 0.5.0 ignores them.
	for _, tc := range []struct {
		name       string
		exclusions []wafv1alpha1.Exclusion
		versions   []string
		reason     string
	}{
		{"cookie, 0.4.1 engine", []wafv1alpha1.Exclusion{{RuleIDs: []int32{1}, When: &wafv1alpha1.ExclusionMatch{Path: "/a"}}, {RuleIDs: []int32{1}, When: &wafv1alpha1.ExclusionMatch{Cookie: "s"}}}, []string{"0.5.0", "0.4.1"}, ReasonEnginesOutdated},
		{"header, new engines", []wafv1alpha1.Exclusion{{RuleIDs: []int32{1}, When: &wafv1alpha1.ExclusionMatch{Header: "X"}}}, []string{"0.5.0"}, ReasonEnforced},
		{"argument, 0.4.1 engine", []wafv1alpha1.Exclusion{{RuleIDs: []int32{1}, When: &wafv1alpha1.ExclusionMatch{Argument: "q"}}}, []string{"0.4.1"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.Exclusions = tc.exclusions
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("envoy-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason || tc.reason == ReasonEnginesOutdated && !strings.Contains(c.Message, "spec.exclusions[1].when") {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
		}
	}

	// Behind comes first: the engine doesn't run the bundle at all.
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
	p.Spec.WebSocket = ws
	p.Status.BundleVersion = 3
	conds, _ := enforcedConditions(p, 3, false, []Engine{{ID: "e", EngineVersion: "0.3.1", Applied: 2}}, 0)
	if c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced); c == nil || c.Reason != ReasonEnginesBehind {
		t.Errorf("behind and outdated: Enforced %+v, want EnginesBehind", c)
	}
}

// An engine before 0.4.0 ignores spec.body.grpcMessages, and leaves gRPC
// messages uninspected: a policy that sets Inspect isn't Enforced while one
// is connected (#275).
func TestEnforcedOutdatedEngineGRPCMessages(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     *wafv1alpha1.BodySpec
		versions []string
		reason   string
	}{
		{"0.3.1 engine", &wafv1alpha1.BodySpec{GRPCMessages: wafv1alpha1.GRPCMessagesInspect}, []string{"0.4.0", "0.3.1"}, ReasonEnginesOutdated},
		{"new engines", &wafv1alpha1.BodySpec{GRPCMessages: wafv1alpha1.GRPCMessagesInspect}, []string{"0.4.0", "v0.4.1"}, ReasonEnforced},
		{"Skip", &wafv1alpha1.BodySpec{GRPCMessages: wafv1alpha1.GRPCMessagesSkip}, []string{"0.3.1"}, ReasonEnforced},
		{"no body", nil, []string{"0.3.1"}, ReasonEnforced},
		// body.grpc: Deny (#367): an engine before 0.5.0 lets gRPC through.
		{"grpc Deny, 0.4.1 engine", &wafv1alpha1.BodySpec{GRPC: wafv1alpha1.GRPCDeny}, []string{"0.5.0", "0.4.1"}, ReasonEnginesOutdated},
		{"grpc Deny, new engines", &wafv1alpha1.BodySpec{GRPC: wafv1alpha1.GRPCDeny}, []string{"0.5.0"}, ReasonEnforced},
		{"grpc Allow", &wafv1alpha1.BodySpec{GRPC: wafv1alpha1.GRPCAllow}, []string{"0.4.1"}, ReasonEnforced},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
		p.Spec.Body = tc.body
		p.Status.BundleVersion = 3
		var engines []Engine
		for i, v := range tc.versions {
			engines = append(engines, Engine{ID: fmt.Sprintf("e%d", i), PodNamespace: "edge", PodName: fmt.Sprintf("traefik-%d", i), EngineVersion: v, Applied: 3})
		}
		conds, _ := enforcedConditions(p, 3, false, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Reason != tc.reason {
			t.Errorf("%s: Enforced %+v, want %s", tc.name, c, tc.reason)
			continue
		}
		field := "spec.body.grpcMessages"
		if tc.body != nil && tc.body.GRPC == wafv1alpha1.GRPCDeny {
			field = "spec.body.grpc,"
		}
		if tc.reason == ReasonEnginesOutdated && !strings.Contains(c.Message, field) {
			t.Errorf("%s: message %q doesn't name the field", tc.name, c.Message)
		}
	}
}

// A policy setting fields of several releases needs the newest: an engine
// new enough for the first field but not for a later one is outdated (#473).
func TestEnforcedOutdatedNewestField(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
	p.Spec.WebSocket = &wafv1alpha1.WebSocketSpec{AllowedOrigins: []wafv1alpha1.WebSocketOrigin{"https://app.example.com"}}
	p.Spec.IPLists = &wafv1alpha1.IPListsSpec{Deny: []wafv1alpha1.IPListName{"blocked"}}
	p.Status.BundleVersion = 3
	engines := []Engine{{ID: "e0", PodNamespace: "edge", PodName: "traefik-0", EngineVersion: "0.4.1", Applied: 3}}
	conds, _ := enforcedConditions(p, 3, false, engines, 0)
	c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
	if c == nil || c.Reason != ReasonEnginesOutdated || !strings.Contains(c.Message, "spec.ipLists") || !strings.Contains(c.Message, "0.5.0 or later") {
		t.Errorf("a 0.4.1 engine and a policy with webSocket and ipLists: Enforced %+v, want EnginesOutdated naming spec.ipLists", c)
	}
}

// A 0.5.0 field before a 0.6.0 one: the 0.6.0 one is named (#423).
func TestEnforcedOutdatedNewestFieldPlacement(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}, CRS: &wafv1alpha1.CRSSettings{AllowedMethods: []wafv1alpha1.HTTPMethodToken{"GET", "PUT"}}},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "tune"}, Placement: wafv1alpha1.PlacementBeforeCRS},
	}
	p.Spec.IPLists = &wafv1alpha1.IPListsSpec{Deny: []wafv1alpha1.IPListName{"blocked"}}
	p.Status.BundleVersion = 3
	engines := []Engine{{ID: "e0", PodNamespace: "edge", PodName: "traefik-0", EngineVersion: "0.5.0", Applied: 3}}
	conds, _ := enforcedConditions(p, 3, false, engines, 0)
	c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
	if c == nil || c.Reason != ReasonEnginesOutdated || !strings.Contains(c.Message, "spec.ruleSets[1].placement") || !strings.Contains(c.Message, "0.6.0 or later") {
		t.Errorf("a 0.5.0 engine and a policy with crs, ipLists and a BeforeCRS rule set: Enforced %+v, want EnginesOutdated naming spec.ruleSets[1].placement", c)
	}
}

// The InkwallConfig's status counts the engines (#375), and 1,000 engines
// connecting one per report don't rewrite it more than once per
// ConfigEvery; the last count is written once the engines settle.
func TestReporterConfigStatus(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "lists"}}
	p.Spec.IPLists = &wafv1alpha1.IPListsSpec{Deny: []wafv1alpha1.IPListName{"blocked"}}
	report := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + "a", Labels: map[string]string{EnginesLabel: "true"}}}
	var writes int
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cfg, p, report).
		WithStatusSubresource(&wafv1alpha1.WAFPolicy{}, &wafv1alpha1.InkwallConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if _, ok := obj.(*wafv1alpha1.InkwallConfig); ok {
				writes++
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	now := time.Unix(1_800_000_000, 0)
	store := NewStore()
	store.Set(&bundlev1.SignedBundle{}, 2)
	r := &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: time.Minute, Store: store, Now: func() time.Time { return now }}

	var engines []Engine
	report.Data = map[string]string{}
	set := func() {
		t.Helper()
		data, _ := json.Marshal(engines)
		report.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := c.Update(ctx, report); err != nil {
			t.Fatal(err)
		}
		if err := r.report(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// 1,000 engines, one more every 100 ms: 100 s.
	for i := range 1000 {
		// A quarter each: current, rejecting bundle 2, behind, and current
		// but a release too old for the policy's IP lists.
		e := Engine{ID: fmt.Sprintf("e%d", i), EngineVersion: "0.5.0", Applied: 2}
		switch i % 4 {
		case 1:
			e.Applied, e.Rejected = 1, 2
		case 2:
			e.Applied = 1
		case 3:
			e.EngineVersion = "0.4.1"
		}
		engines = append(engines, e)
		set()
		now = now.Add(100 * time.Millisecond)
	}
	if most := int(100*time.Second/DefaultConfigEvery) + 1; writes > most {
		t.Errorf("%d InkwallConfig status writes for 1,000 engines connecting over 100 s, want at most %d", writes, most)
	}
	now = now.Add(DefaultConfigEvery)
	set()
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); err != nil {
		t.Fatal(err)
	}
	want := wafv1alpha1.EngineCounts{Connected: 1000, Current: 500, Behind: 250, Rejected: 250, Outdated: 250}
	if got := cfg.Status.Engines; got == nil || *got != want {
		t.Errorf("engines %+v, want %+v", got, want)
	}
	// Unchanged: not written again.
	before := writes
	now = now.Add(DefaultConfigEvery)
	set()
	if writes != before {
		t.Error("unchanged engine counts written again")
	}
}
