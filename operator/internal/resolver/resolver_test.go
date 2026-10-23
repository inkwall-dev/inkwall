// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// policy returns a WAFPolicy in namespace shop targeting Ingresses. A lower
// age means created earlier.
func policy(name string, age int, targets ...string) wafv1alpha1.WAFPolicy {
	p := wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "shop",
		Name:              name,
		CreationTimestamp: metav1.NewTime(t0.Add(time.Duration(age) * time.Minute)),
	}}
	for _, t := range targets {
		p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Kind: "Ingress", Name: t})
	}
	return p
}

func ingress(name string, rules ...networkingv1.IngressRule) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec:       networkingv1.IngressSpec{Rules: rules},
	}
}

func rule(host string, paths ...networkingv1.HTTPIngressPath) networkingv1.IngressRule {
	return networkingv1.IngressRule{Host: host, IngressRuleValue: networkingv1.IngressRuleValue{
		HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths},
	}}
}

func ipath(p string, t networkingv1.PathType) networkingv1.HTTPIngressPath {
	return networkingv1.HTTPIngressPath{Path: p, PathType: &t}
}

func prefix(host, value string) *bundlev1.RouteMatch {
	return &bundlev1.RouteMatch{Host: host, Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: value}}
}

func exact(host, value string) *bundlev1.RouteMatch {
	return &bundlev1.RouteMatch{Host: host, Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT, Value: value}}
}

func seclangRuleSet(name, rules string) wafv1alpha1.WAFRuleSet {
	return wafv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: rules}},
	}
}

func useRuleSet(p *wafv1alpha1.WAFPolicy, name string) {
	p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
}

func key(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: "shop", Name: name}
}

func ptr[T any](v T) *T { return &v }

func wantStatus(t *testing.T, res Result, name string, accepted bool, reason, msg string) {
	t.Helper()
	st, ok := res.PolicyStatus[key(name)]
	if !ok {
		t.Fatalf("no status for %s", name)
	}
	if st.Accepted != accepted || st.Reason != reason || !strings.Contains(st.Message, msg) {
		t.Fatalf("%s: status %+v, want accepted=%v reason=%s and a message containing %q", name, st, accepted, reason, msg)
	}
}

func findPolicy(res Result, id string) *bundlev1.Policy {
	for _, p := range res.Policies {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

func wantProto(t *testing.T, got, want proto.Message) {
	t.Helper()
	if !proto.Equal(got, want) {
		t.Fatalf("got\n  %v\nwant\n  %v", got, want)
	}
}

func TestResolvePolicy(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.Mode = wafv1alpha1.PolicyBlock
	p.Spec.FailureMode = wafv1alpha1.FailOpen
	p.Spec.Timeout = &metav1.Duration{Duration: 100 * time.Millisecond}
	p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/healthz"}, BodyPaths: []wafv1alpha1.PathPattern{"/upload"}}
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}, ParanoiaLevel: ptr(int32(2)), InboundAnomalyThreshold: ptr(int32(7))},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "custom"}},
	}
	p.Spec.Exclusions = []wafv1alpha1.Exclusion{
		{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Path: "/search", Argument: "q"}},
		{RuleIDs: []int32{920350}},
	}
	p.Spec.Body = &wafv1alpha1.BodySpec{MaxBytes: ptr(int64(1024)), OnOversize: wafv1alpha1.OversizeDeny}

	res := Resolve(Input{
		Policies: []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop",
			rule("Shop.Example.com",
				ipath("/", networkingv1.PathTypePrefix),
				ipath("/api/", networkingv1.PathTypeImplementationSpecific),
				ipath("/login", networkingv1.PathTypeExact)),
			rule("*.shop.example.com", ipath("/static", networkingv1.PathTypePrefix)),
		)},
		RuleSets: []wafv1alpha1.WAFRuleSet{seclangRuleSet("custom", "SecMarker X"), seclangRuleSet("unused", "SecMarker Y")},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "crs"},
			Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
		}},
	})

	wantStatus(t, res, "shop", true, ReasonAccepted, "valid")
	if !res.PolicyStatus[key("shop")].Applied {
		t.Error("an accepted policy must be applied")
	}
	if len(res.Policies) != 1 {
		t.Fatalf("got %d policies", len(res.Policies))
	}
	wantProto(t, res.Policies[0], &bundlev1.Policy{
		Id: "shop/shop",
		Routes: []*bundlev1.RouteMatch{
			prefix("shop.example.com", "/"),
			prefix("shop.example.com", "/api"), // ImplementationSpecific: a prefix; the trailing slash dropped
			exact("shop.example.com", "/login"),
			prefix("*.shop.example.com", "/static"),
		},
		Mode:          bundlev1.Mode_MODE_BLOCK,
		FailureMode:   bundlev1.FailureMode_FAILURE_MODE_OPEN,
		Timeout:       durationpb.New(100 * time.Millisecond),
		SkipPaths:     []string{"/healthz"},
		SkipBodyPaths: []string{"/upload"},
		RuleSets: []*bundlev1.RuleSetBinding{
			{RuleSetId: "ClusterWAFRuleSet/crs", ParanoiaLevel: 2, InboundAnomalyThreshold: 7},
			{RuleSetId: "WAFRuleSet/shop/custom"},
		},
		Exclusions: []*bundlev1.Exclusion{
			{RuleIds: []uint32{942100}, Path: "/search", Argument: "q"},
			{RuleIds: []uint32{920350}},
		},
		Body: &bundlev1.BodyConfig{Inspect: true, MaxBytes: 1024, OnOversize: bundlev1.OversizeAction_OVERSIZE_ACTION_DENY},
	})
	// Only the rule sets in use are in the bundle; all of them get a status.
	var ids []string
	for _, rs := range res.RuleSets {
		ids = append(ids, rs.GetId())
	}
	if !slices.Equal(ids, []string{"ClusterWAFRuleSet/crs", "WAFRuleSet/shop/custom"}) {
		t.Errorf("rule sets %v", ids)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/unused"]; !st.Accepted {
		t.Errorf("unused rule set status %+v", st)
	}
}

func TestDefaults(t *testing.T) {
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{policy("shop", 0, "shop")},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("", ipath("", networkingv1.PathTypePrefix)))},
	})
	// Detect mode, no host (any), an empty path is "/".
	wantProto(t, res.Policies[0], &bundlev1.Policy{
		Id:     "shop/shop",
		Mode:   bundlev1.Mode_MODE_DETECT,
		Routes: []*bundlev1.RouteMatch{prefix("", "/")},
	})
}

func TestDefaultBackend(t *testing.T) {
	only := ingress("default-only")
	only.Spec.DefaultBackend = &networkingv1.IngressBackend{}
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{policy("shop", 0, "default-only")}, Ingresses: []networkingv1.Ingress{only}})
	wantProto(t, res.Policies[0].GetRoutes()[0], prefix("", "/"))
}

func TestMissingTarget(t *testing.T) {
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{policy("shop", 0, "shop", "gone")},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "Ingress gone not found; the policy applies to its other targets")
	if !res.PolicyStatus[key("shop")].Applied {
		t.Error("a policy with a missing target still applies to the others")
	}
	if p := findPolicy(res, "shop/shop"); p == nil || len(p.GetRoutes()) != 1 {
		t.Fatalf("the policy must still cover its existing target: %v", p)
	}
}

func TestMissingRuleSet(t *testing.T) {
	p := policy("shop", 0, "shop")
	useRuleSet(&p, "custom")
	in := Input{
		Policies:  []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	}

	// Never resolved: left out.
	res := Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "WAFRuleSet custom not found")
	if len(res.Policies) != 0 {
		t.Fatalf("an unresolvable new policy must be left out: %v", res.Policies)
	}

	// Resolved before: the previous version stays, with its rule set.
	in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("custom", "SecMarker OLD")}
	good := Resolve(in)
	prev := &bundlev1.Bundle{Version: 7, Policies: good.Policies, RuleSets: good.RuleSets}

	in.RuleSets = nil
	in.Previous = prev
	in.Policies[0].Spec.Mode = wafv1alpha1.PolicyBlock // an edit that can't take effect
	res = Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "the previous version of the policy stays in force")
	if res.PolicyStatus[key("shop")].Applied {
		t.Error("a fallback to the previous version is not the current spec applied")
	}
	wantProto(t, findPolicy(res, "shop/shop"), prev.Policies[0])
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker OLD" {
		t.Fatalf("the previous rule set must stay: %v", res.RuleSets)
	}
}

func TestCrossNamespaceRuleSet(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "theirs", Namespace: "other"}}}
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "use a ClusterWAFRuleSet")
}

func TestConflict(t *testing.T) {
	older, newer := policy("older", 0, "shop"), policy("newer", 1, "shop")
	newer.Spec.Mode = wafv1alpha1.PolicyBlock
	res := Resolve(Input{
		// Input order doesn't matter: creation time decides.
		Policies:  []wafv1alpha1.WAFPolicy{newer, older},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	})
	wantStatus(t, res, "older", true, ReasonAccepted, "valid")
	wantStatus(t, res, "newer", false, ReasonConflict, "older WAFPolicy older")
	if len(res.Policies) != 1 || res.Policies[0].GetId() != "shop/older" {
		t.Fatalf("only the older policy applies: %v", res.Policies)
	}
}

func TestSharedRoute(t *testing.T) {
	// Two Ingresses with the same host and path, each with its policy: the
	// older policy gets the route, the newer keeps its other routes.
	res := Resolve(Input{
		Policies: []wafv1alpha1.WAFPolicy{policy("a", 0, "a"), policy("b", 1, "b")},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix), ipath("/b", networkingv1.PathTypePrefix))),
		},
	})
	wantStatus(t, res, "b", true, ReasonAccepted, "shop.example.com/ (older policy shop/a)")
	if got := findPolicy(res, "shop/b").GetRoutes(); len(got) != 1 || got[0].GetPath().GetValue() != "/b" {
		t.Fatalf("policy b routes: %v", got)
	}
}

func TestConfigMapRules(t *testing.T) {
	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "rules"},
		Data:       map[string]string{"good.conf": "SecMarker GOOD", "bad.conf": "SecRuleEngine Off"},
	}
	fromCM := func(name, k string) wafv1alpha1.WAFRuleSet {
		return wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{ConfigMapRef: &wafv1alpha1.ConfigMapKeyRef{Name: "rules", Key: k}}},
		}
	}
	check := func(rules string) error {
		if strings.Contains(rules, "SecRuleEngine") {
			return errors.New(`line 1: directive "secruleengine" is not allowed`)
		}
		return nil
	}
	in := Input{
		RuleSets:   []wafv1alpha1.WAFRuleSet{fromCM("good", "good.conf"), fromCM("bad", "bad.conf"), fromCM("nokey", "missing.conf")},
		CheckRules: check,
	}

	res := Resolve(in)
	if st := res.RuleSetStatus["WAFRuleSet/shop/good"]; st.Accepted || !strings.Contains(st.Message, "not labeled "+RulesLabel) {
		t.Errorf("ConfigMap not watched: %+v", st)
	}

	in.ConfigMaps = []corev1.ConfigMap{cm}
	p := policy("shop", 0)
	useRuleSet(&p, "good")
	q := policy("broken", 0)
	useRuleSet(&q, "bad")
	in.Policies = []wafv1alpha1.WAFPolicy{p, q}
	res = Resolve(in)
	if st := res.RuleSetStatus["WAFRuleSet/shop/good"]; !st.Accepted {
		t.Errorf("good: %+v", st)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/bad"]; st.Accepted || st.Reason != ReasonRuleCompileError || !strings.Contains(st.Message, "line 1") {
		t.Errorf("bad: %+v", st)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/nokey"]; st.Accepted || !strings.Contains(st.Message, `no key "missing.conf"`) {
		t.Errorf("nokey: %+v", st)
	}
	wantStatus(t, res, "broken", false, ReasonInvalidRef, "WAFRuleSet bad is not usable: ConfigMap shop/rules key \"bad.conf\": line 1")
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker GOOD" {
		t.Fatalf("the ConfigMap's rules must be inlined: %v", res.RuleSets)
	}
}

func TestHTTPRouteNotYet(t *testing.T) {
	p := policy("shop", 0)
	p.Spec.TargetRefs = []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "api"}}
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}})
	wantStatus(t, res, "shop", false, ReasonTargetUnsupported, "only Ingress targets are resolved so far")
}

func TestDeterministic(t *testing.T) {
	var in Input
	for i := range 20 {
		name := string(rune('a' + i))
		p := policy(name, i%3, name, "shared")
		in.Policies = append(in.Policies, p)
		in.Ingresses = append(in.Ingresses, ingress(name, rule(name+".example.com", ipath("/", networkingv1.PathTypePrefix))))
	}
	in.Ingresses = append(in.Ingresses, ingress("shared", rule("shared.example.com", ipath("/", networkingv1.PathTypePrefix))))
	want := Resolve(in)
	for range 10 {
		rand.Shuffle(len(in.Policies), func(i, j int) { in.Policies[i], in.Policies[j] = in.Policies[j], in.Policies[i] })
		rand.Shuffle(len(in.Ingresses), func(i, j int) { in.Ingresses[i], in.Ingresses[j] = in.Ingresses[j], in.Ingresses[i] })
		got := Resolve(in)
		wantProto(t, &bundlev1.Bundle{Policies: got.Policies, RuleSets: got.RuleSets}, &bundlev1.Bundle{Policies: want.Policies, RuleSets: want.RuleSets})
	}
}
