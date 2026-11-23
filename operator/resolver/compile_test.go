// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"context"
	"net/http"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	enginepolicy "github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// verdictFor compiles a resolution as the engine does and checks an SQL
// injection to host.
func verdictFor(t *testing.T, res Result, host string) pipeline.Verdict {
	t.Helper()
	set, err := enginepolicy.Compile(&bundlev1.Bundle{Version: 1, Policies: res.Policies, RuleSets: res.RuleSets}, enginepolicy.Options{})
	if err != nil {
		t.Fatalf("the bundle doesn't compile: %v", err)
	}
	r := &request.Request{Proto: "HTTP/1.1", Method: "GET", Scheme: "https", Host: host,
		RawURI: "/?id=1%27%20OR%20%271%27%3D%271", Headers: http.Header{"User-Agent": {"Mozilla/5.0"}, "Accept": {"text/html"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return set.Check(ctx, r)
}

// compileInput is two Block policies, "bad" on a.example.com and "other" on
// b.example.com, with the built-in CRS.
func compileInput() Input {
	crs := wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}}
	bad := policy("bad", 0, "a")
	other := policy("other", 1, "b")
	for _, p := range []*wafv1alpha1.WAFPolicy{&bad, &other} {
		p.Spec.Mode = wafv1alpha1.PolicyBlock
		p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{crs}
	}
	return Input{
		Policies: []wafv1alpha1.WAFPolicy{bad, other},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "crs"},
			Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
		}},
		CheckPolicy: enginepolicy.NewRuleChecker().Check,
	}
}

// wantLeftOut: policy bad isn't Accepted, with reason and msg, and is left
// out of the bundle, which compiles and enforces the other policy; its
// previous version stays, when it compiles.
func wantLeftOut(t *testing.T, in Input, reason, msg string) {
	t.Helper()
	res := Resolve(in)
	wantStatus(t, res, "bad", false, reason, msg)
	wantStatus(t, res, "other", true, ReasonAccepted, PolicyValid)
	if findPolicy(res, "shop/bad") != nil {
		t.Fatal("a policy the engine can't compile must stay out of the bundle")
	}
	if v := verdictFor(t, res, "b.example.com"); v.Action != pipeline.ActionDeny || v.Policy != "shop/other" {
		t.Errorf("the other policy: %v of %q, want its deny", v.Action, v.Policy)
	}

	// The policy's previous version, with the CRS alone, stays in force.
	good := compileInput()
	good.Policies[0].Spec.RuleSets = good.Policies[0].Spec.RuleSets[:1]
	prev := Resolve(good)
	in.Previous = &bundlev1.Bundle{Policies: prev.Policies, RuleSets: prev.RuleSets}
	res = Resolve(in)
	wantStatus(t, res, "bad", false, reason, "the previous version of the policy stays in force")
	if findPolicy(res, "shop/bad") == nil {
		t.Fatal("the previous version must stay")
	}
	if v := verdictFor(t, res, "a.example.com"); v.Action != pipeline.ActionDeny || v.Policy != "shop/bad" {
		t.Errorf("the previous version: %v of %q, want its deny", v.Action, v.Policy)
	}
}

// TestExclusionOnRemovedRule: an exclusion of an argument on a rule the
// policy's own SecLang removes, with a negation in it (even in a comment,
// which gives the policy its own compiled rules): the exclusion doesn't
// compile with its rules, so the policy is left out.
func TestExclusionOnRemovedRule(t *testing.T) {
	for name, rules := range map[string]string{
		"a CRS rule":   "# !args\nSecRuleRemoveById 942100",
		"its own rule": "SecRule ARGS|!ARGS:x \"@contains evil\" \"id:10001,phase:2,deny\"\nSecRuleRemoveById 10001",
	} {
		t.Run(name, func(t *testing.T) {
			in := compileInput()
			in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("r", rules)}
			p := &in.Policies[0]
			useRuleSet(p, "r")
			p.Spec.Exclusions = []wafv1alpha1.Exclusion{{RuleIDs: []int32{942100, 10001}, When: &wafv1alpha1.ExclusionMatch{Argument: "foo"}}}
			wantLeftOut(t, in, ReasonRuleSetsIncompatible, "not found")
		})
	}
}

// TestCheckSpec: what the webhook checks of a spec with CheckSpec, as the
// bundle builder does: what the engine wouldn't compile, whatever field.
func TestCheckSpec(t *testing.T) {
	p := policy("p", 0, "a")
	p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/healthz"}}
	p.Spec.Exclusions = []wafv1alpha1.Exclusion{{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Argument: "q"}}}
	if err := CheckSpec(p.Spec); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	p.Spec.Skip.Paths[0] = "/a/../healthz"
	if err := CheckSpec(p.Spec); err == nil {
		t.Error("a skip path that isn't clean compiles")
	}
}

// TestPreviousVersionSharesRuleSet: a policy kept at its previous version
// and another policy bind the same rule set, which changed: the bundle has
// one version of it, the new one, which the previous version doesn't
// compile with (an exclusion on a rule it now removes). The previous version
// is left out, whichever policy is older, and the bundle compiles.
func TestPreviousVersionSharesRuleSet(t *testing.T) {
	for _, badFirst := range []bool{true, false} {
		mk := func(rules string) Input {
			in := compileInput()
			in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("r", rules)}
			for i := range in.Policies {
				useRuleSet(&in.Policies[i], "r")
			}
			in.Policies[0].Spec.Exclusions = []wafv1alpha1.Exclusion{{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Argument: "foo"}}}
			if !badFirst {
				in.Policies[0].CreationTimestamp, in.Policies[1].CreationTimestamp = in.Policies[1].CreationTimestamp, in.Policies[0].CreationTimestamp
			}
			return in
		}
		prev := Resolve(mk("# !args\nSecRule ARGS \"@contains zzz\" \"id:10001,phase:2,deny\""))
		in := mk("# !args\nSecRuleRemoveById 942100")
		in.Previous = &bundlev1.Bundle{Policies: prev.Policies, RuleSets: prev.RuleSets}
		res := Resolve(in)
		wantStatus(t, res, "bad", false, ReasonRuleSetsIncompatible, "so the policy is left out")
		wantStatus(t, res, "other", true, ReasonAccepted, PolicyValid)
		if findPolicy(res, "shop/bad") != nil {
			t.Fatalf("older %v: the previous version must stay out", badFirst)
		}
		// r removes 942100, so the other policy lets the injection
		// through, but applies.
		if v := verdictFor(t, res, "b.example.com"); v.Policy != "shop/other" {
			t.Errorf("older %v: policy %q applies, want shop/other", badFirst, v.Policy)
		}
	}
}

// TestBundleGuard: whatever puts a policy in the bundle that doesn't compile
// with the rule sets the bundle has, the last check leaves it out: a
// previous version that shares a rule set ID with another policy, the rule
// set changed to give a rule ID of another of its rule sets.
func TestBundleGuard(t *testing.T) {
	in := compileInput()
	in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("r", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`),
		seclangRuleSet("s", `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`)}
	useRuleSet(&in.Policies[0], "r")
	useRuleSet(&in.Policies[0], "s")
	useRuleSet(&in.Policies[1], "s")
	prev := Resolve(in)
	in.Previous = &bundlev1.Bundle{Policies: prev.Policies, RuleSets: prev.RuleSets}
	// bad's spec now fails (a rule set it binds is missing), so its
	// previous version would stay; s now has r's rule ID.
	useRuleSet(&in.Policies[0], "missing")
	in.RuleSets[1] = seclangRuleSet("s", `SecRule ARGS "@contains y" "id:100001,phase:1,pass,nolog"`)
	wantLeftOut(t, in, ReasonInvalidRef, "so the policy is left out")
}
