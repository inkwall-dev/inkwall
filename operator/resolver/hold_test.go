// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	enginepolicy "github.com/inkwall-dev/inkwall/pkg/policy"
)

// A policy held back (the bundle with it is too large) keeps its previous
// version, a new one is left out, and the others apply as they are now.
func TestHold(t *testing.T) {
	a, b := policy("a", 0, "a"), policy("b", 1, "b")
	useRuleSet(&a, "a-rules")
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{a, b},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("c", rule("c.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		RuleSets: []wafv1alpha1.WAFRuleSet{seclangRuleSet("a-rules", "SecMarker SMALL")},
	}
	first := Resolve(in)
	in.Previous = &bundlev1.Bundle{Version: 3, Policies: first.Policies, RuleSets: first.RuleSets}

	in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("a-rules", "SecMarker LARGE")}
	in.Policies[1].Spec.Mode = wafv1alpha1.PolicyBlock
	in.Policies = append(in.Policies, policy("c", 2, "c"))
	in.Hold = map[types.NamespacedName]string{key("a"): "too large", key("c"): "too large"}
	res := Resolve(in)

	wantStatus(t, res, "a", false, ReasonBundleTooLarge, "too large; the previous version of the policy stays in force")
	wantStatus(t, res, "c", false, ReasonBundleTooLarge, "too large; it has no previous version, so it is left out")
	wantStatus(t, res, "b", true, ReasonAccepted, "")
	for _, name := range []string{"a", "c"} {
		if res.PolicyStatus[key(name)].Applied {
			t.Errorf("%s held back, but Applied", name)
		}
	}
	wantProto(t, findPolicy(res, "shop/a"), first.Policies[0])
	if findPolicy(res, "shop/c") != nil {
		t.Error("a new policy held back is in the bundle")
	}
	if findPolicy(res, "shop/b").GetMode() != bundlev1.Mode_MODE_BLOCK {
		t.Error("the change of a policy not held back isn't in the bundle")
	}
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker SMALL" {
		t.Fatalf("the rule set only a held policy binds must stay as it was: %v", res.RuleSets)
	}
}

// A held policy whose previous version binds a rule set that changed, and
// that another policy uses as it is now, keeps its previous version with
// the rule set as it is now, if it compiles with it: holding it back must
// not take its routes' protection away. A policy that fails is still left
// out, as before.
func TestHoldSharedRuleSet(t *testing.T) {
	shared := func(rules string) wafv1alpha1.ClusterWAFRuleSet {
		rs := wafv1alpha1.ClusterWAFRuleSet{}
		rs.Name = "shared"
		rs.Spec.Source.SecLang = rules
		return rs
	}
	bind := func(p *wafv1alpha1.WAFPolicy) {
		p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "shared"}})
	}
	a, b := policy("a", 0, "a"), policy("b", 1, "b")
	bind(&a)
	bind(&b)
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{a, b},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{shared("SecMarker OLD")},
	}
	first := Resolve(in)
	in.Previous = &bundlev1.Bundle{Version: 3, Policies: first.Policies, RuleSets: first.RuleSets}
	in.ClusterRuleSets = []wafv1alpha1.ClusterWAFRuleSet{shared("SecMarker NEW")}
	in.Policies[0].Spec.Mode = wafv1alpha1.PolicyBlock

	in.Hold = map[types.NamespacedName]string{key("a"): "too large"}
	res := Resolve(in)
	wantStatus(t, res, "a", false, ReasonBundleTooLarge, "the previous version of the policy stays in force")
	if p := findPolicy(res, "shop/a"); p == nil || p.GetMode() != bundlev1.Mode_MODE_DETECT {
		t.Fatalf("the held policy must keep its previous version: %v", p)
	}
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker NEW" {
		t.Fatalf("the shared rule set ships as it is now: %v", res.RuleSets)
	}

	// Failing for another reason, the previous version is left out.
	in.Hold = nil
	in.Policies[0].Spec.RuleSets = append(in.Policies[0].Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "gone"}})
	res = Resolve(in)
	if st := res.PolicyStatus[key("a")]; !strings.Contains(st.Message, "so the policy is left out") || findPolicy(res, "shop/a") != nil {
		t.Fatalf("a failed policy's previous version with a changed shared rule set: %+v", st)
	}
}

// A held policy whose previous version doesn't compile with a cluster rule
// set as it is now, which another policy binds, never holds the cluster
// rule set (one namespace mustn't pin a CRS upgrade): it is left out, and
// says why. A rule set of its own namespace is held with it instead: it
// ships as it was, and the namespace's other policy is checked with it.
func TestHoldKeepsPreviousVersion(t *testing.T) {
	old := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
	clash := `SecRule ARGS "@contains z" "id:100001,phase:1,pass,nolog"`
	own := seclangRuleSet("a-own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`)
	for _, scope := range []string{"ClusterWAFRuleSet", "WAFRuleSet"} {
		t.Run(scope, func(t *testing.T) {
			a, b := policy("a", 0, "a"), policy("b", 1, "b")
			bind := func(p *wafv1alpha1.WAFPolicy) {
				p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: scope, Name: "shared"}})
			}
			bind(&a)
			useRuleSet(&a, "a-own")
			bind(&b)
			shared := func(in *Input, rules string) {
				in.RuleSets = []wafv1alpha1.WAFRuleSet{own}
				in.ClusterRuleSets = nil
				if scope == "WAFRuleSet" {
					in.RuleSets = append(in.RuleSets, seclangRuleSet("shared", rules))
					return
				}
				rs := wafv1alpha1.ClusterWAFRuleSet{}
				rs.Name = "shared"
				rs.Spec.Source.SecLang = rules
				in.ClusterRuleSets = []wafv1alpha1.ClusterWAFRuleSet{rs}
			}
			in := Input{
				Policies: []wafv1alpha1.WAFPolicy{a, b},
				Ingresses: []networkingv1.Ingress{
					ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
					ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
				},
				CheckPolicy: enginepolicy.NewRuleChecker().Check,
			}
			shared(&in, old)
			first := Resolve(in)
			in.Previous = &bundlev1.Bundle{Version: 3, Policies: first.Policies, RuleSets: first.RuleSets}

			// The shared rule set now has a-own's rule id: a's previous
			// version doesn't compile with it. a drops a-own and changes,
			// and is held; b changes.
			shared(&in, clash)
			in.Policies[0].Spec.RuleSets = in.Policies[0].Spec.RuleSets[:1]
			in.Policies[0].Spec.Mode = wafv1alpha1.PolicyBlock
			in.Policies[1].Spec.Mode = wafv1alpha1.PolicyBlock
			in.Hold = map[types.NamespacedName]string{key("a"): "too large"}
			res := Resolve(in)

			id := scope + "/shared"
			if scope == "WAFRuleSet" {
				id = "WAFRuleSet/shop/shared"
			}
			shipped := ""
			for _, rs := range res.RuleSets {
				if rs.GetId() == id {
					shipped = rs.GetSeclang()
				}
			}
			st := res.RuleSetStatus[id]
			if scope == "ClusterWAFRuleSet" {
				wantStatus(t, res, "a", false, ReasonBundleTooLarge,
					"too large; and its previous version doesn't compile with ClusterWAFRuleSet shared as it is now")
				if p := findPolicy(res, "shop/a"); p != nil {
					t.Fatalf("the held policy, incompatible with the cluster rule set as it is now, is in the bundle: %v", p)
				}
				if !st.Accepted || shipped != clash {
					t.Errorf("the cluster rule set is held for one namespace's policy: %+v, ships %q", st, shipped)
				}
				wantStatus(t, res, "b", true, ReasonAccepted, "")
			} else {
				wantStatus(t, res, "a", false, ReasonBundleTooLarge, "too large; the previous version of the policy stays in force")
				if p := findPolicy(res, "shop/a"); p == nil || p.GetMode() != bundlev1.Mode_MODE_DETECT {
					t.Fatalf("the held policy must keep its previous version: %v", p)
				}
				if st.Accepted || st.Reason != ReasonBundleTooLarge || !strings.Contains(st.Message, "WAFPolicy shop/a is held back") {
					t.Errorf("the namespace's rule set's status: %+v, want BundleTooLarge naming shop/a", st)
				}
				if shipped != old {
					t.Errorf("the namespace's rule set, held, ships as it is now: %q", shipped)
				}
				wantStatus(t, res, "b", true, ReasonAccepted, "WAFRuleSet shared is held back at its previous version")
			}
			if p := findPolicy(res, "shop/b"); p.GetMode() != bundlev1.Mode_MODE_BLOCK {
				t.Errorf("b's change, not held, isn't published: %v", p)
			}
			if _, err := enginepolicy.Compile(&bundlev1.Bundle{Version: 4, Policies: res.Policies, RuleSets: res.RuleSets}, enginepolicy.Options{}); err != nil {
				t.Fatalf("the bundle doesn't compile: %v", err)
			}

			// Not held, a's change compiles with the rule set as it is now.
			in.Hold = nil
			res = Resolve(in)
			wantStatus(t, res, "a", true, ReasonAccepted, "")
			if st := res.RuleSetStatus[id]; !st.Accepted {
				t.Errorf("the shared rule set, not held: %+v", st)
			}
		})
	}
}
