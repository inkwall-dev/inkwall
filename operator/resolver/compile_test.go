// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/iplist"
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

// TestIPListsOverTheEngineTotal: WAFIPLists each within its limit, more
// entries together than the engine takes: the engine would refuse the
// whole bundle, so the policy is left out.
func TestIPListsOverTheEngineTotal(t *testing.T) {
	in := compileInput()
	p := &in.Policies[0]
	p.Spec.IPLists = &wafv1alpha1.IPListsSpec{}
	n := 0
	for i := range 16 {
		name := fmt.Sprintf("list-%d", i)
		var cidrs []string
		for range 10000 {
			cidrs = append(cidrs, fmt.Sprintf("10.%d.%d.%d", n>>16, n>>8&255, n&255))
			n++
		}
		in.IPLists = append(in.IPLists, ipList(name, cidrs...))
		p.Spec.IPLists.Allow = append(p.Spec.IPLists.Allow, wafv1alpha1.IPListName(name))
	}
	if n <= iplist.MaxEntries {
		t.Fatalf("%d entries, not over the engine's %d", n, iplist.MaxEntries)
	}
	wantLeftOut(t, in, ReasonInvalidSpec, fmt.Sprintf("IP allow list: %d entries, more than %d", n, iplist.MaxEntries))
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
