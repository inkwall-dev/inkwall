// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	enginepolicy "github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// engineVerdict compiles a resolution as the engine does and checks an
// SQL injection to shop.example.com/login.
func engineVerdict(t *testing.T, res Result) pipeline.Verdict {
	t.Helper()
	set, err := enginepolicy.Compile(&bundlev1.Bundle{Version: 1, Policies: res.Policies, RuleSets: res.RuleSets}, enginepolicy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := &request.Request{Proto: "HTTP/1.1", Method: "GET", Scheme: "https", Host: "shop.example.com",
		RawURI: "/login?id=1%27%20OR%20%271%27%3D%271", Headers: http.Header{"User-Agent": {"Mozilla/5.0"}, "Accept": {"text/html"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return set.Check(ctx, r)
}

// A route of another namespace's policy that no proxy routes, or that
// another proxy routes, doesn't change the policy the engine applies to
// a protected host: the protected policy (Block, the older) still blocks.
// A route of the same Gateway does, as the proxy routes it.
func TestOtherNamespaceRoutesKeepTheHostsPolicy(t *testing.T) {
	type side struct {
		hr  gatewayv1.HTTPRoute
		ing *networkingv1.Ingress
		p   wafv1alpha1.WAFPolicy
	}
	nsRoute := func(ns string, hosts []gatewayv1.Hostname, rule gatewayv1.HTTPRouteRule) gatewayv1.HTTPRoute {
		hr := httpRoute("web", hosts, rule)
		hr.Namespace, hr.Spec.ParentRefs, hr.Status.Parents = ns, nil, nil
		return hr
	}
	nsPolicy := func(ns string, age int, mode wafv1alpha1.PolicyMode, section string) wafv1alpha1.WAFPolicy {
		p := policy("waf", age)
		p.Namespace, p.Spec.Mode = ns, mode
		targetingHTTPRoute(&p, "web", section)
		return p
	}
	shop := []gatewayv1.Hostname{"shop.example.com"}
	protected := func(kind string) side {
		if kind == "Ingress" {
			ing := ingress("web", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))
			ing.Namespace = "team-a"
			p := policy("waf", 0, "web")
			p.Namespace, p.Spec.Mode = "team-a", wafv1alpha1.PolicyBlock
			return side{ing: &ing, p: p}
		}
		hosts := shop
		if kind == "HTTPRouteAnyHost" {
			hosts = nil
		}
		hr := nsRoute("team-a", hosts, hrule(""))
		attach(&hr, "gateways", "shared", true)
		return side{hr: hr, p: nsPolicy("team-a", 0, wafv1alpha1.PolicyBlock, "")}
	}
	for _, tc := range []struct {
		name, protected string
		other           func() side
		// wantOther: the other policy applies to the request (it is
		// routed by the same Gateway, or stricter).
		wantOther bool
		// wantReason is the other policy's Accepted reason.
		wantReason string
	}{
		{
			name: "same route, more specific target, not attached", protected: "HTTPRoute",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule("x", hpath(gatewayv1.PathMatchPathPrefix, "/")))
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "x")}
			},
			wantReason: ReasonTargetNotAttached,
		},
		{
			name: "rejected by the Gateway", protected: "HTTPRoute",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule("", hpath(gatewayv1.PathMatchPathPrefix, "/login")))
				attach(&hr, "gateways", "shared", false)
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "")}
			},
			wantReason: ReasonTargetNotAttached,
		},
		{
			name: "same route, more specific target, same Gateway", protected: "HTTPRoute",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule("x", hpath(gatewayv1.PathMatchPathPrefix, "/")))
				attach(&hr, "gateways", "shared", true)
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "x")}
			},
			wantReason: ReasonRouteOverlap,
		},
		{
			name: "protected by an Ingress, HTTPRoute of another proxy", protected: "Ingress",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule(""))
				attach(&hr, "team-b", "own", true)
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "")}
			},
			wantReason: ReasonRouteOverlap,
		},
		{
			name: "longer path on another Gateway", protected: "HTTPRoute",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule("", hpath(gatewayv1.PathMatchPathPrefix, "/login")))
				attach(&hr, "team-b", "own", true)
				p := nsPolicy("team-b", 9, wafv1alpha1.PolicyBlock, "")
				p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/*"}}
				return side{hr: hr, p: p}
			},
			wantReason: ReasonRouteOverlap,
		},
		{
			name: "exact host on another Gateway, protected route without hostnames", protected: "HTTPRouteAnyHost",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule(""))
				attach(&hr, "team-b", "own", true)
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "")}
			},
			wantReason: ReasonRouteOverlap,
		},
		{
			name: "longer path on the same Gateway", protected: "HTTPRoute",
			other: func() side {
				hr := nsRoute("team-b", shop, hrule("", hpath(gatewayv1.PathMatchPathPrefix, "/login")))
				attach(&hr, "gateways", "shared", true)
				return side{hr: hr, p: nsPolicy("team-b", 9, wafv1alpha1.PolicyDetect, "")}
			},
			wantOther: true, wantReason: ReasonAccepted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := protected(tc.protected), tc.other()
			in := Input{Policies: []wafv1alpha1.WAFPolicy{a.p, b.p}, HTTPRoutes: []gatewayv1.HTTPRoute{b.hr}}
			if a.ing != nil {
				in.Ingresses = []networkingv1.Ingress{*a.ing}
			} else {
				in.HTTPRoutes = append(in.HTTPRoutes, a.hr)
			}
			res := Resolve(in)
			v := engineVerdict(t, res)
			if tc.wantOther {
				if v.Policy != "team-b/waf" {
					t.Fatalf("verdict %v of %s, want team-b/waf's", v.Action, v.Policy)
				}
			} else if v.Policy != "team-a/waf" || v.Action != pipeline.ActionDeny {
				t.Fatalf("verdict %v of %s, want team-a/waf's deny", v.Action, v.Policy)
			}
			bst := res.PolicyStatus[types.NamespacedName{Namespace: "team-b", Name: "waf"}]
			if bst.Reason != tc.wantReason || bst.Accepted != (tc.wantReason == ReasonAccepted) {
				t.Errorf("team-b/waf status %+v, want reason %s", bst, tc.wantReason)
			}
			ast := res.PolicyStatus[types.NamespacedName{Namespace: "team-a", Name: "waf"}]
			if !ast.Accepted {
				t.Errorf("team-a/waf status %+v, want Accepted", ast)
			}
			if tc.wantReason == ReasonRouteOverlap && (ast.Reason != ReasonRouteOverlap || !strings.Contains(ast.Message, "team-b/waf")) {
				t.Errorf("team-a/waf status %+v, want the overlap with team-b/waf", ast)
			}
		})
	}
}

// Where the engine can't tell two namespaces' routes apart, a stricter
// newer policy applies, never a weaker one.
func TestOverlapGoesToTheStricterPolicy(t *testing.T) {
	ing := ingress("web", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))
	ing.Namespace = "team-a"
	older := policy("waf", 0, "web")
	older.Namespace, older.Spec.Mode = "team-a", wafv1alpha1.PolicyDetect
	older.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/login"}}
	hr := httpRoute("web", []gatewayv1.Hostname{"shop.example.com"}, hrule(""))
	hr.Namespace = "team-b"
	newer := policy("waf", 9)
	newer.Namespace, newer.Spec.Mode = "team-b", wafv1alpha1.PolicyBlock
	targetingHTTPRoute(&newer, "web", "")
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{older, newer}, Ingresses: []networkingv1.Ingress{ing}, HTTPRoutes: []gatewayv1.HTTPRoute{hr}})
	if v := engineVerdict(t, res); v.Policy != "team-b/waf" || v.Action != pipeline.ActionDeny {
		t.Fatalf("verdict %v of %s, want team-b/waf's deny", v.Action, v.Policy)
	}
	if st := res.PolicyStatus[types.NamespacedName{Namespace: "team-a", Name: "waf"}]; st.Accepted || st.Reason != ReasonRouteOverlap {
		t.Errorf("team-a/waf status %+v, want not Accepted, RouteOverlap", st)
	}

	// The same route of both namespaces: the same.
	ing.Spec = networkingv1.IngressSpec{}
	hr2 := httpRoute("web", []gatewayv1.Hostname{"shop.example.com"}, hrule(""))
	hr2.Namespace = "team-a"
	older.Spec.TargetRefs = nil
	targetingHTTPRoute(&older, "web", "")
	res = Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{older, newer}, HTTPRoutes: []gatewayv1.HTTPRoute{hr, hr2}})
	if v := engineVerdict(t, res); v.Policy != "team-b/waf" || v.Action != pipeline.ActionDeny {
		t.Fatalf("same route: verdict %v of %s, want team-b/waf's deny", v.Action, v.Policy)
	}
}

// Rule sets valid alone but not together (the same rule ID) make their
// policy not Accepted and leave it out of the bundle, which compiles: the
// other policies keep working.
func TestIncompatibleRuleSetsLeaveOnlyTheirPolicyOut(t *testing.T) {
	a := `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`
	b := `SecRule ARGS "@contains y" "id:100001,phase:1,pass,nolog"`
	p := policy("both", 0, "web")
	useRuleSet(&p, "a")
	useRuleSet(&p, "b")
	one := policy("one", 1, "other")
	useRuleSet(&one, "a")
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{p, one},
		Ingresses: []networkingv1.Ingress{
			ingress("web", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("other", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		RuleSets:    []wafv1alpha1.WAFRuleSet{seclangRuleSet("a", a), seclangRuleSet("b", b)},
		CheckPolicy: enginepolicy.NewRuleChecker().Check,
	}
	res := Resolve(in)
	wantStatus(t, res, "both", false, ReasonRuleSetsIncompatible, "its rule sets don't compile together")
	wantStatus(t, res, "one", true, ReasonAccepted, PolicyValid)
	if findPolicy(res, "shop/both") != nil {
		t.Error("the policy whose rule sets don't compile together must stay out")
	}
	bundle := &bundlev1.Bundle{Version: 2, Policies: res.Policies, RuleSets: res.RuleSets}
	if _, err := enginepolicy.Compile(bundle, enginepolicy.Options{}); err != nil {
		t.Fatalf("the bundle doesn't compile: %v", err)
	}

	// Its previous version stays when it compiles; not when it doesn't.
	good := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, Ingresses: in.Ingresses,
		RuleSets: []wafv1alpha1.WAFRuleSet{seclangRuleSet("a", a), seclangRuleSet("b", `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`)}})
	in.Previous = &bundlev1.Bundle{Policies: good.Policies, RuleSets: good.RuleSets}
	in.RuleSets[1] = seclangRuleSet("b", b)
	res = Resolve(in)
	wantStatus(t, res, "both", false, ReasonRuleSetsIncompatible, "the previous version of the policy stays in force")
	unchecked := in
	unchecked.CheckPolicy, unchecked.Previous = nil, nil
	bad := Resolve(unchecked)
	in.Previous = &bundlev1.Bundle{Policies: bad.Policies, RuleSets: bad.RuleSets}
	res = Resolve(in)
	wantStatus(t, res, "both", false, ReasonRuleSetsIncompatible, "its previous version doesn't compile either")
	if findPolicy(res, "shop/both") != nil {
		t.Error("a previous version that doesn't compile must stay out")
	}
}

// A policy whose rate limits the engine can't compile (saved before the
// webhook checked them) is left out, or keeps its previous version: the
// other policies' bundle still compiles, with their changes.
func TestInvalidRateLimitsLeaveOnlyTheirPolicyOut(t *testing.T) {
	limit := func(path wafv1alpha1.PathPattern) []wafv1alpha1.RateLimit {
		return []wafv1alpha1.RateLimit{{Name: "login", Requests: 5, Period: metav1.Duration{Duration: time.Hour},
			Match: &wafv1alpha1.RateLimitMatch{Paths: []wafv1alpha1.PathPattern{path}}}}
	}
	bad := policy("bad", 0, "web")
	bad.Spec.RateLimits = limit("/a/./login")
	other := policy("other", 1, "other")
	other.Spec.RateLimits = limit("/login")
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{bad, other},
		Ingresses: []networkingv1.Ingress{
			ingress("web", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("other", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		CheckPolicy: enginepolicy.NewRuleChecker().Check,
	}
	compiles := func(res Result) {
		t.Helper()
		b := &bundlev1.Bundle{Version: 2, Policies: res.Policies, RuleSets: res.RuleSets}
		if _, err := enginepolicy.Compile(b, enginepolicy.Options{RateLimits: ratelimit.New(100, 0)}); err != nil {
			t.Fatalf("the bundle doesn't compile: %v", err)
		}
	}
	res := Resolve(in)
	wantStatus(t, res, "bad", false, ReasonInvalidRateLimits, `path pattern "/a/./login" is not clean`)
	wantStatus(t, res, "other", true, ReasonAccepted, PolicyValid)
	if findPolicy(res, "shop/bad") != nil {
		t.Error("the policy whose rate limits don't compile must stay out")
	}
	if findPolicy(res, "shop/other") == nil {
		t.Fatal("the other policy must stay in")
	}
	compiles(res)

	// Its previous version stays when it compiles.
	good := bad.DeepCopy()
	good.Spec.RateLimits = limit("/login")
	prev := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{*good}, Ingresses: in.Ingresses})
	in.Previous = &bundlev1.Bundle{Policies: prev.Policies}
	res = Resolve(in)
	wantStatus(t, res, "bad", false, ReasonInvalidRateLimits, "the previous version of the policy stays in force")
	if p := findPolicy(res, "shop/bad"); p == nil || p.GetRateLimits()[0].GetPaths()[0] != "/login" {
		t.Errorf("the previous version must stay in force: %v", p)
	}
	compiles(res)

	// A previous bundle built by hand with a bad limit: not kept either.
	handBuilt := proto.Clone(prev.Policies[0]).(*bundlev1.Policy)
	handBuilt.RateLimits[0].Paths = []string{"/x/../login"}
	in.Previous = &bundlev1.Bundle{Policies: []*bundlev1.Policy{handBuilt}}
	res = Resolve(in)
	wantStatus(t, res, "bad", false, ReasonInvalidRateLimits, "its previous version's rate limits don't compile either")
	if findPolicy(res, "shop/bad") != nil {
		t.Error("a previous version that doesn't compile must stay out")
	}
	compiles(res)
}

// A policy whose spec.llm the engine can't compile (two endpoint paths it
// reads as one, which the CRD finds distinct) stays out of the bundle,
// LLMInvalid: in it, every engine would refuse the bundle (#277).
func TestLLMInvalidLeftOut(t *testing.T) {
	p := policy("chat", 0, "web")
	p.Spec.LLM = &wafv1alpha1.LLMSpec{Endpoints: []wafv1alpha1.LLMEndpoint{
		{Paths: []wafv1alpha1.PathPattern{"/v1/chat"}, Format: wafv1alpha1.LLMOpenAIChat},
		{Paths: []wafv1alpha1.PathPattern{"/V1/Chat/"}, Format: wafv1alpha1.LLMAnthropicMessages},
	}}
	other := policy("other", 1, "other")
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{p, other},
		Ingresses: []networkingv1.Ingress{
			ingress("web", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("other", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
	}
	res := Resolve(in)
	wantStatus(t, res, "chat", false, ReasonLLMInvalid, "its LLM endpoints don't compile as the engine compiles them")
	wantStatus(t, res, "other", true, ReasonAccepted, PolicyValid)
	if findPolicy(res, "shop/chat") != nil {
		t.Error("the policy whose spec.llm doesn't compile must stay out")
	}
	if _, err := enginepolicy.Compile(&bundlev1.Bundle{Version: 2, Policies: res.Policies}, enginepolicy.Options{}); err != nil {
		t.Fatalf("the bundle doesn't compile: %v", err)
	}
	// Its previous version stays in force.
	valid := p
	valid.Spec.LLM = &wafv1alpha1.LLMSpec{Endpoints: p.Spec.LLM.Endpoints[:1]}
	good := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{valid}, Ingresses: in.Ingresses})
	in.Previous = &bundlev1.Bundle{Policies: good.Policies}
	res = Resolve(in)
	wantStatus(t, res, "chat", false, ReasonLLMInvalid, "the previous version of the policy stays in force")
	if prev := findPolicy(res, "shop/chat"); prev == nil || len(prev.GetLlm().GetEndpoints()) != 1 {
		t.Errorf("previous version: %v", prev)
	}
}
