// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// httpRoute returns an HTTPRoute in namespace shop.
func httpRoute(name string, hostnames []gatewayv1.Hostname, rules ...gatewayv1.HTTPRouteRule) gatewayv1.HTTPRoute {
	return gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec:       gatewayv1.HTTPRouteSpec{Hostnames: hostnames, Rules: rules},
	}
}

// hrule returns a rule named name (none when empty) with the given matches.
func hrule(name string, matches ...gatewayv1.HTTPRouteMatch) gatewayv1.HTTPRouteRule {
	r := gatewayv1.HTTPRouteRule{Matches: matches}
	if name != "" {
		r.Name = ptr(gatewayv1.SectionName(name))
	}
	return r
}

func hpath(t gatewayv1.PathMatchType, value string) gatewayv1.HTTPRouteMatch {
	return gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{Type: &t, Value: &value}}
}

func withMethod(m gatewayv1.HTTPRouteMatch, method gatewayv1.HTTPMethod) gatewayv1.HTTPRouteMatch {
	m.Method = &method
	return m
}

func targetingHTTPRoute(p *wafv1alpha1.WAFPolicy, name, section string) {
	p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: name, SectionName: section})
}

func wantRoutes(t *testing.T, got, want []*bundlev1.RouteMatch) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("routes %v, want %v", got, want)
	}
	for i := range want {
		wantProto(t, got[i], want[i])
	}
}

// anyDepth marks a wildcard route as matching subdomains at any depth.
func anyDepth(m *bundlev1.RouteMatch) *bundlev1.RouteMatch {
	m.WildcardAnyDepth = true
	return m
}

func withMethods(m *bundlev1.RouteMatch, methods ...string) *bundlev1.RouteMatch {
	m.Methods = methods
	return m
}

func TestHTTPRouteTarget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route gatewayv1.HTTPRoute
		want  []*bundlev1.RouteMatch
	}{{
		name: "hostnames × matches",
		route: httpRoute("api", []gatewayv1.Hostname{"API.example.com", "*.api.example.com"},
			hrule("", hpath(gatewayv1.PathMatchPathPrefix, "/v1/"), hpath(gatewayv1.PathMatchExact, "/login"))),
		want: []*bundlev1.RouteMatch{
			prefix("api.example.com", "/v1"), anyDepth(prefix("*.api.example.com", "/v1")),
			exact("api.example.com", "/login"), anyDepth(exact("*.api.example.com", "/login")),
		},
	}, {
		name:  "no hostnames: any host",
		route: httpRoute("api", nil, hrule("", hpath(gatewayv1.PathMatchExact, "/a/../login"))),
		want:  []*bundlev1.RouteMatch{exact("", "/login")},
	}, {
		name:  "a rule without matches is PathPrefix /",
		route: httpRoute("api", []gatewayv1.Hostname{"api.example.com"}, hrule("")),
		want:  []*bundlev1.RouteMatch{prefix("api.example.com", "/")},
	}, {
		name:  "a match without a path is PathPrefix /",
		route: httpRoute("api", nil, hrule("", withMethod(gatewayv1.HTTPRouteMatch{}, gatewayv1.HTTPMethodPost))),
		want:  []*bundlev1.RouteMatch{withMethods(prefix("", "/"), "POST")},
	}, {
		name: "methods kept, duplicates once",
		route: httpRoute("api", []gatewayv1.Hostname{"api.example.com"},
			hrule("a", withMethod(hpath(gatewayv1.PathMatchPathPrefix, "/orders"), gatewayv1.HTTPMethodPost), hpath(gatewayv1.PathMatchPathPrefix, "/orders")),
			hrule("b", hpath(gatewayv1.PathMatchPathPrefix, "/orders/"))),
		want: []*bundlev1.RouteMatch{withMethods(prefix("api.example.com", "/orders"), "POST"), prefix("api.example.com", "/orders")},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy("shop", 0)
			targetingHTTPRoute(&p, "api", "")
			res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, HTTPRoutes: []gatewayv1.HTTPRoute{tc.route}})
			wantStatus(t, res, "shop", true, ReasonAccepted, PolicyValid)
			wantRoutes(t, findPolicy(res, "shop/shop").GetRoutes(), tc.want)
		})
	}
}

func TestHTTPRouteSectionName(t *testing.T) {
	route := httpRoute("api", []gatewayv1.Hostname{"api.example.com"},
		hrule("public", hpath(gatewayv1.PathMatchPathPrefix, "/")),
		hrule("admin", hpath(gatewayv1.PathMatchPathPrefix, "/admin")),
		// A rule not targeted isn't read: its header match is no error.
		hrule("canary", gatewayv1.HTTPRouteMatch{Headers: []gatewayv1.HTTPHeaderMatch{{Name: "X-Canary", Value: "1"}}}))
	p := policy("shop", 0)
	targetingHTTPRoute(&p, "api", "admin")
	targetingHTTPRoute(&p, "api", "gone")
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, HTTPRoutes: []gatewayv1.HTTPRoute{route}})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "rule gone of HTTPRoute api not found; the policy applies to its other targets")
	wantRoutes(t, findPolicy(res, "shop/shop").GetRoutes(), []*bundlev1.RouteMatch{prefix("api.example.com", "/admin")})
}

func TestHTTPRouteUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match gatewayv1.HTTPRouteMatch
		err   string
	}{
		{"regular expression", hpath(gatewayv1.PathMatchRegularExpression, "/v[0-9]+"),
			"HTTPRoute api: spec.rules[1].matches[0] (rule b): RegularExpression paths are not supported"},
		{"headers", gatewayv1.HTTPRouteMatch{Headers: []gatewayv1.HTTPHeaderMatch{{Name: "X-A", Value: "b"}}},
			"HTTPRoute api: spec.rules[1].matches[0] (rule b): headers matches are not supported"},
		{"query parameters", gatewayv1.HTTPRouteMatch{QueryParams: []gatewayv1.HTTPQueryParamMatch{{Name: "a", Value: "b"}}},
			"HTTPRoute api: spec.rules[1].matches[0] (rule b): queryParams matches are not supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy("shop", 0)
			targetingHTTPRoute(&p, "api", "")
			good := httpRoute("api", nil, hrule("a", hpath(gatewayv1.PathMatchPathPrefix, "/")))
			prev := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, HTTPRoutes: []gatewayv1.HTTPRoute{good}})

			bad := httpRoute("api", nil, good.Spec.Rules[0], hrule("b", tc.match))
			res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, HTTPRoutes: []gatewayv1.HTTPRoute{bad}})
			wantStatus(t, res, "shop", false, ReasonTargetUnsupported, tc.err)
			if findPolicy(res, "shop/shop") != nil {
				t.Error("a policy never resolved must stay out of the bundle")
			}

			// A bad edit keeps the previous version in force.
			res = Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, HTTPRoutes: []gatewayv1.HTTPRoute{bad}, Previous: &bundlev1.Bundle{Policies: prev.Policies}})
			wantStatus(t, res, "shop", false, ReasonTargetUnsupported, "the previous version of the policy stays in force")
			wantRoutes(t, findPolicy(res, "shop/shop").GetRoutes(), []*bundlev1.RouteMatch{prefix("", "/")})
		})
	}
}

func TestHTTPRouteMissing(t *testing.T) {
	p := policy("shop", 0)
	targetingHTTPRoute(&p, "api", "")
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "HTTPRoute api not found")
}

// The most specific target wins a route, whatever the policies' ages: an
// HTTPRoute rule, then an HTTPRoute, then an Ingress.
func TestHTTPRoutePrecedence(t *testing.T) {
	ing := ingress("web", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix), ipath("/admin", networkingv1.PathTypePrefix)))
	route := httpRoute("web", []gatewayv1.Hostname{"shop.example.com"},
		hrule("public", hpath(gatewayv1.PathMatchPathPrefix, "/")),
		hrule("admin", hpath(gatewayv1.PathMatchPathPrefix, "/admin")))
	onIngress := policy("on-ingress", 0, "web")
	onRoute := policy("on-route", 1)
	targetingHTTPRoute(&onRoute, "web", "")
	onRule := policy("on-rule", 2)
	targetingHTTPRoute(&onRule, "web", "admin")

	res := Resolve(Input{
		Policies:   []wafv1alpha1.WAFPolicy{onIngress, onRoute, onRule},
		Ingresses:  []networkingv1.Ingress{ing},
		HTTPRoutes: []gatewayv1.HTTPRoute{route},
	})
	wantStatus(t, res, "on-rule", true, ReasonAccepted, PolicyValid)
	wantRoutes(t, findPolicy(res, "shop/on-rule").GetRoutes(), []*bundlev1.RouteMatch{prefix("shop.example.com", "/admin")})
	wantStatus(t, res, "on-route", true, ReasonAccepted,
		"routes covered by another policy, which applies to them: shop.example.com/admin (policy on a more specific target shop/on-rule)")
	wantRoutes(t, findPolicy(res, "shop/on-route").GetRoutes(), []*bundlev1.RouteMatch{prefix("shop.example.com", "/")})
	wantStatus(t, res, "on-ingress", true, ReasonAccepted,
		"shop.example.com/ (policy on a more specific target shop/on-route), shop.example.com/admin (policy on a more specific target shop/on-rule)")
	wantRoutes(t, findPolicy(res, "shop/on-ingress").GetRoutes(), nil)
}

// An HTTPRoute wildcard covers subdomains at any depth, an Ingress wildcard
// one label: the same hostname on both is two routes, each its policy's.
func TestHTTPRouteWildcard(t *testing.T) {
	ing := ingress("web", rule("*.example.com", ipath("/", networkingv1.PathTypePrefix)))
	route := httpRoute("web", []gatewayv1.Hostname{"*.example.com"}, hrule(""))
	onIngress := policy("on-ingress", 0, "web")
	onRoute := policy("on-route", 1)
	targetingHTTPRoute(&onRoute, "web", "")
	res := Resolve(Input{
		Policies:   []wafv1alpha1.WAFPolicy{onIngress, onRoute},
		Ingresses:  []networkingv1.Ingress{ing},
		HTTPRoutes: []gatewayv1.HTTPRoute{route},
	})
	wantStatus(t, res, "on-ingress", true, ReasonAccepted, PolicyValid)
	wantRoutes(t, findPolicy(res, "shop/on-ingress").GetRoutes(), []*bundlev1.RouteMatch{prefix("*.example.com", "/")})
	wantStatus(t, res, "on-route", true, ReasonAccepted, PolicyValid)
	wantRoutes(t, findPolicy(res, "shop/on-route").GetRoutes(), []*bundlev1.RouteMatch{anyDepth(prefix("*.example.com", "/"))})
}

// Two policies on the same HTTPRoute rule: the older applies, the newer is
// a Conflict. A policy on the whole route doesn't conflict with one on a
// rule.
func TestHTTPRouteConflict(t *testing.T) {
	route := httpRoute("web", nil, hrule("admin", hpath(gatewayv1.PathMatchPathPrefix, "/admin")))
	older, newer, whole := policy("older", 0), policy("newer", 1), policy("whole", 2)
	targetingHTTPRoute(&older, "web", "admin")
	targetingHTTPRoute(&newer, "web", "admin")
	targetingHTTPRoute(&whole, "web", "")
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{newer, whole, older}, HTTPRoutes: []gatewayv1.HTTPRoute{route}})
	wantStatus(t, res, "older", true, ReasonAccepted, PolicyValid)
	wantStatus(t, res, "newer", false, ReasonConflict, "rule admin of HTTPRoute web is also targeted by the older WAFPolicy older")
	wantStatus(t, res, "whole", true, ReasonAccepted, "(policy on a more specific target shop/older)")
	if findPolicy(res, "shop/newer") != nil {
		t.Error("the newer conflicting policy must stay out")
	}
}
