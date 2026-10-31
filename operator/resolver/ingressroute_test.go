// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func TestParseMatch(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want *bundlev1.RouteMatch
	}{
		{"Host(`shop.example.com`)", prefix("shop.example.com", "/")},
		{"Host(`Shop.Example.com`) && PathPrefix(`/api/`)", prefix("shop.example.com", "/api")},
		{"PathPrefix(`/static`) && Host(`shop.example.com`)", prefix("shop.example.com", "/static")},
		{"Host(`shop.example.com`) && Path(`/login`)", exact("shop.example.com", "/login")},
		{"Path(`/healthz`)", exact("", "/healthz")},
		{"PathPrefix(`/`)", prefix("", "/")},
		{"PathPrefix(`/a/../b`)", prefix("", "/b")},
		{`Host("shop.example.com") && PathPrefix("/qé")`, prefix("shop.example.com", "/qé")},
		{"(Host(`a.example.com`) && (PathPrefix(`/x`)))", prefix("a.example.com", "/x")},
		{" Host( `a.example.com` )&&Path(`/x`) ", exact("a.example.com", "/x")},
		{"Host(`a.example.com`) && Host(`A.example.com`)", prefix("a.example.com", "/")},
	} {
		got, err := parseMatch(tc.rule)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		wantProto(t, got, tc.want)
	}
}

func TestParseMatchErrors(t *testing.T) {
	for _, tc := range []struct{ rule, err string }{
		{"", "empty"},
		{"Host(`a.example.com`) || Host(`b.example.com`)", "|| is not supported"},
		{"(Host(`a.example.com`) || Host(`b.example.com`)) && Path(`/`)", "|| is not supported"},
		{"Host(`a.example.com`) && !Path(`/admin`)", "! is not supported"},
		{"HostRegexp(`^.+\\.example\\.com$`)", "HostRegexp is not supported"},
		{"Host(`a.example.com`) && Method(`GET`)", "Method is not supported"},
		{"Host(`a.example.com`) && Header(`X-A`, `b`)", "Header is not supported"},
		{"PathRegexp(`^/api`)", "PathRegexp is not supported"},
		{"ClientIP(`10.0.0.0/8`)", "ClientIP is not supported"},
		{"host(`a.example.com`)", "host is not supported"},
		{"Host(`a.example.com`, `b.example.com`)", "Host takes one value, not 2"},
		{"Host(`a.example.com`) && Host(`b.example.com`)", "more than one Host"},
		{"Path(`/a`) && PathPrefix(`/b`)", "more than one path matcher (Path and PathPrefix)"},
		{"Host(``)", "not a host name"},
		{"Host(`*.example.com`)", "not a host name"},
		{"PathPrefix(`api`)", "not an absolute path"},
		{"Host(a.example.com)", "must be a string"},
		{"Host(`a.example.com`", "missing )"},
		{"Host(`a.example.com", "unterminated `"},
		{`Host("a.example.com)`, `unterminated "`},
		{`Host("\q")`, "bad string"},
		{"Host", "missing ( after Host"},
		{"Host(`a.example.com`) Path(`/`)", `unexpected "Path"`},
		{"Host(`a.example.com`) &&", "ends early"},
		{"(Host(`a.example.com`)", "missing ) before"},
		{"Host(`a.example.com`))", `unexpected ")"`},
		{"&& Host(`a.example.com`)", `unexpected "&&"`},
	} {
		_, err := parseMatch(tc.rule)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: error %v, want one containing %q", tc.rule, err, tc.err)
		}
	}
}

// ingressRoute returns a Traefik IngressRoute in namespace shop with a
// route per match rule.
func ingressRoute(name string, matches ...string) unstructured.Unstructured {
	var routes []any
	for _, m := range matches {
		routes = append(routes, map[string]any{"kind": "Rule", "match": m,
			"services": []any{map[string]any{"name": name, "port": int64(80)}}})
	}
	u := unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"routes": routes}}}
	u.SetAPIVersion("traefik.io/v1alpha1")
	u.SetKind("IngressRoute")
	u.SetNamespace("shop")
	u.SetName(name)
	return u
}

func targetingRoute(p *wafv1alpha1.WAFPolicy, name string) {
	p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Group: "traefik.io", Kind: "IngressRoute", Name: name})
}

func TestIngressRouteTarget(t *testing.T) {
	p := policy("shop", 0, "web")
	targetingRoute(&p, "api")
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("web", rule("web.example.com", ipath("/", networkingv1.PathTypePrefix)))},
		IngressRoutes: []unstructured.Unstructured{ingressRoute("api",
			"Host(`api.example.com`) && PathPrefix(`/v1`)",
			"Host(`api.example.com`) && Path(`/login`)",
			// Another route with the same match (another priority, say).
			"Host(`api.example.com`) && Path(`/login`)",
		)},
	})
	wantStatus(t, res, "shop", true, ReasonAccepted, "")
	got := findPolicy(res, "shop/shop").GetRoutes()
	want := []*bundlev1.RouteMatch{prefix("web.example.com", "/"), prefix("api.example.com", "/v1"), exact("api.example.com", "/login")}
	if len(got) != len(want) {
		t.Fatalf("routes %v, want %v", got, want)
	}
	for i := range want {
		wantProto(t, got[i], want[i])
	}
}

func TestIngressRouteTargetErrors(t *testing.T) {
	p := policy("shop", 0)
	targetingRoute(&p, "api")
	targetingRoute(&p, "gone")
	res := Resolve(Input{
		Policies:      []wafv1alpha1.WAFPolicy{p},
		IngressRoutes: []unstructured.Unstructured{ingressRoute("api", "Host(`api.example.com`)", "Host(`a.example.com`) || Host(`b.example.com`)")},
	})
	// The route and the rule it can't read are named.
	wantStatus(t, res, "shop", false, ReasonTargetUnsupported,
		"IngressRoute api: spec.routes[1] match \"Host(`a.example.com`) || Host(`b.example.com`)\": || is not supported")
	wantStatus(t, res, "shop", false, ReasonTargetUnsupported, "IngressRoute gone not found")
	if findPolicy(res, "shop/shop") != nil {
		t.Error("a policy never resolved must stay out of the bundle")
	}

	// A bad edit keeps the previous version in force.
	prev := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, IngressRoutes: []unstructured.Unstructured{ingressRoute("api", "Host(`api.example.com`)")}})
	res = Resolve(Input{
		Policies:      []wafv1alpha1.WAFPolicy{p},
		IngressRoutes: []unstructured.Unstructured{ingressRoute("api", "Host(`api.example.com`) && Method(`POST`)")},
		Previous:      &bundlev1.Bundle{Policies: prev.Policies},
	})
	wantStatus(t, res, "shop", false, ReasonTargetUnsupported, "the previous version of the policy stays in force")
	wantProto(t, findPolicy(res, "shop/shop").GetRoutes()[0], prefix("api.example.com", "/"))

	// No routes, or a route that isn't an object.
	bad := ingressRoute("api")
	bad.Object["spec"] = map[string]any{"routes": "nope"}
	if _, err := ingressRouteMatches(&bad); err == nil {
		t.Error("spec.routes that isn't a list was read")
	}
	bad.Object["spec"] = map[string]any{"routes": []any{"nope"}}
	if _, err := ingressRouteMatches(&bad); err == nil || !strings.Contains(err.Error(), "spec.routes[0]") {
		t.Errorf("a route that isn't an object: %v", err)
	}
}

// An Ingress and an IngressRoute with the same host and path: two policies
// can't both have it, the older wins.
func TestIngressRouteSharedRoute(t *testing.T) {
	older := policy("older", 0, "web")
	newer := policy("newer", 1)
	targetingRoute(&newer, "web")
	res := Resolve(Input{
		Policies:      []wafv1alpha1.WAFPolicy{newer, older},
		Ingresses:     []networkingv1.Ingress{ingress("web", rule("web.example.com", ipath("/", networkingv1.PathTypePrefix)))},
		IngressRoutes: []unstructured.Unstructured{ingressRoute("web", "Host(`web.example.com`)")},
	})
	wantStatus(t, res, "newer", true, ReasonAccepted, "routes covered by another policy, which applies to them: web.example.com/ (older policy shop/older)")
}
