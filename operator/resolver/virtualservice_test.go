// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// virtualService parses a VirtualService's spec.
func virtualService(t *testing.T, spec string) *unstructured.Unstructured {
	t.Helper()
	var s map[string]any
	if err := yaml.Unmarshal([]byte(spec), &s); err != nil {
		t.Fatal(err)
	}
	vs := &unstructured.Unstructured{Object: map[string]any{"spec": s}}
	vs.SetAPIVersion("networking.istio.io/v1")
	vs.SetKind("VirtualService")
	vs.SetNamespace("shop")
	vs.SetName("web")
	return vs
}

func routeString(routes []*bundlev1.RouteMatch) string {
	var out []string
	for _, r := range routes {
		s := r.GetHost() + r.GetPath().GetValue()
		if r.GetPath().GetType() == bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX {
			s += "*"
		}
		if len(r.GetMethods()) > 0 {
			s += " " + strings.Join(r.GetMethods(), ",")
		}
		if r.GetWildcardAnyDepth() {
			s += " (any depth)"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

// A VirtualService's routes: its hosts × its http routes' matches; an http
// route without matches, or a match without a uri, is every path.
func TestVirtualServiceMatches(t *testing.T) {
	for _, tc := range []struct {
		name, spec, want string
	}{
		{"exact and prefix", `
hosts: [Shop.example.com]
gateways: [edge]
http:
- name: api
  match:
  - uri: {prefix: /api/}
    method: {exact: get}
  - uri: {exact: /login}
  - uri: {prefix: /static}
  route: [{destination: {host: api}}]
- name: web
  route: [{destination: {host: web}}]
`, "shop.example.com/api* GET; shop.example.com/login; shop.example.com/static*; shop.example.com/*"},
		{"any host and wildcards", `
hosts: ["*", "*.example.net"]
http:
- match: [{name: all, uri: {prefix: /}}, {statPrefix: x}]
  route: [{destination: {host: web}}]
`, "/*; *.example.net/* (any depth)"},
	} {
		got, err := virtualServiceMatches(virtualService(t, tc.spec))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if s := routeString(got); s != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, s, tc.want)
		}
	}
}

// What the engine can't express is refused, naming where, rather than
// protecting less than the VirtualService routes.
func TestVirtualServiceMatchesRefused(t *testing.T) {
	for _, tc := range []struct {
		name, spec, want string
	}{
		{"regex uri", "hosts: [a.example.com]\nhttp: [{name: r, match: [{uri: {regex: '/a.*'}}]}]", "spec.http[0].match[0] (route r): regex uris are not supported"},
		{"headers", "hosts: [a.example.com]\nhttp: [{match: [{headers: {x: {exact: y}}}]}]", "headers matches are not supported"},
		{"queryParams", "hosts: [a.example.com]\nhttp: [{match: [{queryParams: {x: {exact: y}}}]}]", "queryParams matches are not supported"},
		{"ignoreUriCase", "hosts: [a.example.com]\nhttp: [{match: [{uri: {exact: /a}, ignoreUriCase: true}]}]", "ignoreUriCase matches are not supported"},
		{"method prefix", "hosts: [a.example.com]\nhttp: [{match: [{method: {prefix: G}}]}]", "only an exact method"},
		{"relative uri", "hosts: [a.example.com]\nhttp: [{match: [{uri: {exact: a}}]}]", `uri "a" is not absolute`},
		{"delegate", "hosts: [a.example.com]\nhttp: [{delegate: {name: other}}]", "spec.http[0]: delegate routes are not supported"},
		{"short host", "hosts: [reviews]\nhttp: [{route: [{destination: {host: reviews}}]}]", `host "reviews" is a short name`},
		{"no http routes", "hosts: [a.example.com]\ntls: [{match: [{sniHosts: [a.example.com]}]}]", "no http routes"},
		{"no hosts", "http: [{route: [{destination: {host: a}}]}]", "no hosts"},
	} {
		_, err := virtualServiceMatches(virtualService(t, tc.spec))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// A policy on a VirtualService gets its routes; a missing one is a missing
// target; one the engine can't express is TargetUnsupported, and a bad edit
// keeps the previous version in force.
func TestVirtualServiceTarget(t *testing.T) {
	p := policy("shop", 0)
	p.Spec.TargetRefs = []wafv1alpha1.TargetRef{{Group: "networking.istio.io", Kind: "VirtualService", Name: "web"}}
	good := virtualService(t, "hosts: [shop.example.com]\ngateways: [edge]\nhttp: [{name: api, match: [{uri: {prefix: /api/}}]}]")
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, VirtualServices: []unstructured.Unstructured{*good}})
	wantStatus(t, res, "shop", true, ReasonAccepted, PolicyValid)
	wantRoutes(t, findPolicy(res, "shop/shop").GetRoutes(), []*bundlev1.RouteMatch{prefix("shop.example.com", "/api")})

	res = Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "VirtualService web not found")

	bad := virtualService(t, "hosts: [shop.example.com]\nhttp: [{name: api, match: [{uri: {regex: /a.*}}]}]")
	prev := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, VirtualServices: []unstructured.Unstructured{*good}})
	res = Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}, VirtualServices: []unstructured.Unstructured{*bad}, Previous: &bundlev1.Bundle{Policies: prev.Policies}})
	wantStatus(t, res, "shop", false, ReasonTargetUnsupported, "VirtualService web: spec.http[0].match[0] (route api): regex uris are not supported")
	wantRoutes(t, findPolicy(res, "shop/shop").GetRoutes(), []*bundlev1.RouteMatch{prefix("shop.example.com", "/api")})
}
