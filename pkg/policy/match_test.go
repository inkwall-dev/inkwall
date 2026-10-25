// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

func rm(host string, exact bool, p string, methods ...string) *bundlev1.RouteMatch {
	t := bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX
	if exact {
		t = bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
	}
	return &bundlev1.RouteMatch{Host: host, Path: &bundlev1.PathMatch{Type: t, Value: p}, Methods: methods}
}

func testMatcher(routes map[string][]*bundlev1.RouteMatch) *matcher {
	var rs []route
	for id, ms := range routes {
		p := &Policy{ID: id}
		for _, m := range ms {
			rs = append(rs, newRoute(m, p))
		}
	}
	return newMatcher(rs)
}

func TestLookup(t *testing.T) {
	m := testMatcher(map[string][]*bundlev1.RouteMatch{
		"site":     {rm("shop.example.com", false, "/")},
		"api":      {rm("shop.example.com", false, "/api/")},
		"api-v2":   {rm("shop.example.com", false, "/api/v2")},
		"login":    {rm("shop.example.com", true, "/login")},
		"admin":    {rm("shop.example.com", false, "/admin")},
		"writes":   {rm("shop.example.com", false, "/orders", "POST", "PUT")},
		"orders":   {rm("shop.example.com", false, "/orders")},
		"tenants":  {rm("*.tenants.example.com", false, "/")},
		"special":  {rm("acme.tenants.example.com", false, "/")},
		"fallback": {rm("", false, "/")},
	})
	for _, tc := range []struct {
		host, uri, method, want string
	}{
		{"shop.example.com", "/", "GET", "site"},
		{"shop.example.com", "/products/42?x=1", "GET", "site"},
		// Element-wise prefixes, longest first.
		{"shop.example.com", "/api", "GET", "api"},
		{"shop.example.com", "/api/orders", "GET", "api"},
		{"shop.example.com", "/apix", "GET", "site"},
		{"shop.example.com", "/api/v2/orders", "GET", "api-v2"},
		{"shop.example.com", "/api/v20", "GET", "api"},
		// Exact over prefix.
		{"shop.example.com", "/login", "GET", "login"},
		{"shop.example.com", "/login/x", "GET", "site"},
		// Methods.
		{"shop.example.com", "/orders/1", "POST", "writes"},
		{"shop.example.com", "/orders/1", "GET", "orders"},
		// The path as the proxy routes it: decoded and cleaned.
		{"shop.example.com", "/api/../admin/users", "GET", "admin"},
		{"shop.example.com", "/api/..%2fadmin", "GET", "admin"},
		{"shop.example.com", "/%61dmin", "GET", "admin"},
		{"shop.example.com", "//admin", "GET", "admin"},
		{"shop.example.com", "/api/./v2", "GET", "api-v2"},
		// Host: case, port, trailing dot.
		{"Shop.Example.COM:443", "/api", "GET", "api"},
		{"shop.example.com.", "/api", "GET", "api"},
		// Wildcards cover one label; an exact host wins.
		{"blue.tenants.example.com", "/", "GET", "tenants"},
		{"acme.tenants.example.com", "/", "GET", "special"},
		{"a.b.tenants.example.com", "/", "GET", "fallback"},
		{"tenants.example.com", "/", "GET", "fallback"},
		{"other.example.com", "/x", "GET", "fallback"},
	} {
		got := m.lookup(tc.host, tc.uri, tc.method)
		if got == nil || got.ID != tc.want {
			id := "<nil>"
			if got != nil {
				id = got.ID
			}
			t.Errorf("%s %s%s: got %s, want %s", tc.method, tc.host, tc.uri, id, tc.want)
		}
	}
}

func TestLookupFallback(t *testing.T) {
	m := testMatcher(map[string][]*bundlev1.RouteMatch{
		"api":    {rm("shop.example.com", false, "/api")},
		"health": {rm("shop.example.com", true, "/healthz")},
	})
	// A covered host, a path none of its routes match: the host's most
	// general policy, not no inspection.
	if got := m.lookup("shop.example.com", "/static/app.js", "GET"); got == nil || got.ID != "api" {
		t.Errorf("unmatched path of a covered host: got %v, want api", got)
	}
	// A host no policy covers.
	if got := m.lookup("other.example.com", "/api", "GET"); got != nil {
		t.Errorf("uncovered host: got %s, want none", got.ID)
	}
}

// BenchmarkLookup measures route matching on every request, with 1,000
// routes over 100 hosts.
func BenchmarkLookup(b *testing.B) {
	routes := map[string][]*bundlev1.RouteMatch{}
	for h := range 100 {
		host := "h" + string(rune('a'+h%26)) + string(rune('a'+h/26)) + ".example.com"
		for p := range 10 {
			id := host + "/" + string(rune('a'+p))
			routes[id] = []*bundlev1.RouteMatch{rm(host, false, "/svc"+string(rune('a'+p)))}
		}
	}
	m := testMatcher(routes)
	b.ReportAllocs()
	for b.Loop() {
		if m.lookup("hzc.example.com", "/svcj/orders/42?page=2", "GET") == nil {
			b.Fatal("no policy")
		}
	}
}
