// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// adminAndSite is a host with a block-mode policy on /admin and a
// detect-mode one on the rest, possibly from another namespace on a shared
// Gateway.
func adminAndSite() *bundlev1.Bundle {
	return &bundlev1.Bundle{
		Version: 1,
		Policies: []*bundlev1.Policy{
			{
				Id:      "shop/admin",
				Mode:    bundlev1.Mode_MODE_BLOCK,
				Routes:  []*bundlev1.RouteMatch{rm("shop.example.com", false, "/admin")},
				Timeout: testTimeout,
			},
			{
				Id:      "other/site",
				Mode:    bundlev1.Mode_MODE_DETECT,
				Routes:  []*bundlev1.RouteMatch{rm("shop.example.com", false, "/")},
				Timeout: testTimeout,
			},
		},
	}
}

// TestCheckAppliesThePolicyOfEveryPathForm: proxies route on different
// forms of a path (as received, with dot segments removed, with slashes
// merged, with %2F decoded). When those forms select different policies,
// the request is inspected by each, and the strictest verdict applies.
func TestCheckAppliesThePolicyOfEveryPathForm(t *testing.T) {
	set, err := Compile(adminAndSite(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		uri  string
		want pipeline.Action
	}{
		{"/admin/users" + sqli, pipeline.ActionDeny},
		{"/products" + sqli, pipeline.ActionLog},
		// Routed to /admin by a proxy that keeps %2F or doesn't normalize.
		{"/admin/..%2Fsite" + sqli, pipeline.ActionDeny},
		{"/admin/..%2fsite" + sqli, pipeline.ActionDeny},
		{"/admin/../site" + sqli, pipeline.ActionDeny},
		{"/admin//../site" + sqli, pipeline.ActionDeny},
		{"/admin/x/..%2F..%2Fsite" + sqli, pipeline.ActionDeny},
		{"/admin/%2e%2e/site" + sqli, pipeline.ActionDeny},
		// Routed to /admin by a proxy that decodes and cleans the path.
		{"/site/..%2Fadmin/users" + sqli, pipeline.ActionDeny},
		{"/site/../admin/users" + sqli, pipeline.ActionDeny},
		{"/%61dmin/users" + sqli, pipeline.ActionDeny},
		{"//admin/users" + sqli, pipeline.ActionDeny},
		// Clean requests with such paths pass.
		{"//admin/users", pipeline.ActionAllow},
		{"/%61dmin/users", pipeline.ActionAllow},
	} {
		v := set.Check(ctx, req("shop.example.com", tc.uri))
		if v.Action != tc.want {
			t.Errorf("%s: %v (policy %s, reason %v), want %v", tc.uri, v.Action, v.Policy, v.Reason, tc.want)
		}
		if tc.want == pipeline.ActionDeny && v.Policy != "shop/admin" {
			t.Errorf("%s: denied by %s, want shop/admin", tc.uri, v.Policy)
		}
	}
}

// TestCheckEveryPathFormDetectOnly: when every policy the forms select is
// in detect mode, the request is logged, never denied.
func TestCheckEveryPathFormDetectOnly(t *testing.T) {
	b := adminAndSite()
	b.Policies[0].Mode = bundlev1.Mode_MODE_DETECT
	set, err := Compile(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := set.Check(context.Background(), req("shop.example.com", "/admin/..%2Fsite"+sqli)); v.Action != pipeline.ActionLog {
		t.Errorf("detect only: %v, want log", v.Action)
	}
}

// TestCheckEveryPathFormSkipPaths: a skip path of one policy doesn't
// skip the other's inspection.
func TestCheckEveryPathFormSkipPaths(t *testing.T) {
	b := adminAndSite()
	b.Policies[1].SkipPaths = []string{"/"}
	set, err := Compile(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := set.Check(context.Background(), req("shop.example.com", "//admin/users"+sqli)); v.Action != pipeline.ActionDeny {
		t.Errorf("skipped by the other policy: %v, want deny", v.Action)
	}
}

// TestCheckEveryPathFormBodies: the body is read to the largest limit of
// the policies, and each inspects it to its own.
func TestCheckEveryPathFormBodies(t *testing.T) {
	b := adminAndSite()
	b.Policies[0].Body = &bundlev1.BodyConfig{Inspect: true, MaxBytes: 4096}
	b.Policies[1].Body = &bundlev1.BodyConfig{Inspect: false}
	set, err := Compile(b, Options{BodyLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	post := func(uri string) *request.Request {
		r := req("shop.example.com", uri)
		r.Method = http.MethodPost
		r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = []byte("id=1%27%20OR%20%271%27%3D%271")
		r.Headers.Set("Content-Length", "29")
		return r
	}
	if got := set.BodyLimit(post("/products"), 0); got != 0 {
		t.Errorf("BodyLimit(/products) = %d, want 0", got)
	}
	if got := set.BodyLimit(post("//admin/users"), 0); got != 4096 {
		t.Errorf("BodyLimit(//admin/users) = %d, want 4096", got)
	}
	if v := set.Check(context.Background(), post("//admin/users")); v.Action != pipeline.ActionDeny {
		t.Errorf("body attack: %v, want deny", v.Action)
	}
}

// TestCheckExchangeEveryPathForm: the response is inspected by each
// policy that inspects responses.
func TestCheckExchangeEveryPathForm(t *testing.T) {
	b := adminAndSite()
	b.Policies[0].Responses = &bundlev1.ResponseConfig{Inspect: true}
	b.Policies[1].Responses = &bundlev1.ResponseConfig{Inspect: true, MaxBytes: 1 << 20}
	set, err := Compile(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, x := set.CheckExchange(ctx, req("shop.example.com", "/admin/..%2Fsite"+sqli)); x != nil {
		t.Error("a denied request kept an exchange")
		x.Close()
	}
	v, x := set.CheckExchange(ctx, req("shop.example.com", "//admin/users"))
	if v.Action != pipeline.ActionAllow || x == nil {
		t.Fatalf("benign request: %v, exchange %v", v.Action, x)
	}
	defer x.Close()
	if x.BodyLimit() != 1<<20 {
		t.Errorf("response body limit %d, want %d", x.BodyLimit(), 1<<20)
	}
	if x.FailureMode() != pipeline.FailClosed {
		t.Errorf("failure mode %v, want closed", x.FailureMode())
	}
	rv := x.CheckResponse(ctx, &request.Response{Status: 500, Headers: http.Header{"Content-Type": {"text/html"}},
		Body: []byte("<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>")})
	if rv.Action != pipeline.ActionDeny || rv.Policy != "shop/admin" {
		t.Errorf("response verdict %v by %q, want deny by shop/admin", rv.Action, rv.Policy)
	}
}

// TestGRPCStreamEveryPathForm: a call whose path forms select several
// policies is buffered, so each inspects it whole.
func TestGRPCStreamEveryPathForm(t *testing.T) {
	b := adminAndSite()
	for _, p := range b.Policies {
		p.Body = &bundlev1.BodyConfig{Inspect: true, GrpcMessages: true, GrpcPerMessage: true}
	}
	set, err := Compile(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	call := func(uri string) *request.Request {
		r := req("shop.example.com", uri)
		r.Method, r.Proto = http.MethodPost, "HTTP/2"
		r.Headers = http.Header{"Content-Type": {"application/grpc"}, "Te": {"trailers"}}
		return r
	}
	if set.GRPCStream(call("/admin.Admin/Run")) == nil {
		t.Error("one policy: GRPCStream nil")
	}
	if set.GRPCStream(call("/admin/..%2Fsite.Site/Run")) != nil {
		t.Error("several policies: GRPCStream not nil")
	}
}

func TestPathForms(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want []string
	}{
		{"/", []string{"/"}},
		{"/api/orders?x=1", []string{"/api/orders"}},
		{"/api/", []string{"/api", "/api/"}},
		{"/admin/..%2Fsite", []string{"/site", "/admin/..%2Fsite"}},
		{"/admin//../site", []string{"/site", "/admin//../site", "/admin/site"}},
		{"/%61dmin", []string{"/admin", "/%61dmin"}},
		{"/a/%2e%2e/b", []string{"/b", "/a/%2e%2e/b"}},
	} {
		got := pathForms(tc.uri, nil)
		for _, w := range tc.want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: forms %q, missing %q", tc.uri, got, w)
			}
		}
		if got[0] != normalizePath(tc.uri) {
			t.Errorf("%s: first form %q, want %q", tc.uri, got[0], normalizePath(tc.uri))
		}
		for _, f := range got {
			if !strings.HasPrefix(f, "/") {
				t.Errorf("%s: form %q", tc.uri, f)
			}
		}
	}
}
