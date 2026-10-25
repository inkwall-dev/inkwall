// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

const sqli = "?id=1%27%20OR%20%271%27%3D%271"

func req(host, uri string) *request.Request {
	return &request.Request{
		Proto:  "HTTP/1.1",
		Method: "GET",
		Scheme: "https",
		Host:   host,
		RawURI: uri,
		Headers: http.Header{
			"User-Agent": {"Mozilla/5.0 inkwall-test"},
			"Accept":     {"text/html"},
		},
	}
}

func testBundle() *bundlev1.Bundle {
	return &bundlev1.Bundle{
		Version: 7,
		Policies: []*bundlev1.Policy{
			{
				// The CRS with its defaults, in block mode.
				Id:     "shop/site",
				Mode:   bundlev1.Mode_MODE_BLOCK,
				Routes: []*bundlev1.RouteMatch{rm("shop.example.com", false, "/")},
			},
			{
				// Custom rules only, detect mode, its own body settings.
				Id:            "shop/api",
				Mode:          bundlev1.Mode_MODE_DETECT,
				Routes:        []*bundlev1.RouteMatch{rm("shop.example.com", false, "/api")},
				RuleSets:      []*bundlev1.RuleSetBinding{{RuleSetId: "WAFRuleSet/shop/custom"}},
				SkipPaths:     []string{"/api/health"},
				SkipBodyPaths: []string{"/api/upload"},
				Body:          &bundlev1.BodyConfig{Inspect: true, MaxBytes: 10},
				Timeout:       durationpb.New(100 * time.Millisecond),
			},
			{
				// The CRS at paranoia level 2, bodies not inspected.
				Id:       "shop/admin",
				Mode:     bundlev1.Mode_MODE_BLOCK,
				Routes:   []*bundlev1.RouteMatch{rm("admin.example.com", false, "/")},
				RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "ClusterWAFRuleSet/crs", ParanoiaLevel: 2}},
				Body:     &bundlev1.BodyConfig{Inspect: false},
			},
		},
		RuleSets: []*bundlev1.RuleSet{
			{Id: "ClusterWAFRuleSet/crs", Source: &bundlev1.RuleSet_Builtin{Builtin: bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4}},
			{Id: "WAFRuleSet/shop/custom", Source: &bundlev1.RuleSet_Seclang{Seclang: `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`}},
		},
	}
}

func TestSet(t *testing.T) {
	adm := pipeline.NewAdmission(4)
	set, err := Compile(testBundle(), Options{Admission: adm, BodyLimit: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if set.Version() != 7 || set.Policies() != 3 {
		t.Fatalf("version %d, %d policies", set.Version(), set.Policies())
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		r      *request.Request
		action pipeline.Action
		reason pipeline.Reason
	}{
		{"CRS blocks", req("shop.example.com", "/"+sqli), pipeline.ActionDeny, pipeline.ReasonRule},
		{"benign", req("shop.example.com", "/products/42"), pipeline.ActionAllow, pipeline.ReasonNone},
		// /api runs its own rules only, in detect mode: SQLi isn't one.
		{"custom rules only", req("shop.example.com", "/api/orders"+sqli), pipeline.ActionAllow, pipeline.ReasonNone},
		{"custom rule logs", req("shop.example.com", "/api/orders?q=attack"), pipeline.ActionLog, pipeline.ReasonRule},
		{"skip path", req("shop.example.com", "/api/health?q=attack"), pipeline.ActionAllow, pipeline.ReasonSkipped},
		{"paranoia level 2", req("admin.example.com", "/"+sqli), pipeline.ActionDeny, pipeline.ReasonRule},
		{"no policy", req("other.example.com", "/"+sqli), pipeline.ActionAllow, pipeline.ReasonNoPolicy},
	} {
		v := set.Check(ctx, tc.r)
		if v.Action != tc.action || v.Reason != tc.reason {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.name, v.Action, v.Reason, tc.action, tc.reason)
		}
	}

	for _, tc := range []struct {
		name string
		r    *request.Request
		want int64
	}{
		{"default limit", req("shop.example.com", "/form"), 65536},
		{"the policy's limit", req("shop.example.com", "/api/orders"), 10},
		{"skipped body path", req("shop.example.com", "/api/upload"), 0},
		{"bodies off", req("admin.example.com", "/"), 0},
		{"no policy", req("other.example.com", "/"), 0},
	} {
		if got := set.BodyLimit(tc.r, 1<<20); got != tc.want {
			t.Errorf("%s: body limit %d, want %d", tc.name, got, tc.want)
		}
	}

	// Every policy shares one admission limit.
	for _, p := range set.policies {
		if p.pipeline.Admission() != adm {
			t.Errorf("%s has its own admission limit", p.ID)
		}
	}
}

func TestBodyOverLimit(t *testing.T) {
	set, err := Compile(testBundle(), Options{BodyLimit: 65536})
	if err != nil {
		t.Fatal(err)
	}
	// /api inspects 10 bytes; a longer body is oversize, logged in detect
	// mode.
	r := req("shop.example.com", "/api/orders")
	r.Method = "POST"
	r.Body = []byte("0123456789")
	r.BodyTruncated = true
	if v := set.Check(context.Background(), r); v.Reason != pipeline.ReasonOversize {
		t.Errorf("got %s/%s, want oversize", v.Action, v.Reason)
	}
}

func TestSuspended(t *testing.T) {
	b := testBundle()
	b.Suspended = true
	set, err := Compile(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := req("shop.example.com", "/"+sqli)
	if v := set.Check(context.Background(), r); v.Action != pipeline.ActionAllow || v.Reason != pipeline.ReasonSuspended {
		t.Errorf("got %s/%s, want allow/suspended", v.Action, v.Reason)
	}
	if set.BodyLimit(r, 100) != 0 {
		t.Error("a suspended set reads bodies")
	}
}

func TestEvaluatorsShared(t *testing.T) {
	ev := NewEvaluators()
	b := testBundle()
	// A fourth policy with the same rules as the first.
	b.Policies = append(b.Policies, &bundlev1.Policy{Id: "web/site", Mode: bundlev1.Mode_MODE_DETECT, Routes: []*bundlev1.RouteMatch{rm("web.example.com", false, "/")}})
	set, err := Compile(b, Options{Evaluators: ev, BodyLimit: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Len() != 3 {
		t.Fatalf("%d rule sets compiled for 3 distinct rule configurations", ev.Len())
	}
	if set.policies[0].pipeline == set.policies[3].pipeline {
		t.Fatal("policies with different modes share a pipeline")
	}
	// The next bundle drops two policies: their rule sets are released.
	b.Policies = b.Policies[:1]
	if _, err := Compile(b, Options{Evaluators: ev, BodyLimit: 65536}); err != nil {
		t.Fatal(err)
	}
	if ev.Len() != 1 {
		t.Fatalf("%d rule sets kept, want 1", ev.Len())
	}
}

func TestCompileErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*bundlev1.Bundle)
		want string
	}{
		{"missing rule set", func(b *bundlev1.Bundle) { b.RuleSets = b.RuleSets[:1] }, "policy shop/api: rule set WAFRuleSet/shop/custom is not in the bundle"},
		{"rules that don't compile", func(b *bundlev1.Bundle) {
			b.RuleSets[1].Source = &bundlev1.RuleSet_Seclang{Seclang: `SecRule ARGS "@nosuchop a" "id:100002,phase:1,deny"`}
		}, "policy shop/api"},
		{"bad skip path", func(b *bundlev1.Bundle) { b.Policies[1].SkipPaths = []string{"relative"} }, "policy shop/api"},
		{"unsafe exclusion", func(b *bundlev1.Bundle) {
			b.Policies[0].Exclusions = []*bundlev1.Exclusion{{RuleIds: []uint32{942100}, Argument: `q" "id:1`}}
		}, "policy shop/site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBundle()
			tc.edit(b)
			_, err := Compile(b, Options{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestHolder(t *testing.T) {
	var h Holder
	r := req("shop.example.com", "/"+sqli)
	if v := h.Check(context.Background(), r); v.Action != pipeline.ActionAllow || v.Reason != pipeline.ReasonNoPolicy {
		t.Errorf("before a bundle: got %s/%s", v.Action, v.Reason)
	}
	set, err := Compile(testBundle(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	h.Store(set)
	if v := h.Check(context.Background(), r); v.Action != pipeline.ActionDeny {
		t.Errorf("after a bundle: got %s/%s", v.Action, v.Reason)
	}
	if h.Load() != set {
		t.Error("Load")
	}
}
