// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"net/http"
	"slices"
	"testing"
)

func withCRS(t *testing.T, s CRSSettings) *Evaluator {
	t.Helper()
	base, err := New(Config{ResponseBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	e, err := base.WithCRS(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestCRSAllowedMethods: a policy's methods replace the CRS's default list
// (GET HEAD POST OPTIONS); a method outside it is still denied (911100).
func TestCRSAllowedMethods(t *testing.T) {
	rest := withCRS(t, CRSSettings{AllowedMethods: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}})
	def := withCRS(t, CRSSettings{})
	for _, tc := range []struct {
		method          string
		rest, byDefault bool // blocked
	}{
		{"GET", false, false},
		{"PUT", false, true},
		{"PATCH", false, true},
		{"DELETE", false, true},
		{"TRACE", true, true},
	} {
		for _, c := range []struct {
			e       *Evaluator
			name    string
			blocked bool
		}{{rest, "allowedMethods", tc.rest}, {def, "default", tc.byDefault}} {
			res, err := c.e.Evaluate(context.Background(), newRequest(tc.method, "/api/items/1", nil, ""))
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted != c.blocked {
				t.Errorf("%s, %s: blocked = %v, want %v (matched %v)", c.name, tc.method, res.Interrupted, c.blocked, res.MatchedRuleIDs)
			}
			if c.blocked && !slices.Contains(res.MatchedRuleIDs, 911100) {
				t.Errorf("%s, %s: blocked without 911100: %v", c.name, tc.method, res.MatchedRuleIDs)
			}
		}
	}
}

// TestCRSAllowedRequestContentTypes: a policy's content types replace the
// CRS's list (920420), case-insensitively as the CRS compares them.
func TestCRSAllowedRequestContentTypes(t *testing.T) {
	allowed := withCRS(t, CRSSettings{AllowedRequestContentTypes: []string{"Application/X-NDJSON", "application/json"}})
	def := withCRS(t, CRSSettings{})
	for _, c := range []struct {
		e           *Evaluator
		contentType string
		blocked     bool
	}{
		{def, "application/x-ndjson", true},
		{allowed, "application/x-ndjson", false},
		{allowed, "application/json", false},
		{allowed, "application/x-www-form-urlencoded", true},
	} {
		h := http.Header{"Content-Type": {c.contentType}}
		res, err := c.e.Evaluate(context.Background(), newRequest("POST", "/api/items", h, `{"a":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if res.Interrupted != c.blocked || c.blocked && !slices.Contains(res.MatchedRuleIDs, 920420) {
			t.Errorf("%s: blocked = %v, want %v (matched %v)", c.contentType, res.Interrupted, c.blocked, res.MatchedRuleIDs)
		}
	}
}

// TestCRSDetectionParanoiaLevel: rules above the blocking level and up to
// the detection level run, and are reported as detected, never blocking.
func TestCRSDetectionParanoiaLevel(t *testing.T) {
	req := newRequest("GET", paranoiaLadder[0], nil, "") // 942480, paranoia level 2
	e := withCRS(t, CRSSettings{ParanoiaLevel: 1, DetectionParanoiaLevel: 2})
	res, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted || !res.Detected || !slices.Contains(res.MatchedRuleIDs, 942480) {
		t.Errorf("detection level 2: %+v, want 942480 detected, not interrupted", res)
	}
	// A request below the threshold at the detection level isn't detected.
	if res, err := e.Evaluate(context.Background(), newRequest("GET", "/?q=%2541", nil, "")); err != nil || res.Detected || res.Interrupted {
		t.Errorf("score 3 at detection level 2: %+v, %v, want neither detected nor interrupted", res, err)
	}
	// Without a detection level, the rule doesn't run.
	res, err = withCRS(t, CRSSettings{ParanoiaLevel: 1}).Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted || res.Detected || len(res.MatchedRuleIDs) != 0 {
		t.Errorf("paranoia level 1 alone: %+v, want nothing", res)
	}
	// Blocking still blocks, and isn't "detected".
	res, err = e.Evaluate(context.Background(), newRequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || res.Detected {
		t.Errorf("SQLi at detection level 2: %+v, want interrupted", res)
	}
}

// TestCRSOutboundAnomalyThreshold: the outbound threshold decides whether a
// leaking response is blocked.
func TestCRSOutboundAnomalyThreshold(t *testing.T) {
	for _, tc := range []struct {
		threshold int
		blocked   bool
	}{{0, true}, {4, true}, {100, false}} {
		x := exchangeFor(t, withCRS(t, CRSSettings{OutboundAnomalyThreshold: tc.threshold}))
		res, err := x.EvaluateResponse(context.Background(), response(500, "text/html", sqlErrorPage))
		if err != nil {
			t.Fatal(err)
		}
		if res.Interrupted != tc.blocked || !slices.Contains(res.MatchedRuleIDs, 951230) {
			t.Errorf("outbound threshold %d: %+v, want blocked=%v with 951230", tc.threshold, res, tc.blocked)
		}
	}
}

func TestCRSSettingsRejected(t *testing.T) {
	for _, s := range []CRSSettings{
		{AllowedMethods: []string{"GET POST"}},
		{AllowedMethods: []string{""}},
		{AllowedMethods: []string{"GET|POST"}},
		{AllowedRequestContentTypes: []string{"json"}},
		{AllowedRequestContentTypes: []string{"application/json; charset=utf-8"}},
		{AllowedRequestContentTypes: []string{"application/json|"}},
		{DetectionParanoiaLevel: 5},
		{DetectionParanoiaLevel: -1},
		{ParanoiaLevel: 3, DetectionParanoiaLevel: 2},
		{OutboundAnomalyThreshold: -1},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded, want error", s)
		}
	}
	for _, s := range []CRSSettings{
		{},
		{AllowedMethods: []string{"GET", "PROPFIND", "M-SEARCH"}},
		{AllowedRequestContentTypes: []string{"application/vnd.api+json", "text/plain"}},
		{ParanoiaLevel: 2, DetectionParanoiaLevel: 2},
		{DetectionParanoiaLevel: 4, OutboundAnomalyThreshold: 1},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", s, err)
		}
	}
}
