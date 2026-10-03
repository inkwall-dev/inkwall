// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

func newRequest(method, uri string, headers http.Header, body string) *request.Request {
	h := http.Header{
		"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64) inkwall-test"},
		"Accept":     {"text/html,application/json"},
	}
	maps.Copy(h, headers)
	r := &request.Request{
		Proto:    "HTTP/1.1",
		Method:   method,
		Scheme:   "https",
		Host:     "shop.example.com",
		RawURI:   uri,
		Headers:  h,
		ClientIP: netip.MustParseAddr("198.51.100.7"),
	}
	if body != "" {
		r.Body = []byte(body)
		r.Headers.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return r
}

var formHeaders = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}

func TestEvaluateCRS(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		req     *request.Request
		blocked bool
	}{
		{name: "benign get", req: newRequest("GET", "/products?id=42&sort=price", nil, "")},
		{name: "benign form post", req: newRequest("POST", "/login", formHeaders, "user=alice&password=correct-horse")},
		{name: "benign json post", req: newRequest("POST", "/api/orders",
			http.Header{"Content-Type": {"application/json"}}, `{"item":"book","qty":2}`)},
		{name: "sql injection in query", req: newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, ""), blocked: true},
		{name: "union select in query", req: newRequest("GET", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", nil, ""), blocked: true},
		{name: "xss in query", req: newRequest("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", nil, ""), blocked: true},
		{name: "path traversal", req: newRequest("GET", "/download?file=../../../../etc/passwd", nil, ""), blocked: true},
		{name: "xss in form body", req: newRequest("POST", "/comments", formHeaders, "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"), blocked: true},
		{name: "sql injection in json body", req: newRequest("POST", "/api/search",
			http.Header{"Content-Type": {"application/json"}}, `{"q":"1' OR '1'='1' -- "}`), blocked: true},
		{name: "scanner user agent", req: newRequest("GET", "/", http.Header{"User-Agent": {"sqlmap/1.7.2#stable (https://sqlmap.org)"}}, ""), blocked: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := e.Evaluate(context.Background(), tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted != tt.blocked {
				t.Fatalf("Interrupted = %v, want %v (interrupting rule %d, matched %v)",
					res.Interrupted, tt.blocked, res.RuleID, res.MatchedRuleIDs)
			}
			if tt.blocked && len(res.MatchedRuleIDs) == 0 {
				t.Fatal("blocked request reports no matched rules")
			}
			if !tt.blocked && len(res.MatchedRuleIDs) != 0 {
				t.Fatalf("benign request matched rules %v", res.MatchedRuleIDs)
			}
		})
	}
}

func TestCustomDirectivesWithoutCRS(t *testing.T) {
	e, err := New(Config{
		DisableCRS: true,
		Directives: `SecRule ARGS:debug "@streq true" "id:100001,phase:1,deny,status:418,log"`,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := e.Evaluate(context.Background(), newRequest("GET", "/?debug=true", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || res.Status != 418 || res.RuleID != 100001 {
		t.Fatalf("got %+v, want interruption by rule 100001 with status 418", res)
	}
	if !slices.Contains(res.MatchedRuleIDs, 100001) {
		t.Fatalf("MatchedRuleIDs = %v, want 100001", res.MatchedRuleIDs)
	}

	res, err = e.Evaluate(context.Background(), newRequest("GET", "/?debug=false", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted {
		t.Fatalf("got %+v, want no interruption", res)
	}
}

func TestExclusionDirectiveRemovesRule(t *testing.T) {
	req := newRequest("GET", "/search?q=1%27%20OR%20%271%27%3D%271", nil, "")

	// Control: without the exclusion, rule 942100 (libinjection SQLi) matches.
	plain, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := plain.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.MatchedRuleIDs, 942100) {
		t.Fatalf("control: rule 942100 did not match, got %v", res.MatchedRuleIDs)
	}
	// CRS bookkeeping rules (setup, initialization) must not be reported.
	for _, id := range res.MatchedRuleIDs {
		if id >= 900000 && id < 902000 {
			t.Fatalf("bookkeeping rule %d reported as a match: %v", id, res.MatchedRuleIDs)
		}
	}

	// A false-positive exclusion: allow SQL-like text in the "q" argument.
	excluded, err := New(Config{Directives: `SecRuleUpdateTargetById 942100 "!ARGS:q"`})
	if err != nil {
		t.Fatal(err)
	}
	res, err = excluded.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.MatchedRuleIDs, 942100) {
		t.Fatalf("rule 942100 still matched ARGS:q: %v", res.MatchedRuleIDs)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{ParanoiaLevel: 5},
		{InboundAnomalyThreshold: -1},
		{DisableCRS: true, Directives: `SecRule ARGS "@nosuchoperator x" "id:1,deny"`},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded, want error", cfg)
		}
	}
}

func BenchmarkEvaluate(b *testing.B) {
	e, err := New(Config{})
	if err != nil {
		b.Fatal(err)
	}
	cases := map[string]*request.Request{
		"benign_get":   newRequest("GET", "/products?id=42&sort=price", nil, ""),
		"benign_form":  newRequest("POST", "/login", formHeaders, "user=alice&password=correct-horse"),
		"attack_sqli":  newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, ""),
		"attack_xss":   newRequest("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil, ""),
		"benign_large": newRequest("POST", "/api/orders", http.Header{"Content-Type": {"application/json"}}, largeJSON(8<<10)),
	}
	for name, req := range cases {
		b.Run(name, func(b *testing.B) {
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				if _, err := e.Evaluate(ctx, req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func largeJSON(size int) string {
	buf := []byte(`{"items":[`)
	for len(buf) < size {
		buf = append(buf, `{"sku":"book-1234","qty":1,"note":"gift wrap please"},`...)
	}
	buf[len(buf)-1] = ']'
	return string(append(buf, '}'))
}
