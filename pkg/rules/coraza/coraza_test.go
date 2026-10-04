// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3/types"

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
		// Caught by rule 942220; Coraza's regex prefilter used to miss it.
		{name: "magic number dos", req: newRequest("GET", "/get?i=2.2250738585072011e-308", nil, ""), blocked: true},
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

func TestMaxArgs(t *testing.T) {
	e, err := New(Config{MaxArgs: 10})
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 30)
	for i := range fields {
		fields[i] = fmt.Sprintf("f%d=v", i)
	}

	// Body arguments over the limit: rejected in phase 2 by rule 200005.
	res, err := e.Evaluate(context.Background(), newRequest("POST", "/api", formHeaders, strings.Join(fields, "&")))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || res.RuleID != 200005 || res.Status != 400 {
		t.Fatalf("30 body args with MaxArgs 10: got %+v, want 400 from rule 200005", res)
	}

	// Query arguments over the limit: rejected in phase 1 by rule 200004.
	res, err = e.Evaluate(context.Background(), newRequest("GET", "/?"+strings.Join(fields, "&"), nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || res.RuleID != 200004 {
		t.Fatalf("30 query args with MaxArgs 10: got %+v, want rule 200004", res)
	}

	res, err = e.Evaluate(context.Background(), newRequest("POST", "/api", formHeaders, strings.Join(fields[:5], "&")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted {
		t.Fatalf("5 args with MaxArgs 10: got %+v, want allowed", res)
	}
}

func TestArgumentsPastTheDefaultLimitAreNotHidden(t *testing.T) {
	// 1000 harmless arguments followed by an attack. Coraza drops arguments
	// past its limit from inspection; the request must be rejected instead.
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]string, DefaultMaxArgs)
	for i := range fields {
		fields[i] = fmt.Sprintf("f%d=1", i)
	}
	attack := "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	for _, req := range []*request.Request{
		newRequest("GET", "/?"+strings.Join(fields, "&")+"&"+attack, nil, ""),
		newRequest("POST", "/", formHeaders, strings.Join(fields, "&")+"&"+attack),
	} {
		res, err := e.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Interrupted {
			t.Fatalf("%s with %d fillers before an attack was not interrupted: %+v", req.Method, len(fields), res)
		}
	}
}

func TestTruncatedBodyIsNotInspected(t *testing.T) {
	// A truncated JSON prefix must not reach the JSON parser: it would fail to
	// parse and rule 200002 would reject a valid request.
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	req := newRequest("POST", "/api", http.Header{"Content-Type": {"application/json"}}, `{"note":"unterminated`)
	req.BodyTruncated = true
	res, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted {
		t.Fatalf("truncated body was parsed: %+v", res)
	}
}

func TestBodyLimitAllowsLargeBodies(t *testing.T) {
	// Coraza's default SecRequestBodyLimit is 12.5 MiB; with BodyLimit set
	// higher, a body within the caller's limit is not rejected by Coraza.
	e, err := New(Config{DisableCRS: true, BodyLimit: 14 << 20})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("a", 13<<20)
	res, err := e.Evaluate(context.Background(), newRequest("POST", "/upload", http.Header{"Content-Type": {"text/plain"}}, body))
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted {
		t.Fatalf("13 MiB body rejected despite BodyLimit 14 MiB: %+v", res)
	}
}
func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{ParanoiaLevel: 5},
		{InboundAnomalyThreshold: -1},
		{MaxArgs: -1},
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

// BenchmarkEvaluateArgs shows how cost grows with the number of request
// arguments: CRS evaluates most rules once per argument, so this is the main
// driver of body inspection time.
func BenchmarkEvaluateArgs(b *testing.B) {
	e, err := New(Config{})
	if err != nil {
		b.Fatal(err)
	}
	jsonHeaders := http.Header{"Content-Type": {"application/json"}}
	for _, n := range []int{10, 50, 150} {
		items := make([]string, n)
		fields := make([]string, n)
		for i := range n {
			items[i] = fmt.Sprintf(`{"v":"value %d"}`, i)
			fields[i] = fmt.Sprintf("f%d=value+%d", i, i)
		}
		cases := map[string]*request.Request{
			fmt.Sprintf("json_%d", n): newRequest("POST", "/api", jsonHeaders, `{"items":[`+strings.Join(items, ",")+`]}`),
			fmt.Sprintf("form_%d", n): newRequest("POST", "/api", formHeaders, strings.Join(fields, "&")),
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
}

func largeJSON(size int) string {
	buf := []byte(`{"items":[`)
	for len(buf) < size {
		buf = append(buf, `{"sku":"book-1234","qty":1,"note":"gift wrap please"},`...)
	}
	buf[len(buf)-1] = ']'
	return string(append(buf, '}'))
}

func TestDirectivesBeforeCRSAndOnMatch(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	e, err := New(Config{
		// A runtime exclusion must run before CRS: drop SQLi detection for
		// requests to /search.
		DirectivesBeforeCRS: `SecRule REQUEST_FILENAME "@streq /search" "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`,
		OnMatch: func(mr types.MatchedRule) {
			mu.Lock()
			defer mu.Unlock()
			logs = append(logs, mr.ErrorLog())
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sqli := "?q=1%27%20OR%20%271%27%3D%271"
	res, err := e.Evaluate(context.Background(), newRequest("GET", "/search"+sqli, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.MatchedRuleIDs, 942100) {
		t.Fatalf("runtime exclusion did not apply: %v", res.MatchedRuleIDs)
	}

	res, err = e.Evaluate(context.Background(), newRequest("GET", "/products"+sqli, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.MatchedRuleIDs, 942100) {
		t.Fatalf("exclusion leaked to other paths: %v", res.MatchedRuleIDs)
	}

	mu.Lock()
	defer mu.Unlock()
	if !slices.ContainsFunc(logs, func(l string) bool { return strings.Contains(l, `[id "942100"]`) }) {
		t.Fatalf("OnMatch did not report rule 942100; got %d log lines", len(logs))
	}
}

func TestDisabledRuleGroups(t *testing.T) {
	php := newRequest("GET", "/?q=%3C%3Fphp%20system(%24_GET%5Bcmd%5D)%3B%20%3F%3E", nil, "")
	hasGroup := func(ids []int, prefix int) bool {
		return slices.ContainsFunc(ids, func(id int) bool { return id/1000 == prefix })
	}

	// Control: the PHP family matches the payload.
	all, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := all.Evaluate(context.Background(), php)
	if err != nil {
		t.Fatal(err)
	}
	if !hasGroup(res.MatchedRuleIDs, 933) {
		t.Fatalf("control: no 933xxx rule matched, got %v", res.MatchedRuleIDs)
	}

	pruned, err := New(Config{DisabledRuleGroups: []string{"php", "java"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err = pruned.Evaluate(context.Background(), php)
	if err != nil {
		t.Fatal(err)
	}
	if hasGroup(res.MatchedRuleIDs, 933) {
		t.Fatalf("php group disabled but 933xxx matched: %v", res.MatchedRuleIDs)
	}

	// Other families still work.
	res, err = pruned.Evaluate(context.Background(), newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted {
		t.Fatal("sqli no longer blocked with php and java disabled")
	}

	if _, err := New(Config{DisabledRuleGroups: []string{"cobol"}}); err == nil {
		t.Fatal("unknown group accepted")
	}
}

func TestUserSettingsBeforeCRSWinOverInkwallDefaults(t *testing.T) {
	sqli := newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, "")

	// A user raising the anomaly threshold before CRS, using CRS's documented
	// setup ID, must neither collide with Inkwall's own setting nor be
	// overwritten by it.
	e, err := New(Config{DirectivesBeforeCRS: `SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=100"`})
	if err != nil {
		t.Fatalf("CRS setup ID 900110 rejected: %v", err)
	}
	res, err := e.Evaluate(context.Background(), sqli)
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted {
		t.Fatalf("user threshold 100 was overwritten: a single SQLi match blocked (%+v)", res)
	}
	if !slices.Contains(res.MatchedRuleIDs, 942100) {
		t.Fatalf("SQLi not detected at all: %v", res.MatchedRuleIDs)
	}
}
