// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
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

// BenchmarkEvaluateExclusions is BenchmarkEvaluate's benign GET with a
// policy's worth of exclusions: arguments everywhere, and rules on paths the
// request is on or isn't.
func BenchmarkEvaluateExclusions(b *testing.B) {
	excl := []Exclusion{
		{RuleIDs: []int{942100}, Argument: "q"},
		{RuleIDs: []int{941100, 941110}, Argument: "comment"},
		{RuleIDs: []int{920350}},
	}
	for i := range 8 {
		excl = append(excl, Exclusion{RuleIDs: []int{942100, 932100}, Path: fmt.Sprintf("/app%d/*", i), Argument: "query"})
	}
	excl = append(excl, Exclusion{RuleIDs: []int{941100}, Path: "/products"})
	e, err := New(Config{Exclusions: excl})
	if err != nil {
		b.Fatal(err)
	}
	cases := map[string]*request.Request{
		"benign_get":      newRequest("GET", "/products?id=42&sort=price", nil, ""),
		"benign_get_app3": newRequest("GET", "/app3/search?query=shoes&page=2", nil, ""),
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

func TestScoreOnlyCustomRulesAreReported(t *testing.T) {
	e, err := New(Config{
		DirectivesBeforeCRS: `SecAction "id:10000,phase:1,pass,nolog,setvar:tx.custom_flag=1"`,
		Directives:          `SecRule ARGS:q "@contains forbidden" "id:10001,phase:2,block,setvar:'tx.inbound_anomaly_score_pl1=+5'"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Evaluate(context.Background(), newRequest("GET", "/search?q=forbidden", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.MatchedRuleIDs, 10001) {
		t.Fatalf("score-only custom rule not reported: %v", res.MatchedRuleIDs)
	}
	if slices.Contains(res.MatchedRuleIDs, 10000) {
		t.Fatalf("custom SecAction reported as a match: %v", res.MatchedRuleIDs)
	}
	for _, id := range res.MatchedRuleIDs {
		if inRange(id, internalIDMin, internalIDMax) || (inRange(id, 900000, 901999)) {
			t.Fatalf("setup rule %d reported: %v", id, res.MatchedRuleIDs)
		}
	}
}

func TestExclusions(t *testing.T) {
	const rule = `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`
	type check struct {
		uri     string
		blocked bool
	}
	for _, tc := range []struct {
		name      string
		exclusion Exclusion
		checks    []check
	}{
		{"everywhere", Exclusion{RuleIDs: []int{100001}}, []check{
			{"/search?q=attack", false}, {"/other?p=attack", false},
		}},
		{"one argument", Exclusion{RuleIDs: []int{100001}, Argument: "q"}, []check{
			{"/search?q=attack", false}, {"/search?p=attack", true},
		}},
		{"exact path", Exclusion{RuleIDs: []int{100001}, Path: "/search"}, []check{
			{"/search?q=attack", false}, {"/search/x?q=attack", true}, {"/other?q=attack", true},
		}},
		{"path prefix", Exclusion{RuleIDs: []int{100001}, Path: "/api/*"}, []check{
			{"/api/v1?q=attack", false}, {"/apix?q=attack", true}, {"/?q=attack", true},
			// Paths a proxy would route outside /api/ don't get its
			// exclusions, however they are spelled.
			{"/api/../admin?q=attack", true},
			{"/api/..%2fadmin?q=attack", true},
			{"/api/%2e%2e/admin?q=attack", true},
			{"/api//../admin?q=attack", true},
			{"/api/./v1?q=attack", true},
			{"/api/v1/..?q=attack", true},
		}},
		{"path and argument", Exclusion{RuleIDs: []int{100001}, Path: "/search", Argument: "q"}, []check{
			{"/search?q=attack", false}, {"/search?p=attack", true}, {"/other?q=attack", true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := New(Config{DisableCRS: true, Directives: rule, Exclusions: []Exclusion{tc.exclusion}})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range tc.checks {
				res, err := e.Evaluate(context.Background(), newRequest("GET", c.uri, nil, ""))
				if err != nil {
					t.Fatal(err)
				}
				if res.Interrupted != c.blocked {
					t.Errorf("%s: blocked=%v, want %v", c.uri, res.Interrupted, c.blocked)
				}
			}
		})
	}
}

func TestExclusionsWithCRS(t *testing.T) {
	// The documented example: rule 942100 (libinjection SQLi) off for the
	// search box only.
	sqli := "?q=1%27%20OR%20%271%27%3D%271"
	plain, err := New(Config{Exclusions: []Exclusion{{RuleIDs: []int{942100}, Path: "/search", Argument: "q"}}})
	if err != nil {
		t.Fatal(err)
	}
	ids := func(uri string) []int {
		res, err := plain.Evaluate(context.Background(), newRequest("GET", uri, nil, ""))
		if err != nil {
			t.Fatal(err)
		}
		return res.MatchedRuleIDs
	}
	if slices.Contains(ids("/search"+sqli), 942100) {
		t.Error("942100 matched q on /search despite the exclusion")
	}
	if !slices.Contains(ids("/other"+sqli), 942100) {
		t.Error("942100 no longer matches elsewhere")
	}
}

func TestExclusionsShareRules(t *testing.T) {
	const rule = `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"
SecRule ARGS "@contains exploit" "id:100002,phase:2,deny,status:403,log"`
	shared, err := New(Config{DisableCRS: true, Directives: rule})
	if err != nil {
		t.Fatal(err)
	}
	a, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100001}, Argument: "a"}, {RuleIDs: []int{100002}, Path: "/a/*"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100001}, Argument: "b"}, {RuleIDs: []int{100002}, Path: "/b"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.waf != shared.waf || b.waf != shared.waf {
		t.Fatal("WithExclusions compiled its own rules")
	}
	// Each evaluator gets its own exclusions only; the shared one none.
	checks := []struct {
		uri              string
		shared, inA, inB bool // blocked
	}{
		{"/x?a=attack", true, false, true},
		{"/x?b=attack", true, true, false},
		{"/x?c=attack", true, true, true},
		{"/a/1?q=exploit", true, false, true},
		{"/b?q=exploit", true, true, false},
		{"/b/1?q=exploit", true, true, true},
	}
	evals := []*Evaluator{shared, a, b}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for i := range 50 {
				c := checks[i%len(checks)]
				for j, want := range []bool{c.shared, c.inA, c.inB} {
					res, err := evals[j].Evaluate(context.Background(), newRequest("GET", c.uri, nil, ""))
					if err != nil {
						t.Error(err)
						return
					}
					if res.Interrupted != want {
						t.Errorf("evaluator %d, %s: blocked=%v, want %v", j, c.uri, res.Interrupted, want)
					}
				}
			}
		})
	}
	wg.Wait()

	// Replacing, not adding to, the exclusions.
	none, err := a.WithExclusions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := none.Evaluate(context.Background(), newRequest("GET", "/x?a=attack", nil, "")); err != nil || !res.Interrupted {
		t.Errorf("a's exclusions survived WithExclusions(nil): %+v, %v", res, err)
	}
}

// leaks evaluates "/<x>?<y>=attack" concurrently on each evaluator, which
// must block it (none excludes y on x), and counts the requests let through.
func leaks(t *testing.T, cases map[*Evaluator][]string) int {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	leaked := 0
	for e, uris := range cases {
		for _, uri := range uris {
			for range 4 {
				wg.Go(func() {
					for range 300 {
						res, err := e.Evaluate(context.Background(), newRequest("GET", uri, nil, ""))
						if err != nil {
							t.Error(err)
							return
						}
						if !res.Interrupted {
							mu.Lock()
							leaked++
							mu.Unlock()
						}
					}
				})
			}
		}
	}
	wg.Wait()
	return leaked
}

// Coraza 3.8.1 appends a transaction's target exclusions to the rule's own
// negations in place (see argsNegation). Before exclusions were applied per
// transaction, three argument exclusions everywhere (compiled in as
// negations) and a path one for the same rule let concurrent requests swap
// exclusions.
func TestExclusionsDontLeakAcrossRequests(t *testing.T) {
	const rule = `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`
	e, err := New(Config{DisableCRS: true, Directives: rule, Exclusions: []Exclusion{
		{RuleIDs: []int{100001}, Argument: "z1"}, {RuleIDs: []int{100001}, Argument: "z2"}, {RuleIDs: []int{100001}, Argument: "z3"},
		{RuleIDs: []int{100001}, Path: "/a", Argument: "a"}, {RuleIDs: []int{100001}, Path: "/b", Argument: "b"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if n := leaks(t, map[*Evaluator][]string{e: {"/a?b=attack", "/b?a=attack"}}); n != 0 {
		t.Errorf("%d requests got another request's exclusions", n)
	}
}

// Rules that negate ARGS targets themselves get a rule set of their own for
// argument exclusions, so policies can't swap them.
func TestExclusionsWithArgsNegatingRules(t *testing.T) {
	const rule = `SecRule ARGS|!ARGS:z1|!ARGS:z2|!ARGS:z3 "@contains attack" "id:100001,phase:2,deny,status:403,log"`
	shared, err := New(Config{DisableCRS: true, Directives: rule})
	if err != nil {
		t.Fatal(err)
	}
	a, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100001}, Argument: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100001}, Argument: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	ruleOff, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100001}, Path: "/off"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.variants == nil || b.variants == nil {
		t.Error("argument exclusions share rules that negate ARGS targets")
	}
	if ruleOff.variants != nil {
		t.Error("an exclusion without arguments compiled its own rules")
	}
	if n := leaks(t, map[*Evaluator][]string{a: {"/x?b=attack"}, b: {"/x?a=attack"}, shared: {"/x?a=attack"}}); n != 0 {
		t.Errorf("%d requests got another policy's exclusions", n)
	}
	// Their own exclusions, and none from a's compiled rules once replaced.
	for _, c := range []struct {
		e       *Evaluator
		uri     string
		blocked bool
	}{{a, "/x?a=attack", false}, {b, "/x?b=attack", false}, {ruleOff, "/off?a=attack", false}, {ruleOff, "/on?a=attack", true}} {
		if res, err := c.e.Evaluate(context.Background(), newRequest("GET", c.uri, nil, "")); err != nil || res.Interrupted != c.blocked {
			t.Errorf("%s: %+v, %v; want blocked=%v", c.uri, res, err, c.blocked)
		}
	}
	none, err := a.WithExclusions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := none.Evaluate(context.Background(), newRequest("GET", "/x?a=attack", nil, "")); err != nil || !res.Interrupted {
		t.Errorf("a's compiled exclusions survived WithExclusions(nil): %+v, %v", res, err)
	}
}

// With rules that negate ARGS targets themselves, argument exclusions on
// paths are compiled in too, one rule set for each set of path exclusions a
// request can be on.
func TestPathExclusionsWithArgsNegatingRules(t *testing.T) {
	const rule = `SecRule ARGS|!ARGS:z1|!ARGS:z2|!ARGS:z3 "@contains attack" "id:100001,phase:2,deny,status:403,log"`
	e, err := New(Config{DisableCRS: true, Directives: rule, Exclusions: []Exclusion{
		{RuleIDs: []int{100001}, Argument: "all"},
		{RuleIDs: []int{100001}, Path: "/a", Argument: "a"},
		{RuleIDs: []int{100001}, Path: "/b", Argument: "b"},
		{RuleIDs: []int{100001}, Path: "/api/*", Argument: "p1"},
		{RuleIDs: []int{100001}, Path: "/api/v1/*", Argument: "p2"},
		{RuleIDs: []int{100001}, Path: "/api/v1/x", Argument: "x"},
		{RuleIDs: []int{100001}, Path: "/off"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if e.variants == nil {
		t.Fatal("argument exclusions applied per transaction to rules that negate ARGS targets")
	}
	// none, /a, /b, /api/*, /api/v1/*, /api/v1/x
	if n := len(e.variants.wafs); n != 6 {
		t.Errorf("%d rule sets, want 6", n)
	}
	if n := leaks(t, map[*Evaluator][]string{e: {"/a?b=attack", "/b?a=attack", "/api/v1/x?b=attack", "/api/x?p2=attack"}}); n != 0 {
		t.Errorf("%d requests got another request's exclusions", n)
	}
	for _, c := range []struct {
		uri     string
		blocked bool
	}{
		{"/x?all=attack", false}, {"/a?all=attack", false}, {"/x?a=attack", true},
		{"/a?a=attack", false}, {"/b?b=attack", false}, {"/a/?a=attack", true},
		{"/api/x?p1=attack", false}, {"/api/x?p2=attack", true},
		{"/api/v1/y?p1=attack", false}, {"/api/v1/y?p2=attack", false}, {"/api/v1/y?x=attack", true},
		{"/api/v1/x?p1=attack", false}, {"/api/v1/x?p2=attack", false}, {"/api/v1/x?x=attack", false},
		{"/api/../b?p1=attack", true}, {"/api//v1/y?p1=attack", true},
		{"/off?q=attack", false}, {"/on?q=attack", true},
	} {
		res, err := e.Evaluate(context.Background(), newRequest("GET", c.uri, nil, ""))
		if err != nil {
			t.Fatal(err)
		}
		if res.Interrupted != c.blocked {
			t.Errorf("%s: blocked=%v, want %v", c.uri, res.Interrupted, c.blocked)
		}
	}
}

// A rule ID no rule has is ignored, with rules that negate ARGS targets
// themselves or not.
func TestExclusionsIgnoreUnknownRules(t *testing.T) {
	for _, rule := range []string{
		`SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`,
		`SecRule ARGS|!ARGS:z "@contains attack" "id:100001,phase:2,deny,status:403,log"`,
	} {
		e, err := New(Config{DisableCRS: true, Directives: rule, Exclusions: []Exclusion{
			{RuleIDs: []int{999999}},
			{RuleIDs: []int{999998, 100001}, Argument: "q"},
			{RuleIDs: []int{999997}, Path: "/p", Argument: "q"},
			{RuleIDs: []int{999996}, Path: "/p"},
		}})
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		for _, c := range []struct {
			uri     string
			blocked bool
		}{{"/x?q=attack", false}, {"/x?p=attack", true}, {"/p?p=attack", true}} {
			res, err := e.Evaluate(context.Background(), newRequest("GET", c.uri, nil, ""))
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted != c.blocked {
				t.Errorf("%s, %s: blocked=%v, want %v", rule, c.uri, res.Interrupted, c.blocked)
			}
		}
	}
}

// An argument exclusion covers the rules chained to the rule too
// (ctl:ruleRemoveTargetById); with rules that negate ARGS targets
// themselves it is compiled in and covers the rule only
// (SecRuleUpdateTargetById).
func TestArgumentExclusionsAndChainedRules(t *testing.T) {
	const chain = `SecRule REQUEST_METHOD "@streq GET" "id:100001,phase:2,deny,status:403,log,chain"
SecRule ARGS "@contains attack" "t:none"`
	for _, tc := range []struct {
		directives string
		blocked    bool
	}{
		{chain, false},
		{chain + "\nSecRule ARGS|!ARGS:z \"@contains never\" \"id:100002,phase:2,pass,nolog\"", true},
	} {
		for _, path := range []string{"", "/x"} {
			e, err := New(Config{DisableCRS: true, Directives: tc.directives, Exclusions: []Exclusion{{RuleIDs: []int{100001}, Path: path, Argument: "q"}}})
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Evaluate(context.Background(), newRequest("GET", "/x?q=attack", nil, ""))
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted != tc.blocked {
				t.Errorf("path %q, private %v: blocked=%v, want %v", path, e.variants != nil, res.Interrupted, tc.blocked)
			}
		}
	}
}

// Sharing rules across argument exclusions is safe only while the CRS
// negates no ARGS targets itself (see argsNegation).
func TestCRSNegatesNoArgs(t *testing.T) {
	negation := regexp.MustCompile(`(?i)!\s*args(?:[^a-z_]|$)`)
	err := fs.WalkDir(coreruleset.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && negation.MatchString(line) {
				t.Errorf("%s negates ARGS: %s", path, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPathExclusionMatchesSecLang checks that path exclusions are decided
// as the SecLang rules they replace decided them, on tricky paths.
func TestPathExclusionMatchesSecLang(t *testing.T) {
	uris := []string{
		"/", "/api", "/api/", "/api/v1", "/apix", "/api/v1/", "/API/v1", "/api/./v1", "/api/../admin",
		"/api/..%2fadmin", "/api/%2e%2e/admin", "/api//v1", "/api/v1/..", "/api/v1/.", "/api/.hidden",
		"/api/..x", "/api/x..", "/api/x%0a../admin", "/api/x%0a/../admin", "/api/x%0d%0a..", "/api/%00/..",
		"/api/v1%3fq", "/api/v1?q=1", "/api%2fv1", "/search", "/search/", "/search%2f", "/searc%68",
		"//api/v1", "/api/v1#frag", "http://host/api/v1", "/api/v1;x=1",
	}
	for _, pattern := range []string{"/api/*", "/search", "/"} {
		x, err := compileExclusions([]Exclusion{{RuleIDs: []int{1}, Path: pattern}})
		if err != nil {
			t.Fatal(err)
		}
		p := &x.paths[0]
		var rule string
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
			rule = fmt.Sprintf("SecRule REQUEST_FILENAME \"@beginsWith %s\" \"id:100001,phase:1,deny,status:403,t:none,nolog,chain\"\n", prefix) +
				"SecRule REQUEST_FILENAME \"!@rx (?:^|/)\\.\\.?(?:/|$)|//\" \"t:none\""
		} else {
			rule = fmt.Sprintf("SecRule REQUEST_FILENAME \"@streq %s\" \"id:100001,phase:1,deny,status:403,t:none,nolog\"", pattern)
		}
		e, err := New(Config{DisableCRS: true, Directives: rule})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[bool]bool{}
		for _, uri := range uris {
			tx := e.waf.NewTransaction()
			tx.ProcessURI(uri, "GET", "HTTP/1.1")
			filename := tx.(plugintypes.TransactionState).Variables().RequestFilename().Get()
			want := tx.ProcessRequestHeaders() != nil
			_ = tx.Close()
			if got := p.matches(filename); got != want {
				t.Errorf("%s on %q (REQUEST_FILENAME %q): matches=%v, SecLang %v", pattern, uri, filename, got, want)
			}
			seen[want] = true
		}
		if !seen[true] || !seen[false] {
			t.Errorf("%s: the paths don't test both outcomes: %v", pattern, seen)
		}
	}
}

// TestPathExclusionsKeepSetupRules: the phase 1 rules that ran before path
// exclusions when they were SecLang rules are still not turned off by them.
func TestPathExclusionsKeepSetupRules(t *testing.T) {
	conf, err := fs.ReadFile(coreruleset.FS, "@coraza.conf-recommended")
	if err != nil {
		t.Fatal(err)
	}
	phase1 := regexp.MustCompile(`id:'?(\d+)'?,\s*phase:1`)
	var ids []int
	for _, m := range phase1.FindAllStringSubmatch(string(conf)+argumentLimitRules, -1) {
		id, _ := strconv.Atoi(m[1])
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		t.Fatal("no phase 1 rules found")
	}
	for _, id := range append(ids, idParanoiaLevel, idAnomalyThreshold) {
		if !setupRules[id] {
			t.Errorf("phase 1 setup rule %d missing from setupRules", id)
		}
	}

	// A path exclusion of the JSON body processor rule leaves JSON parsed
	// (and inspected); one everywhere turns it off, as before.
	json := http.Header{"Content-Type": {"application/json"}}
	body := `{"q":"1' OR '1'='1"}`
	for _, tc := range []struct {
		exclusion Exclusion
		blocked   bool
	}{
		{Exclusion{RuleIDs: []int{200001}, Path: "/api/*"}, true},
		{Exclusion{RuleIDs: []int{200001, 942100}, Path: "/api/*"}, false},
		{Exclusion{RuleIDs: []int{200001}}, false},
	} {
		e, err := New(Config{Exclusions: []Exclusion{tc.exclusion}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Evaluate(context.Background(), newRequest("POST", "/api/search", json, body))
		if err != nil {
			t.Fatal(err)
		}
		if res.Interrupted != tc.blocked {
			t.Errorf("%+v: blocked=%v, want %v (%v)", tc.exclusion, res.Interrupted, tc.blocked, res.MatchedRuleIDs)
		}
	}
}

func TestExclusionsRejectUnsafeValues(t *testing.T) {
	for _, e := range []Exclusion{
		{},
		{RuleIDs: []int{0}},
		{RuleIDs: []int{1}, Path: `/a" "id:1`},
		{RuleIDs: []int{1}, Path: "relative"},
		{RuleIDs: []int{1}, Argument: `q" "id:1`},
		{RuleIDs: []int{1}, Argument: "a b"},
	} {
		if _, err := New(Config{DisableCRS: true, Exclusions: []Exclusion{e}}); err == nil {
			t.Errorf("%+v: accepted", e)
		}
	}
}

func TestMatchesAndAnomalyScore(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Evaluate(context.Background(), newRequest("GET", "/search?q=1%27%20OR%20%271%27%3D%271", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	var sqli *rules.Match
	for i, m := range res.Matches {
		if !slices.Contains(res.MatchedRuleIDs, m.RuleID) {
			t.Errorf("match %+v for a rule not in MatchedRuleIDs %v", m, res.MatchedRuleIDs)
		}
		if m.RuleID == 942100 {
			sqli = &res.Matches[i]
		}
	}
	if sqli == nil {
		t.Fatalf("no match for 942100: %+v", res.Matches)
	}
	if sqli.Variable != "ARGS:q" || !strings.Contains(sqli.Value, "OR") {
		t.Errorf("942100 matched %s = %q, want ARGS:q with the payload", sqli.Variable, sqli.Value)
	}
	// 942100 alone is critical (5); the threshold is 5 by default.
	if res.AnomalyScore < 5 {
		t.Errorf("anomaly score %d, want at least 5", res.AnomalyScore)
	}

	benign, err := e.Evaluate(context.Background(), newRequest("GET", "/search?q=shoes", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if benign.AnomalyScore != 0 || len(benign.Matches) != 0 {
		t.Errorf("benign request: score %d, matches %+v", benign.AnomalyScore, benign.Matches)
	}
}
