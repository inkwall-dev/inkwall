// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// A MySQL error page, as an application leaking its SQL errors returns.
const sqlErrorPage = `<html><body><h1>Error</h1><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p></body></html>`

func response(status int, contentType, body string) *request.Response {
	return &request.Response{
		Status:  status,
		Proto:   "HTTP/1.1",
		Headers: http.Header{"Content-Type": {contentType}},
		Body:    []byte(body),
	}
}

// exchange evaluates a benign request, keeping its transaction.
func exchangeFor(t *testing.T, e *Evaluator) rules.Exchange {
	t.Helper()
	res, x, err := e.EvaluateExchange(context.Background(), newRequest("GET", "/products?id=42", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Interrupted || x == nil {
		t.Fatalf("benign request: interrupted %v, exchange %v", res.Interrupted, x)
	}
	t.Cleanup(x.Close)
	return x
}

func TestEvaluateResponseCRS(t *testing.T) {
	e, err := New(Config{ResponseBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		resp    *request.Response
		blocked bool
		rule    int // a rule that must match
	}{
		{name: "benign html", resp: response(200, "text/html; charset=utf-8", "<html><body>Hello</body></html>")},
		{name: "benign json", resp: response(200, "application/json", `{"items":[1,2,3]}`)},
		{name: "sql error in html", resp: response(500, "text/html", sqlErrorPage), blocked: true, rule: 951230},
		// JSON is read too, unlike coraza.conf-recommended's list.
		{name: "sql error in json", resp: response(500, "application/json",
			`{"error":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"}`), blocked: true, rule: 951230},
		{name: "directory listing", resp: response(200, "text/html",
			`<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><a href="?C=N;O=D">Name</a> <a href="?C=M;O=A">Last modified</a> <a href="/">Parent Directory</a></body></html>`), blocked: true, rule: 950130},
		// The rules don't read an image's body.
		{name: "sql error in an image", resp: response(200, "image/png", sqlErrorPage)},
		// CRS skips encoded bodies (the pipeline decodes gzip and deflate).
		{name: "encoded", resp: &request.Response{Status: 200, Proto: "HTTP/1.1",
			Headers: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"br"}}, Body: []byte(sqlErrorPage)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := exchangeFor(t, e)
			res, err := x.EvaluateResponse(context.Background(), tt.resp)
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted != tt.blocked {
				t.Fatalf("interrupted = %v, want %v (rules %v)", res.Interrupted, tt.blocked, res.MatchedRuleIDs)
			}
			if tt.rule != 0 && !slices.Contains(res.MatchedRuleIDs, tt.rule) {
				t.Errorf("rules %v, want %d among them", res.MatchedRuleIDs, tt.rule)
			}
			if tt.blocked && res.AnomalyScore == 0 {
				t.Error("no outbound anomaly score")
			}
			for _, m := range res.Matches {
				if m.RuleID < 950000 && m.RuleID != res.RuleID {
					t.Errorf("response result lists request rule %d", m.RuleID)
				}
			}
		})
	}
}

// The response's result lists only what matched the response: a request
// that scored (in detect mode, let through) doesn't report its rules again.
func TestEvaluateResponseReportsOnlyResponseMatches(t *testing.T) {
	// A threshold no request reaches: the request scores, isn't interrupted.
	e, err := New(Config{InboundAnomalyThreshold: 1000, ResponseBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	req := newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, "")
	res, x, err := e.EvaluateExchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if res.Interrupted || len(res.MatchedRuleIDs) == 0 {
		t.Fatalf("request: interrupted %v, rules %v; want scored, not interrupted", res.Interrupted, res.MatchedRuleIDs)
	}
	resp, err := x.EvaluateResponse(context.Background(), response(200, "text/html", "<p>ok</p>"))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.MatchedRuleIDs) != 0 || resp.Interrupted {
		t.Errorf("clean response: rules %v, interrupted %v", resp.MatchedRuleIDs, resp.Interrupted)
	}
	if _, err := x.EvaluateResponse(context.Background(), response(200, "text/html", "")); err == nil {
		t.Error("a second response was evaluated")
	}
}

// An interrupted request has no response to evaluate.
func TestEvaluateExchangeInterrupted(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	res, x, err := e.EvaluateExchange(context.Background(), newRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || x != nil {
		t.Fatalf("interrupted %v, exchange %v; want interrupted, no exchange", res.Interrupted, x)
	}
}

// A custom phase 4 rule, as a WAFRuleSet adds: an AWS access key in a
// response.
func TestEvaluateResponseCustomRule(t *testing.T) {
	e, err := New(Config{
		DisableCRS:        true,
		ResponseBodyLimit: 1024,
		Directives: `SecRule RESPONSE_BODY "@rx AKIA[0-9A-Z]{16}" "id:100100,phase:4,deny,status:403,log,msg:'AWS access key in a response'"
SecRule RESPONSE_HEADERS:X-Debug "@streq on" "id:100101,phase:3,deny,status:403,log"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		resp *request.Response
		rule int
	}{
		{name: "clean", resp: response(200, "application/json", `{"key":"none"}`)},
		{name: "key in body", resp: response(200, "application/json", `{"key":"AKIAABCDEFGHIJKLMNOP"}`), rule: 100100},
		{name: "debug header", resp: &request.Response{Status: 200, Headers: http.Header{"X-Debug": {"on"}}}, rule: 100101},
		// Past the limit Coraza doesn't read.
		{name: "key past the limit", resp: response(200, "text/plain", string(make([]byte, 1100))+"AKIAABCDEFGHIJKLMNOP")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := exchangeFor(t, e)
			res, err := x.EvaluateResponse(context.Background(), tt.resp)
			if err != nil {
				t.Fatal(err)
			}
			if res.RuleID != tt.rule || res.Interrupted != (tt.rule != 0) {
				t.Errorf("interrupted %v by %d, want %d", res.Interrupted, res.RuleID, tt.rule)
			}
		})
	}
}
