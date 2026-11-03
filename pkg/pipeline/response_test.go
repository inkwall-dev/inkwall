// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// exchangeEvaluator allows every request and interrupts responses whose
// body contains "LEAK"; it records what it was given.
type exchangeEvaluator struct {
	block  <-chan struct{} // if set, EvaluateResponse waits for it to close
	mu     sync.Mutex
	got    []*request.Response
	open   atomic.Int32
	closed chan struct{}
}

func (f *exchangeEvaluator) Evaluate(context.Context, *request.Request) (rules.Result, error) {
	return rules.Result{}, nil
}

func (f *exchangeEvaluator) EvaluateExchange(_ context.Context, r *request.Request) (rules.Result, rules.Exchange, error) {
	if strings.Contains(r.RawURI, "attack") {
		return blocked, nil, nil
	}
	f.open.Add(1)
	return rules.Result{}, &fakeExchange{f: f}, nil
}

type fakeExchange struct {
	f      *exchangeEvaluator
	closed bool
}

func (x *fakeExchange) EvaluateResponse(_ context.Context, resp *request.Response) (rules.Result, error) {
	if x.closed {
		panic("evaluated after Close")
	}
	if x.f.block != nil {
		<-x.f.block
	}
	x.f.mu.Lock()
	x.f.got = append(x.f.got, resp)
	x.f.mu.Unlock()
	if bytes.Contains(resp.Body, []byte("LEAK")) {
		return rules.Result{Interrupted: true, Status: 403, RuleID: 951230, MatchedRuleIDs: []int{951230, 959100}, AnomalyScore: 5}, nil
	}
	return rules.Result{}, nil
}

func (x *fakeExchange) Close() {
	if x.closed {
		panic("closed twice")
	}
	x.closed = true
	if x.f.open.Add(-1) == 0 && x.f.closed != nil {
		close(x.f.closed)
	}
}

func get(uri string) *request.Request {
	return &request.Request{Method: "GET", RawURI: uri, Proto: "HTTP/1.1", Headers: http.Header{}}
}

func html(body string) *request.Response {
	return &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte(body)}
}

func TestCheckResponse(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		oversize OversizeAction
		resp     *request.Response
		action   Action
		status   int
		reason   Reason
	}{
		{name: "clean", mode: ModeBlock, resp: html("hello"), action: ActionAllow},
		{name: "leak blocked", mode: ModeBlock, resp: html("a LEAK"), action: ActionDeny, status: 403, reason: ReasonRule},
		{name: "leak detected", mode: ModeDetect, resp: html("a LEAK"), action: ActionLog, reason: ReasonRule},
		// A truncated body's prefix is inspected: the leak in it is found.
		{name: "leak in a truncated prefix", mode: ModeDetect, oversize: OversizeAllow,
			resp:   &request.Response{Status: 200, Headers: http.Header{}, Body: []byte("LEAK"), BodyTruncated: true},
			action: ActionLog, reason: ReasonRule},
		{name: "truncated, block mode default", mode: ModeBlock,
			resp:   &request.Response{Status: 200, Headers: http.Header{}, Body: []byte("ok"), BodyTruncated: true},
			action: ActionDeny, status: 502, reason: ReasonOversize},
		{name: "truncated, allowed", mode: ModeBlock, oversize: OversizeAllow,
			resp:   &request.Response{Status: 200, Headers: http.Header{}, Body: []byte("ok"), BodyTruncated: true},
			action: ActionAllow, reason: ReasonOversize},
		{name: "truncated, detect mode default", mode: ModeDetect,
			resp:   &request.Response{Status: 200, Headers: http.Header{}, Body: []byte("ok"), BodyTruncated: true},
			action: ActionAllow, reason: ReasonOversize},
		{name: "uninspected, denied in detect mode", mode: ModeDetect, oversize: OversizeDeny,
			resp:   &request.Response{Status: 200, Headers: http.Header{}, BodyUninspected: true},
			action: ActionLog, reason: ReasonOversize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(&exchangeEvaluator{}, Config{Mode: tt.mode, Responses: ResponseConfig{Inspect: true, MaxBytes: 64, Oversize: tt.oversize}})
			v, x := p.CheckExchange(context.Background(), get("/"))
			if v.Action != ActionAllow || x == nil {
				t.Fatalf("request: %v, exchange %v", v.Action, x)
			}
			defer x.Close()
			x.OnVerdict("ns/p", nil)
			got := x.CheckResponse(context.Background(), tt.resp)
			if got.Action != tt.action || got.Status != tt.status || got.Reason != tt.reason {
				t.Errorf("verdict %v %d %v, want %v %d %v", got.Action, got.Status, got.Reason, tt.action, tt.status, tt.reason)
			}
			if !got.Response || got.Policy != "ns/p" {
				t.Errorf("verdict Response %v, Policy %q", got.Response, got.Policy)
			}
		})
	}
}

// Without response inspection, or on a skipped route, or for a request
// denied, there is no exchange; Check never keeps one.
func TestCheckExchangeWhenNotInspected(t *testing.T) {
	routes, err := router.New([]string{"/healthz"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eval := &exchangeEvaluator{}
	on := New(eval, Config{Mode: ModeBlock, Routes: routes, Responses: ResponseConfig{Inspect: true}})
	off := New(eval, Config{Mode: ModeBlock})
	for _, tc := range []struct {
		name string
		p    *Pipeline
		uri  string
	}{
		{"responses off", off, "/"},
		{"skipped route", on, "/healthz"},
		{"denied request", on, "/attack"},
	} {
		if _, x := tc.p.CheckExchange(context.Background(), get(tc.uri)); x != nil {
			t.Errorf("%s: an exchange", tc.name)
			x.Close()
		}
	}
	on.Check(context.Background(), get("/"))
	if n := eval.open.Load(); n != 0 {
		t.Errorf("%d evaluations left open", n)
	}
}

// A response evaluation that times out gets the failure mode, and Close
// during it closes the evaluation once it finishes, not before.
func TestCheckResponseTimeout(t *testing.T) {
	release := make(chan struct{})
	eval := &exchangeEvaluator{block: release, closed: make(chan struct{})}
	p := New(eval, Config{Mode: ModeBlock, Timeout: 10 * time.Millisecond, Responses: ResponseConfig{Inspect: true, MaxBytes: 64}})
	_, x := p.CheckExchange(context.Background(), get("/"))
	v := x.CheckResponse(context.Background(), html("hello"))
	if v.Action != ActionDeny || v.Status != http.StatusServiceUnavailable || v.Reason != ReasonTimeout {
		t.Errorf("timed out: %v %d %v, want fail closed", v.Action, v.Status, v.Reason)
	}
	x.Close()
	select {
	case <-eval.closed:
		t.Fatal("closed while evaluating")
	default:
	}
	close(release)
	select {
	case <-eval.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("not closed after the evaluation finished")
	}
	// Checked once only.
	if v := x.CheckResponse(context.Background(), html("x")); v.Reason != ReasonError {
		t.Errorf("second check: %v", v.Reason)
	}
}

// A response refused an evaluation slot gets the failure mode, and Close
// still releases the request's evaluation.
func TestCheckResponseOverload(t *testing.T) {
	eval := &exchangeEvaluator{closed: make(chan struct{})}
	adm := NewAdmission(1)
	p := New(eval, Config{Mode: ModeBlock, Admission: adm, Responses: ResponseConfig{Inspect: true, MaxBytes: 64}})
	_, x := p.CheckExchange(context.Background(), get("/"))
	if x == nil {
		t.Fatal("no exchange")
	}
	adm.slots <- struct{}{} // every slot taken
	v := x.CheckResponse(context.Background(), html("hello"))
	<-adm.slots
	if v.Action != ActionDeny || v.Status != http.StatusServiceUnavailable || v.Reason != ReasonOverload {
		t.Errorf("overloaded: %v %d %v, want fail closed", v.Action, v.Status, v.Reason)
	}
	x.Close()
	select {
	case <-eval.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the request's evaluation was never closed")
	}
}

func gzipped(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func deflated(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCheckResponseDecodes(t *testing.T) {
	long := strings.Repeat("x", 100) + "LEAK"
	tests := []struct {
		name       string
		encoding   string
		body       []byte
		truncated  bool // input cut by the proxy
		action     Action
		reason     Reason
		inspected  string
		uninspectd bool
	}{
		{name: "gzip", encoding: "gzip", body: gzipped(t, "a LEAK"), action: ActionDeny, reason: ReasonRule, inspected: "a LEAK"},
		{name: "deflate", encoding: "deflate", body: deflated(t, "a LEAK"), action: ActionDeny, reason: ReasonRule, inspected: "a LEAK"},
		// Decoded past the limit: the prefix, truncated.
		{name: "gzip over the limit", encoding: "gzip", body: gzipped(t, long), action: ActionDeny, reason: ReasonOversize, inspected: strings.Repeat("x", 64)},
		// Cut by the proxy: what decodes is inspected.
		{name: "gzip cut", encoding: "gzip", body: gzipped(t, "a LEAK and more")[:20], truncated: true, action: ActionDeny, reason: ReasonOversize},
		{name: "brotli", encoding: "br", body: []byte("\x0b\x02\x80a LEAK\x03"), action: ActionDeny, reason: ReasonOversize, uninspectd: true},
		{name: "garbage gzip", encoding: "gzip", body: []byte("not gzip at all"), action: ActionDeny, reason: ReasonOversize, uninspectd: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := &exchangeEvaluator{}
			p := New(eval, Config{Mode: ModeBlock, Responses: ResponseConfig{Inspect: true, MaxBytes: 64}})
			_, x := p.CheckExchange(context.Background(), get("/"))
			defer x.Close()
			resp := &request.Response{Status: 200, Body: tt.body, BodyTruncated: tt.truncated,
				Headers: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {tt.encoding}, "Content-Length": {"10"}}}
			v := x.CheckResponse(context.Background(), resp)
			if v.Action != tt.action || v.Reason != tt.reason {
				t.Errorf("verdict %v %v, want %v %v", v.Action, v.Reason, tt.action, tt.reason)
			}
			got := eval.got[0]
			if got.Headers.Get("Content-Encoding") != "" && !tt.uninspectd {
				t.Error("rules saw Content-Encoding on a decoded body")
			}
			if resp.Headers.Get("Content-Encoding") != tt.encoding {
				t.Error("the adapter's headers were changed")
			}
			if got.BodyUninspected != tt.uninspectd || tt.uninspectd && got.Body != nil {
				t.Errorf("uninspected %v, body %q", got.BodyUninspected, got.Body)
			}
			if tt.inspected != "" && string(got.Body) != tt.inspected {
				t.Errorf("inspected %q, want %q", got.Body, tt.inspected)
			}
			if len(got.Body) > 64 {
				t.Errorf("inspected %d bytes, limit 64", len(got.Body))
			}
		})
	}
}

func TestInspectedResponseType(t *testing.T) {
	for ct, want := range map[string]bool{
		"text/html; charset=utf-8": true,
		"application/json":         true,
		"Application/JSON":         true,
		"image/png":                false,
		"text/event-stream":        false,
		"application/grpc":         false,
		"":                         false,
		";;":                       false,
	} {
		if got := InspectedResponseType(ct); got != want {
			t.Errorf("%q: %v, want %v", ct, got, want)
		}
	}
	x := &Exchange{p: New(&exchangeEvaluator{}, Config{Responses: ResponseConfig{Inspect: true}})}
	if x.WantsBody("text/html") {
		t.Error("a body is wanted with no body limit")
	}
}
