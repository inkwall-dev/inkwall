// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/inkwall-dev/inkwall/pkg/iplist"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// limited builds a pipeline in mode with limits, its evaluator recording
// what it saw.
func limitedPipeline(t *testing.T, mode Mode, eval *recordingEvaluator, cfgs ...RateLimitConfig) (*Pipeline, *ratelimit.Store) {
	t.Helper()
	store := ratelimit.New(1024, 0)
	live := ratelimit.NewLive()
	rl, err := CompileRateLimits(store, live, "shop/web", cfgs)
	if err != nil {
		t.Fatal(err)
	}
	allow, _ := iplist.Parse([]string{"10.0.0.0/8"})
	deny, _ := iplist.Parse([]string{"203.0.113.0/24"})
	routes, err := router.New([]string{"/healthz"}, []string{"/upload"})
	if err != nil {
		t.Fatal(err)
	}
	return New(eval, Config{Mode: mode, RateLimits: rl, IPAllow: allow, IPDeny: deny, Routes: routes}), store
}

func req(client, method, uri string) *request.Request {
	return &request.Request{Method: method, RawURI: uri, ClientIP: netip.MustParseAddr(client), Headers: http.Header{}}
}

func check(p *Pipeline, r *request.Request) Verdict { return p.Check(context.Background(), r) }

func TestRateLimitBlock(t *testing.T) {
	eval := &recordingEvaluator{}
	p, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "login", Requests: 1, Period: time.Hour, Burst: 2})
	for i := range 2 {
		if v := check(p, req("198.51.100.7", "POST", "/login")); v.Action != ActionAllow {
			t.Fatalf("request %d of the burst: %s/%s", i+1, v.Action, v.Reason)
		}
	}
	eval.got = nil
	v := check(p, req("198.51.100.7", "POST", "/login"))
	if v.Action != ActionDeny || v.Status != http.StatusTooManyRequests || v.Reason != ReasonRateLimit || v.RateLimit != "login" {
		t.Fatalf("over the limit: %+v, want 429 rate-limit login", v)
	}
	if v.RetryAfter <= 0 || v.RetryAfter > time.Hour {
		t.Errorf("Retry-After %v", v.RetryAfter)
	}
	if eval.got != nil {
		t.Error("a limited request was evaluated: limits run before the rules")
	}
	if !v.RateLimitEvent || v.SampledCount != 1 {
		t.Errorf("first limited request: event %v, sampled %d; want an event of 1", v.RateLimitEvent, v.SampledCount)
	}
	if v := check(p, req("198.51.100.7", "POST", "/login")); v.RateLimitEvent {
		t.Error("the second limited request within the minute is an event too")
	}
	// Another client has its own bucket.
	if v := check(p, req("198.51.100.8", "POST", "/login")); v.Action != ActionAllow {
		t.Errorf("another client: %s/%s", v.Action, v.Reason)
	}
}

// IP lists and skipped paths come first, and aren't counted; a path whose
// body only is skipped is counted.
func TestRateLimitOrder(t *testing.T) {
	eval := &recordingEvaluator{}
	p, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "all", Requests: 1, Period: time.Hour, Burst: 1})
	for _, tc := range []struct {
		name, client, uri string
		reason            Reason
	}{
		{"denied client", "203.0.113.9", "/x", ReasonIPDeny},
		{"allowed client", "10.1.2.3", "/x", ReasonIPAllow},
		{"skipped path", "198.51.100.1", "/healthz", ReasonSkipped},
	} {
		for range 3 {
			if v := check(p, req(tc.client, "GET", tc.uri)); v.Reason != tc.reason {
				t.Errorf("%s: %s, want %s, never rate-limit", tc.name, v.Reason, tc.reason)
			}
		}
	}
	// The skipped paths took no token of 198.51.100.1's bucket.
	if v := check(p, req("198.51.100.1", "GET", "/x")); v.Action != ActionAllow {
		t.Errorf("after skipped requests: %s/%s, want its first token", v.Action, v.Reason)
	}
	check(p, req("198.51.100.2", "POST", "/upload"))
	if v := check(p, req("198.51.100.2", "POST", "/upload")); v.Reason != ReasonRateLimit {
		t.Errorf("a body-skipped path: %s, want counted", v.Reason)
	}
}

// In Detect mode, and for a Detect limit on a Block policy, a request over
// the limit is logged and the rules still run; a rule's reason wins.
func TestRateLimitDetect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   Mode
		detect bool
	}{{"detect policy", ModeDetect, false}, {"detect limit", ModeBlock, true}} {
		eval := &recordingEvaluator{}
		p, _ := limitedPipeline(t, tc.mode, eval, RateLimitConfig{Name: "d", Requests: 1, Period: time.Hour, Burst: 1, Detect: tc.detect})
		check(p, req("198.51.100.7", "GET", "/x"))
		eval.got = nil
		v := check(p, req("198.51.100.7", "GET", "/x"))
		if v.Action != ActionLog || v.Reason != ReasonRateLimit || v.RateLimit != "d" || eval.got == nil {
			t.Errorf("%s: %s/%s %q (evaluated %v), want log rate-limit d, evaluated", tc.name, v.Action, v.Reason, v.RateLimit, eval.got != nil)
		}
		eval.res = blocked
		if v := check(p, req("198.51.100.7", "GET", "/x")); v.Reason != ReasonRule {
			t.Errorf("%s with a rule matching: %s, want the rule's reason", tc.name, v.Reason)
		}
	}
}

// Block limits are charged together: one refusing refunds the others, the
// largest Retry-After of those exceeded is given, and a Detect limit over
// its rate never stops a Block one from being charged.
func TestRateLimitSeveral(t *testing.T) {
	eval := &recordingEvaluator{}
	p, store := limitedPipeline(t, ModeBlock, eval,
		RateLimitConfig{Name: "loose", Requests: 1, Period: time.Hour, Burst: 3},
		RateLimitConfig{Name: "tight", Requests: 1, Period: time.Minute, Burst: 1},
		RateLimitConfig{Name: "noisy", Requests: 1, Period: time.Hour, Burst: 1, Detect: true},
	)
	c := "198.51.100.7"
	if v := check(p, req(c, "GET", "/x")); v.Action != ActionAllow {
		t.Fatalf("first: %s/%s", v.Action, v.Reason)
	}
	v := check(p, req(c, "GET", "/x"))
	if v.Action != ActionDeny || v.RateLimit != "tight" {
		t.Fatalf("second: %s %q, want denied by tight", v.Action, v.RateLimit)
	}
	// loose was refunded: 2 of its 3 tokens left, though 2 requests came.
	k, _ := ratelimit.IPKey(netip.MustParseAddr(c), DefaultIPv6Prefix)
	loose := p.limits.limits[0].lim
	if w := store.Wait(loose, k, time.Now()); w != 0 {
		t.Errorf("loose after a refused request: wait %v, want tokens left", w)
	}
	// A Detect limit over its rate (noisy, from the second request) doesn't
	// gate tight: it still denies on its own count.
	if v.RetryAfter < 59*time.Second {
		t.Errorf("Retry-After %v, want tight's minute", v.RetryAfter)
	}
}

// Paths compare in lower case with one trailing slash ignored, a path that
// can't be read one way counts against every limit with paths, and methods
// narrow it.
func TestRateLimitMatch(t *testing.T) {
	eval := &recordingEvaluator{}
	p, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "login", Requests: 1, Period: time.Hour, Burst: 1,
		Paths: []string{"/login", "/api/session/*"}, Methods: []string{"POST"}})
	for i, tc := range []struct {
		method, uri string
		counted     bool
	}{
		{"POST", "/login", true},
		{"POST", "/Login", true},
		{"POST", "/login/", true},
		{"POST", "/LOGIN/?next=/", true},
		{"POST", "/api/session/new", true},
		{"POST", "/API/Session/x", true},
		{"POST", "/%6Cogin", true},
		{"POST", "/login;x", true},
		{"POST", "//login", true},
		{"POST", "/a/../login", true},
		{"POST", "/logout", false},
		{"POST", "/loginx", false},
		{"POST", "/api/sessions", false},
		{"GET", "/login", false},
		// Methods compare in upper case: an application may serve "post"
		// as POST.
		{"post", "/login", true},
		// Percent-encoding that doesn't change routing is decoded: an é on
		// another path doesn't count against /login.
		{"POST", "/search/caf%C3%A9", false},
		{"POST", "/files/a%20b.pdf", false},
		{"POST", "/log%69n", true},
		// Encodings that do change routing: ambiguous, so counted.
		{"POST", "/x%2F..%2Flogin", true},
		{"POST", "/x%5Clogin", true},
		{"POST", "/%EF%BC%ACogin", true},      // a fullwidth L
		{"POST", "/%C0%AE%C0%AE/login", true}, // overlong dots: invalid UTF-8
	} {
		// A fresh client each: its first request passes, a counted second is limited.
		c := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String()
		check(p, req(c, tc.method, tc.uri))
		v := check(p, req(c, tc.method, tc.uri))
		if (v.Reason == ReasonRateLimit) != tc.counted {
			t.Errorf("%s %s: %s, counted want %v", tc.method, tc.uri, v.Reason, tc.counted)
		}
	}
}

// A header key counts by the header's value; a request without it by its
// client IP, apart from the values; no valid client address isn't limited.
func TestRateLimitKeys(t *testing.T) {
	eval := &recordingEvaluator{}
	p, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "api", Requests: 1, Period: time.Hour, Burst: 1, Header: "X-Api-Key"})
	withKey := func(client, key string) *request.Request {
		r := req(client, "GET", "/x")
		r.Headers.Set("X-Api-Key", key)
		return r
	}
	check(p, withKey("198.51.100.1", "tenant-a"))
	// The same value from another address shares the bucket.
	if v := check(p, withKey("198.51.100.2", "tenant-a")); v.Reason != ReasonRateLimit {
		t.Errorf("tenant-a from a second address: %s, want limited", v.Reason)
	}
	if v := check(p, withKey("198.51.100.1", "tenant-b")); v.Action != ActionAllow {
		t.Errorf("tenant-b: %s, want its own bucket", v.Reason)
	}
	// Without the header: by the client IP, not by an empty value.
	check(p, req("198.51.100.3", "GET", "/x"))
	if v := check(p, req("198.51.100.3", "GET", "/x")); v.Reason != ReasonRateLimit {
		t.Errorf("no header, the same address: %s, want limited", v.Reason)
	}
	if v := check(p, req("198.51.100.4", "GET", "/x")); v.Action != ActionAllow {
		t.Errorf("no header, another address: %s, want allowed", v.Reason)
	}
	// No address at all (a /v1/check call without client_ip): not limited.
	ip, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "ip", Requests: 1, Period: time.Hour, Burst: 1})
	none := &request.Request{Method: "GET", RawURI: "/x", Headers: http.Header{}}
	for range 3 {
		if v := check(ip, none); v.Action != ActionAllow {
			t.Fatalf("no client address: %s/%s, want not limited", v.Action, v.Reason)
		}
	}
}

// The same limit in a later bundle keeps its buckets: a policy edit doesn't
// give every client a fresh burst.
func TestRateLimitAcrossBundles(t *testing.T) {
	store := ratelimit.New(1024, 0)
	cfg := RateLimitConfig{Name: "login", Requests: 1, Period: time.Hour, Burst: 1}
	compile := func(c RateLimitConfig) *Pipeline {
		rl, err := CompileRateLimits(store, ratelimit.NewLive(), "shop/web", []RateLimitConfig{c})
		if err != nil {
			t.Fatal(err)
		}
		return New(&recordingEvaluator{}, Config{Mode: ModeBlock, RateLimits: rl})
	}
	check(compile(cfg), req("198.51.100.7", "GET", "/x"))
	if v := check(compile(cfg), req("198.51.100.7", "GET", "/x")); v.Reason != ReasonRateLimit {
		t.Errorf("the next bundle: %s, want the bucket kept", v.Reason)
	}
	renamed := cfg
	renamed.Name = "login2"
	if v := check(compile(renamed), req("198.51.100.7", "GET", "/x")); v.Action != ActionAllow {
		t.Errorf("a renamed limit: %s, want a fresh bucket", v.Reason)
	}
}

func TestCompileRateLimitsErrors(t *testing.T) {
	store := ratelimit.New(1024, 0)
	for _, c := range []RateLimitConfig{
		{Name: "zero", Requests: 0, Period: time.Second},
		{Name: "short", Requests: 1, Period: time.Millisecond},
		{Name: "path", Requests: 1, Period: time.Second, Paths: []string{"login"}},
		{Name: "star", Requests: 1, Period: time.Second, Paths: []string{"/a*/b"}},
	} {
		if _, err := CompileRateLimits(store, nil, "p", []RateLimitConfig{c}); err == nil {
			t.Errorf("%s: compiled", c.Name)
		}
	}
	if _, err := CompileRateLimits(nil, nil, "p", []RateLimitConfig{{Name: "a", Requests: 1, Period: time.Second}}); err == nil {
		t.Error("compiled without a store")
	}
	if rl, err := CompileRateLimits(nil, nil, "p", nil); rl != nil || err != nil {
		t.Error("no limits needs no store")
	}
}

// BodyLimit decides the limits before the body is read: a request over a
// Block limit gets a body limit of 0, and Check uses that outcome instead
// of charging again (#705).
func TestRateLimitBodyLimit(t *testing.T) {
	eval := &recordingEvaluator{}
	p, _ := limitedPipeline(t, ModeBlock, eval, RateLimitConfig{Name: "upload", Requests: 1, Period: time.Hour, Burst: 2})
	c := "198.51.100.7"
	// Charged once per request, though both BodyLimit and Check ask.
	for i := range 2 {
		r := req(c, "POST", "/x")
		if got := p.BodyLimit(r, 100); got != 100 {
			t.Fatalf("request %d: body limit %d, want 100", i+1, got)
		}
		if v := check(p, r); v.Action != ActionAllow {
			t.Fatalf("request %d: %s/%s, want allowed (charged once)", i+1, v.Action, v.Reason)
		}
	}
	r := req(c, "POST", "/x")
	if got := p.BodyLimit(r, 100); got != 0 {
		t.Fatalf("over the limit: body limit %d, want 0 (the body isn't read)", got)
	}
	if v := check(p, r); v.Status != http.StatusTooManyRequests || !v.RateLimitEvent {
		t.Fatalf("over the limit: %+v, want 429 decided in BodyLimit", v)
	}
	if !p.RateLimited(r) {
		t.Error("RateLimited doesn't name the pipeline that limited")
	}
}

// A bundle swap between BodyLimit and Check: the new bundle's pipeline,
// sharing the store, finds no outcome of its own and decides again,
// charging the request twice: the rare cost of a swap mid-request
// (design 0009 §5.1).
func TestRateLimitBodyLimitSwap(t *testing.T) {
	store := ratelimit.New(1024, 0)
	compile := func() *Pipeline {
		rl, err := CompileRateLimits(store, ratelimit.NewLive(), "shop/web", []RateLimitConfig{{Name: "upload", Requests: 1, Period: time.Hour, Burst: 2}})
		if err != nil {
			t.Fatal(err)
		}
		return New(&recordingEvaluator{}, Config{Mode: ModeBlock, RateLimits: rl})
	}
	old, next := compile(), compile()
	r := req("198.51.100.7", "POST", "/x")
	old.BodyLimit(r, 100)
	if v := check(next, r); v.Action != ActionAllow || next.RateLimited(r) {
		t.Fatalf("after a swap: %s/%s, want allowed by the new pipeline", v.Action, v.Reason)
	}
	// Both charged: the burst of 2 is spent.
	if v := check(next, req("198.51.100.7", "POST", "/x")); v.Reason != ReasonRateLimit {
		t.Errorf("the next request: %s, want limited (the swapped request was charged twice)", v.Reason)
	}
}

// The engine refuses what the CRD refuses, rather than trust the bundle:
// more than 8 limits (a 9th couldn't be refunded), or two of one name
// (they'd share buckets).
func TestCompileRateLimitsBounds(t *testing.T) {
	store := ratelimit.New(1024, 0)
	var nine []RateLimitConfig
	for i := range 9 {
		nine = append(nine, RateLimitConfig{Name: string(rune('a' + i)), Requests: 1, Period: time.Second})
	}
	if _, err := CompileRateLimits(store, nil, "p", nine); err == nil {
		t.Error("9 limits compiled")
	}
	if _, err := CompileRateLimits(store, nil, "p", nine[:8]); err != nil {
		t.Errorf("8 limits: %v", err)
	}
	dup := []RateLimitConfig{{Name: "a", Requests: 1, Period: time.Second}, {Name: "a", Requests: 2, Period: time.Second}}
	if _, err := CompileRateLimits(store, nil, "p", dup); err == nil {
		t.Error("two limits of one name compiled")
	}
}

// A request without a client address is counted once in skipped, however
// many IP limits it skips.
func TestRateLimitNoKeyCountedOnce(t *testing.T) {
	eval := &recordingEvaluator{}
	p, store := limitedPipeline(t, ModeBlock, eval,
		RateLimitConfig{Name: "a", Requests: 1, Period: time.Hour},
		RateLimitConfig{Name: "b", Requests: 1, Period: time.Hour},
		RateLimitConfig{Name: "c", Requests: 1, Period: time.Hour, Detect: true})
	check(p, &request.Request{Method: "GET", RawURI: "/x", Headers: http.Header{}})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(store.Collectors()...)
	if n := testutil.ToFloat64(firstCollector(t, reg, "inkwall_rate_limit_skipped_total")); n != 1 {
		t.Errorf("skipped %v, want 1", n)
	}
}

func firstCollector(t *testing.T, reg *prometheus.Registry, name string) prometheus.Collector {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name && len(mf.GetMetric()) > 0 {
			v := mf.GetMetric()[0].GetCounter().GetValue()
			return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "x", Help: "x"}, func() float64 { return v })
		}
	}
	t.Fatalf("no %s", name)
	return nil
}
