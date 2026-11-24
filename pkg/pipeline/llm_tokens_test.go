// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// tokenPipeline is a Block policy with a chat endpoint capping output at
// 1,000 tokens, and limits: tokens per client per minute (the cfgs).
func tokenPipeline(t *testing.T, mode Mode, cfgs ...RateLimitConfig) (*Pipeline, *exchangeEvaluator) {
	t.Helper()
	limits, err := CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat", cfgs)
	if err != nil {
		t.Fatal(err)
	}
	l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}},
		Checks: llm.Config{MaxOutputTokens: 1000}, Metrics: llm.NewMetrics()})
	eval := &exchangeEvaluator{}
	return New(eval, Config{Mode: mode, LLM: l, RateLimits: limits, Responses: ResponseConfig{Inspect: true, MaxBytes: 64 << 10}}), eval
}

// chat is a chat request whose estimate is 1 (a 3-byte prompt) plus
// maxTokens.
func chat(maxTokens int) *request.Request {
	return llmRequest("/v1/chat/completions", fmt.Sprintf(`{"model":"m","messages":[{"role":"user","content":"abc"}],"max_tokens":%d}`, maxTokens))
}

func usage(total int) *request.Response {
	return &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}},
		Body: fmt.Appendf(nil, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":%d}}`, total-1)}
}

var tokensPerMinute = RateLimitConfig{Name: "tokens", Requests: 1000, Period: time.Minute, Tokens: true}

func TestTokenLimits(t *testing.T) {
	ctx := context.Background()
	p, _ := tokenPipeline(t, ModeBlock, tokensPerMinute)
	// 400 + 1 tokens each: two fit in 1,000, a third doesn't.
	for i := range 2 {
		if v := p.Check(ctx, chat(400)); v.Action != ActionAllow {
			t.Fatalf("request %d: %s %s", i, v.Action, v.Reason)
		}
	}
	v := p.Check(ctx, chat(400))
	if v.Action != ActionDeny || v.Status != 429 || v.Reason != ReasonRateLimit || v.RateLimit != "tokens" || v.RetryAfter < time.Second {
		t.Fatalf("over the tokens: %s %d %s %q %v", v.Action, v.Status, v.Reason, v.RateLimit, v.RetryAfter)
	}
	// A smaller request still fits: the refused one took nothing.
	if v := p.Check(ctx, chat(100)); v.Action != ActionAllow {
		t.Errorf("101 tokens of the 198 left: %s", v.Reason)
	}
	// A request a check denies isn't charged, nor one elsewhere.
	if v := p.Check(ctx, chat(5000)); v.Reason != ReasonLLM {
		t.Errorf("over the output cap: %s", v.Reason)
	}
	if v := p.Check(ctx, llmRequest("/v1/models", "")); v.Action != ActionAllow {
		t.Errorf("another path: %s", v.Reason)
	}
	if v := p.Check(ctx, chat(90)); v.Action != ActionAllow {
		t.Errorf("91 tokens of the 97 left: %s", v.Reason)
	}
}

// A request limit and a token limit on one policy: each counts its own.
func TestTokenAndRequestLimits(t *testing.T) {
	ctx := context.Background()
	p, _ := tokenPipeline(t, ModeBlock, tokensPerMinute, RateLimitConfig{Name: "requests", Requests: 3, Period: time.Minute})
	for i := range 2 {
		if v := p.Check(ctx, chat(400)); v.Action != ActionAllow {
			t.Fatalf("request %d: %s", i, v.Reason)
		}
	}
	if v := p.Check(ctx, chat(400)); v.RateLimit != "tokens" {
		t.Errorf("third: limit %q, want tokens", v.RateLimit)
	}
	if v := p.Check(ctx, chat(1)); v.RateLimit != "requests" {
		t.Errorf("fourth: limit %q, want requests", v.RateLimit)
	}
}

func TestTokenLimitDetect(t *testing.T) {
	ctx := context.Background()
	detect := tokensPerMinute
	detect.Detect = true
	p, _ := tokenPipeline(t, ModeBlock, detect)
	p.Check(ctx, chat(900))
	v := p.Check(ctx, chat(900))
	if v.Action != ActionLog || v.Reason != ReasonRateLimit || v.RateLimit != "tokens" {
		t.Errorf("a Detect token limit: %s %s %q", v.Action, v.Reason, v.RateLimit)
	}
	p, _ = tokenPipeline(t, ModeDetect, tokensPerMinute)
	p.Check(ctx, chat(900))
	if v := p.Check(ctx, chat(900)); v.Action != ActionLog || v.Reason != ReasonRateLimit {
		t.Errorf("a Detect policy: %s %s", v.Action, v.Reason)
	}
}

// TestTokenSettlement: a whole response's usage settles the bucket: what
// the estimate overcharged is refunded, what it undercharged is debt, and
// a key in debt is refused before its body is read.
func TestTokenSettlement(t *testing.T) {
	ctx := context.Background()
	exchange := func(p *Pipeline, r *request.Request, resp *request.Response) Verdict {
		t.Helper()
		v, x := p.CheckExchange(ctx, r)
		if x == nil {
			return v
		}
		defer x.Close()
		if x.BodyLimit() == 0 {
			t.Error("the response body isn't read for its usage")
		}
		x.CheckResponse(ctx, resp)
		return v
	}
	p, eval := tokenPipeline(t, ModeBlock, tokensPerMinute)
	// 901 charged, 50 used: 851 back, so another 901 fits.
	if v := exchange(p, chat(900), usage(50)); v.Action != ActionAllow {
		t.Fatal(v.Reason)
	}
	if v := exchange(p, chat(900), usage(901)); v.Action != ActionAllow {
		t.Fatalf("after a refund: %s", v.Reason)
	}
	// 50 + 901 used of 1,000: a request of 101 doesn't fit.
	if v := p.Check(ctx, chat(100)); v.Reason != ReasonRateLimit {
		t.Fatalf("after the refund's tokens were used: %s", v.Reason)
	}
	// The rules never got the response's body (ruleSetBody: Skip).
	for _, resp := range eval.got {
		if resp.Body != nil {
			t.Error("the rules read an endpoint's response body")
		}
	}

	// Debt: 11 charged, 3,000 used. The key is refused before its body is
	// read (BodyLimit 0), with Retry-After.
	p, _ = tokenPipeline(t, ModeBlock, tokensPerMinute)
	exchange(p, chat(10), usage(3000))
	r := chat(1)
	if n := p.BodyLimit(r, 1<<20); n != 0 {
		t.Errorf("a key in debt: body limit %d", n)
	}
	if v := p.Check(ctx, r); v.Status != 429 || v.RetryAfter < 10*time.Second {
		t.Errorf("a key in debt: %d, Retry-After %v", v.Status, v.RetryAfter)
	}

	// No usage (a stream, an error page, a body cut): the estimate stands.
	for _, resp := range []*request.Response{
		{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}, Body: usage(1).Body},
		{Status: 502, Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte("<h1>Bad Gateway</h1>")},
		{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}}, Body: usage(1).Body[:20], BodyTruncated: true},
	} {
		p, _ = tokenPipeline(t, ModeBlock, tokensPerMinute)
		exchange(p, chat(900), resp)
		if v := p.Check(ctx, chat(900)); v.Reason != ReasonRateLimit {
			t.Errorf("%s %s: settled", resp.Headers.Get("Content-Type"), resp.Body)
		}
	}
}

// TestTokenFallback: a request on an endpoint whose body can't be
// estimated (not parsed, cut, encoded, or not read) is charged as large as
// it may be, its bytes ÷ 3 plus the output cap, never nothing.
func TestTokenFallback(t *testing.T) {
	ctx := context.Background()
	limit := RateLimitConfig{Name: "tokens", Requests: 5000, Period: time.Minute, Tokens: true}
	dup := `{"model":"m","messages":[{"role":"user","content":"abc"}],"max_tokens":1,"max_tokens":1}`
	for _, tc := range []struct {
		name   string
		llm    func(*LLMConfig)
		routes []string // skip.bodyPaths
		req    func() *request.Request
	}{
		{"unparsed, the LLM checks in Detect", func(c *LLMConfig) { c.Detect = true }, nil,
			func() *request.Request { return llmRequest("/v1/chat/completions", dup) }},
		{"cut (onOversize Allow, a proxy's small buffer)", nil, nil, func() *request.Request {
			r := chat(1)
			r.Body, r.BodyTruncated = r.Body[:20], true
			r.Headers.Set("Content-Length", "3000")
			return r
		}},
		{"encoded, llm-malformed excluded", func(c *LLMConfig) {
			c.Exclusions = []LLMExclusion{{Path: "/v1/chat/completions", Checks: llm.CheckSet(0).With(llm.CheckMalformed)}}
		}, nil, func() *request.Request {
			r := chat(1)
			r.Headers.Set("Content-Encoding", "gzip")
			return r
		}},
		{"not read (skip.bodyPaths)", nil, []string{"/v1/chat/completions"}, func() *request.Request {
			r := chat(1)
			r.Headers.Set("Content-Length", "3000")
			return r
		}},
	} {
		limits, err := CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat", []RateLimitConfig{limit})
		if err != nil {
			t.Fatal(err)
		}
		// A body not read whole is charged as maxBodyBytes at least: 2,000
		// tokens and the output cap.
		cfg := LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}},
			Checks: llm.Config{MaxOutputTokens: 1000}, Metrics: llm.NewMetrics(), MaxBodyBytes: 6000}
		if tc.llm != nil {
			tc.llm(&cfg)
		}
		routes, err := router.New(nil, tc.routes)
		if err != nil {
			t.Fatal(err)
		}
		p := New(&exchangeEvaluator{}, Config{Mode: ModeBlock, LLM: compileLLM(t, cfg), RateLimits: limits, Routes: routes, Oversize: OversizeAllow})
		// At least 1,000 tokens each (the output cap): at most 5 of 20.
		allowed := 0
		for range 20 {
			if v := p.Check(ctx, tc.req()); v.Action == ActionAllow || v.Action == ActionLog {
				allowed++
			} else if v.Reason != ReasonRateLimit {
				t.Fatalf("%s: denied for %s", tc.name, v.Reason)
			}
		}
		if allowed == 0 || allowed > 5 {
			t.Errorf("%s: %d of 20 allowed, want 1 to 5", tc.name, allowed)
		}
	}
}

// TestTokenFallbackUnread: a body not read whole, without a
// Content-Length or with a smaller one, is charged as maxBodyBytes: what
// was read doesn't tell its size.
func TestTokenFallbackUnread(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name          string
		contentLength string
		want          int64 // the tokens charged
	}{
		{"no Content-Length", "", 1<<20/3 + 1 + 1000},
		{"a smaller Content-Length", "10", 1<<20/3 + 1 + 1000},
		{"a larger Content-Length", "3000000", 1000000 + 1000},
	} {
		// The burst is the charge: one fits, a second doesn't.
		limit := RateLimitConfig{Name: "tokens", Requests: tc.want, Period: time.Hour, Tokens: true}
		limits, err := CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat", []RateLimitConfig{limit})
		if err != nil {
			t.Fatal(err)
		}
		routes, err := router.New(nil, []string{"/v1/chat/completions"})
		if err != nil {
			t.Fatal(err)
		}
		l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}},
			Checks: llm.Config{MaxOutputTokens: 1000}, Metrics: llm.NewMetrics()})
		p := New(&exchangeEvaluator{}, Config{Mode: ModeBlock, LLM: l, RateLimits: limits, Routes: routes})
		req := func() *request.Request {
			r := chat(1)
			r.Headers.Del("Content-Length")
			if tc.contentLength != "" {
				r.Headers.Set("Content-Length", tc.contentLength)
			}
			return r
		}
		if v := p.Check(ctx, req()); v.Action != ActionAllow {
			t.Errorf("%s: the first refused: %s", tc.name, v.Reason)
		}
		if v := p.Check(ctx, req()); v.Reason != ReasonRateLimit {
			t.Errorf("%s: a second allowed (charged less than %d)", tc.name, tc.want)
		}
		// One token short of the charge: never fits.
		limit.Requests--
		limits, _ = CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat", []RateLimitConfig{limit})
		p = New(&exchangeEvaluator{}, Config{Mode: ModeBlock, LLM: l, RateLimits: limits, Routes: routes})
		if v := p.Check(ctx, req()); v.Reason != ReasonRateLimit {
			t.Errorf("%s: charged less than %d", tc.name, tc.want)
		}
	}
}

// TestTokenChoices: OpenAI Chat's n multiplies the output charged.
func TestTokenChoices(t *testing.T) {
	ctx := context.Background()
	p, _ := tokenPipeline(t, ModeBlock, RateLimitConfig{Name: "tokens", Requests: 5000, Period: time.Minute, Tokens: true})
	body := `{"model":"m","messages":[{"role":"user","content":"abc"}],"max_tokens":400,"n":4,"stream":true}` // 1,601
	allowed := 0
	for range 10 {
		if v := p.Check(ctx, llmRequest("/v1/chat/completions", body)); v.Action == ActionAllow {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("%d of 10 allowed, want 3 (1,601 tokens each of 5,000)", allowed)
	}
}

// images is a chat request of n images by URL and an output of 1: its
// prompt has no text, so its estimate is the images' floors and the
// output.
func images(n int, stream bool) *request.Request {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `{"type":"image_url","image_url":{"url":"https://example.com/a.png","detail":"high"}}`
	}
	s := ""
	if stream {
		s = `,"stream":true`
	}
	return llmRequest("/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[`+strings.Join(parts, ",")+`]}],"max_tokens":1`+s+`}`)
}

// TestTokenNonText: a part that isn't text is charged its floor, so
// images by URL, whose bytes are few, aren't free, whatever their answer
// (a stream, an encoding the engine doesn't decode).
func TestTokenNonText(t *testing.T) {
	ctx := context.Background()
	for _, resp := range []*request.Response{
		{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}, Body: []byte("data: {}\n\n")},
		{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"br"}}, Body: []byte("\x1b\x00garbage")},
	} {
		// 10,000 tokens a minute: 6 images (9,601) fit once.
		p, _ := tokenPipeline(t, ModeBlock, RateLimitConfig{Name: "tokens", Requests: 10000, Period: time.Minute, Tokens: true})
		allowed := 0
		for range 10 {
			v, x := p.CheckExchange(ctx, images(6, resp.Headers.Get("Content-Encoding") == ""))
			if v.Action != ActionAllow {
				continue
			}
			allowed++
			x.CheckResponse(ctx, resp)
			x.Close()
		}
		if allowed != 1 {
			t.Errorf("%s: %d of 10 requests of 6 images allowed, want 1", resp.Headers.Get("Content-Type"), allowed)
		}
		// 200 images (320,000 tokens) never fit.
		if v := p.Check(ctx, images(200, false)); v.Reason != ReasonRateLimit {
			t.Errorf("200 images: %s", v.Reason)
		}
	}
}

// TestTokenReferences: a request that references state the server keeps
// is charged each limit's whole burst, which its response's usage settles.
func TestTokenReferences(t *testing.T) {
	ctx := context.Background()
	limits, err := CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat",
		[]RateLimitConfig{{Name: "tokens", Requests: 10000, Period: time.Hour, Tokens: true}})
	if err != nil {
		t.Fatal(err)
	}
	l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/responses"}, Format: llm.OpenAIResponses}},
		Checks: llm.Config{MaxOutputTokens: 1000}, Metrics: llm.NewMetrics()})
	p := New(&exchangeEvaluator{}, Config{Mode: ModeBlock, LLM: l, RateLimits: limits, Responses: ResponseConfig{Inspect: true, MaxBytes: 64 << 10}})
	ref := func() *request.Request {
		return llmRequest("/v1/responses", `{"model":"m","input":"hi","previous_response_id":"resp_1","max_output_tokens":10}`)
	}
	plain := func() *request.Request {
		return llmRequest("/v1/responses", `{"model":"m","input":"hi","max_output_tokens":10}`)
	}
	v, x := p.CheckExchange(ctx, ref())
	if v.Action != ActionAllow {
		t.Fatalf("a reference on a full bucket: %s", v.Reason)
	}
	if v := p.Check(ctx, plain()); v.Reason != ReasonRateLimit {
		t.Errorf("after a reference took the burst: %s", v.Reason)
	}
	// It used 2,000: 8,000 back.
	x.CheckResponse(ctx, &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}},
		Body: []byte(`{"output":[],"usage":{"input_tokens":1990,"output_tokens":10}}`)})
	x.Close()
	if v := p.Check(ctx, plain()); v.Action != ActionAllow {
		t.Errorf("after the settlement: %s", v.Reason)
	}
	// Another reference doesn't fit until the bucket is full again.
	if v := p.Check(ctx, ref()); v.Reason != ReasonRateLimit {
		t.Errorf("a reference on a bucket not full: %s", v.Reason)
	}
}

// sse is a streamed response of events.
func sse(events ...string) *request.Response {
	var b strings.Builder
	for _, ev := range events {
		b.WriteString("data: " + ev + "\n\n")
	}
	return &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}, Body: []byte(b.String())}
}

// TestTokenStreamSettlement: a streamed response's usage events settle the
// estimate through the exchange's UsageMeter, written the stream in any
// chunks; a stream cut before its final usage only adds debt.
func TestTokenStreamSettlement(t *testing.T) {
	ctx := context.Background()
	stream := func(p *Pipeline, r *request.Request, resp *request.Response, chunk int) {
		t.Helper()
		v, x := p.CheckExchange(ctx, r)
		if v.Action != ActionAllow {
			t.Fatalf("refused: %s", v.Reason)
		}
		x.CheckResponse(ctx, resp)
		x.Close()
		m := x.UsageMeter(resp.Headers)
		if m == nil {
			t.Fatal("no usage meter")
		}
		if x.UsageMeter(resp.Headers) != nil {
			t.Error("a second usage meter")
		}
		for b := resp.Body; len(b) > 0; b = b[min(chunk, len(b)):] {
			m.Write(b[:min(chunk, len(b))])
		}
		m.Close()
		m.Close()
	}
	final := sse(`{"choices":[{"delta":{"content":"hi"}}],"usage":null}`, `{"choices":[],"usage":{"prompt_tokens":2999,"completion_tokens":1}}`, `[DONE]`)
	// Debt: 11 charged, 3,000 used.
	p, _ := tokenPipeline(t, ModeBlock, tokensPerMinute)
	stream(p, chat(10), final, 7)
	if v := p.Check(ctx, chat(1)); v.Status != 429 || v.RetryAfter < 2*time.Minute {
		t.Errorf("after a stream used 3,000: %d, Retry-After %v", v.Status, v.RetryAfter)
	}
	// A refund: 901 charged, 50 used.
	p, _ = tokenPipeline(t, ModeBlock, tokensPerMinute)
	stream(p, chat(900), sse(`{"choices":[],"usage":{"prompt_tokens":40,"completion_tokens":10}}`), 1)
	if v := p.Check(ctx, chat(900)); v.Action != ActionAllow {
		t.Errorf("after a stream's refund: %s", v.Reason)
	}
	// Cut before the final usage: Anthropic's start says 5,000 input,
	// more than the estimate: debt; a start of less is no refund.
	l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/messages"}, Format: llm.AnthropicMessages}},
		Checks: llm.Config{MaxOutputTokens: 1000}, Metrics: llm.NewMetrics()})
	anthropic := func(start int) (*Pipeline, *request.Request, *request.Response) {
		limits, _ := CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "ai/chat", []RateLimitConfig{tokensPerMinute})
		p := New(&exchangeEvaluator{}, Config{Mode: ModeBlock, LLM: l, RateLimits: limits, Responses: ResponseConfig{Inspect: true, MaxBytes: 64 << 10}})
		return p, llmRequest("/v1/messages", `{"model":"m","max_tokens":900,"stream":true,"messages":[{"role":"user","content":"abc"}]}`),
			sse(fmt.Sprintf(`{"type":"message_start","message":{"usage":{"input_tokens":%d,"output_tokens":1}}}`, start))
	}
	p, r, resp := anthropic(5000)
	stream(p, r, resp, 64)
	if v := p.Check(ctx, chat(1)); v.Status != 429 || v.RetryAfter < 4*time.Minute {
		t.Errorf("a cut stream that used 5,000: %d, Retry-After %v", v.Status, v.RetryAfter)
	}
	p, r, resp = anthropic(10)
	stream(p, r, resp, 64)
	if v := p.Check(ctx, llmRequest("/v1/messages", `{"model":"m","max_tokens":900,"messages":[{"role":"user","content":"abc"}]}`)); v.Reason != ReasonRateLimit {
		t.Errorf("a cut stream refunded: %s", v.Reason)
	}
	// No meter: an encoded stream, a response that isn't one, a request
	// no token limit charged.
	p, _ = tokenPipeline(t, ModeBlock, tokensPerMinute)
	_, x := p.CheckExchange(ctx, chat(1))
	for _, h := range []http.Header{
		{"Content-Type": {"text/event-stream"}, "Content-Encoding": {"gzip"}},
		{"Content-Type": {"application/json"}},
	} {
		if x.UsageMeter(h) != nil {
			t.Errorf("a usage meter for %v", h)
		}
	}
	x.Close()
	p, _ = tokenPipeline(t, ModeBlock)
	if _, x := p.CheckExchange(ctx, chat(1)); x != nil && x.UsageMeter(final.Headers) != nil {
		t.Error("a usage meter without token limits")
	}
	var nilMeter *UsageMeter
	nilMeter.Write([]byte("x"))
	nilMeter.Close()
}

// TestTokenConcurrentDebt: requests in flight before the first settles are
// charged their estimates only; once their responses settle, the real
// cost is owed in full up to the debt horizon (an hour of the rate, more
// than two bursts here).
func TestTokenConcurrentDebt(t *testing.T) {
	ctx := context.Background()
	p, _ := tokenPipeline(t, ModeBlock, tokensPerMinute)
	var xs []*Exchange
	for range 50 {
		v, x := p.CheckExchange(ctx, chat(1))
		if v.Action != ActionAllow {
			t.Fatalf("an estimate of 2 refused: %s", v.Reason)
		}
		xs = append(xs, x)
	}
	for _, x := range xs {
		x.CheckResponse(ctx, usage(150000))
		x.Close()
	}
	v := p.Check(ctx, chat(1))
	if v.Status != 429 || v.RetryAfter < ratelimit.MaxDebt-2*time.Minute || v.RetryAfter > ratelimit.MaxDebt {
		t.Errorf("7.5M tokens used at 1,000 a minute: %d, Retry-After %v, want about %v", v.Status, v.RetryAfter, ratelimit.MaxDebt)
	}
}

// TestAuthorizationKey: an Authorization header counts as servers read it:
// one key whatever the scheme's case and the spacing.
func TestAuthorizationKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Bearer sk-ABC", "bearer sk-ABC"},
		{"bearer sk-ABC", "bearer sk-ABC"},
		{"BEARER   sk-ABC", "bearer sk-ABC"},
		{" Bearer\tsk-ABC ", "bearer sk-ABC"},
		{"sk-ABC", "sk-ABC"},
		{"  sk-ABC ", "sk-ABC"},
		{"Digest a=1,  b=2", "digest a=1, b=2"},
	} {
		if got := authorizationKey(tc.in); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.in, got, tc.want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { authorizationKey("bearer sk-ABC") }); n != 0 {
		t.Errorf("%v allocations for a value written so already", n)
	}
	ctx := context.Background()
	p, _ := tokenPipeline(t, ModeBlock, RateLimitConfig{Name: "tokens", Requests: 1000, Period: time.Minute, Tokens: true, Header: "Authorization"})
	for i, auth := range []string{"Bearer sk-1", "bearer sk-1", "BEARER  sk-1"} {
		r := chat(400)
		r.Headers.Set("Authorization", auth)
		if v := p.Check(ctx, r); (v.Action == ActionAllow) != (i < 2) {
			t.Errorf("%q, request %d: %s %s", auth, i, v.Action, v.Reason)
		}
	}
}
