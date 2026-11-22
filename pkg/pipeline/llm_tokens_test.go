// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
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
