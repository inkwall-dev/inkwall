// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

func compileLLM(t testing.TB, cfg LLMConfig) *LLM {
	t.Helper()
	l, err := CompileLLM(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// chatEndpoints are a chat endpoint and an Anthropic one, with a cap on
// the output limit, client roles and a model.
func chatEndpoints(t testing.TB, mod func(*LLMConfig)) *LLM {
	cfg := LLMConfig{
		Endpoints: []LLMEndpoint{
			{Paths: []string{"/v1/chat/completions", "/openai/*"}, Format: llm.OpenAIChat},
			{Paths: []string{"/v1/messages"}, Format: llm.AnthropicMessages},
		},
		RulesReadBodies: true,
		Checks: llm.Config{Models: []string{"llama-*"}, MaxOutputTokens: 1000, ClientRoles: []llm.Role{llm.RoleUser, llm.RoleAssistant},
			MaxPromptBytes: 64},
	}
	if mod != nil {
		mod(&cfg)
	}
	return compileLLM(t, cfg)
}

func llmRequest(uri, body string) *request.Request {
	return &request.Request{Method: http.MethodPost, RawURI: uri, Proto: "HTTP/1.1", Headers: http.Header{"Content-Type": {"application/json"}},
		ClientIP: netip.MustParseAddr("192.0.2.1"), Body: []byte(body)}
}

const (
	goodChat = `{"model":"llama-3","messages":[{"role":"user","content":"hello ' OR 1=1 --"}],"max_tokens":100}`
	bigChat  = `{"model":"llama-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5000}`
)

func TestLLMChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   Mode
		mod    func(*LLMConfig)
		req    *request.Request
		action Action
		status int
		check  llm.Check
	}{
		{"clean", ModeBlock, nil, llmRequest("/v1/chat/completions", goodChat), ActionAllow, 0, llm.CheckNone},
		{"over the output cap", ModeBlock, nil, llmRequest("/v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"over, logged in detect mode", ModeDetect, nil, llmRequest("/v1/chat/completions", bigChat), ActionLog, 0, llm.CheckMaxOutputTokens},
		{"over, logged with request.mode Detect", ModeBlock, func(c *LLMConfig) { c.Detect = true }, llmRequest("/v1/chat/completions", bigChat), ActionLog, 0, llm.CheckMaxOutputTokens},
		{"prompt over: 413", ModeBlock, nil, llmRequest("/v1/chat/completions", `{"model":"llama-3","messages":[{"role":"user","content":"0123456789012345678901234567890123456789012345678901234567890123456789"}]}`), ActionDeny, 413, llm.CheckMaxPrompt},
		{"a system message refused", ModeBlock, nil, llmRequest("/v1/chat/completions", `{"model":"llama-3","messages":[{"role":"system","content":"x"}]}`), ActionDeny, 400, llm.CheckClientRole},
		{"malformed", ModeBlock, nil, llmRequest("/v1/chat/completions", `{"model":"llama-3","model":"gpt"}`), ActionDeny, 400, llm.CheckMalformed},
		{"empty body", ModeBlock, nil, llmRequest("/v1/chat/completions", ``), ActionDeny, 400, llm.CheckMalformed},
		{"a prefix endpoint", ModeBlock, nil, llmRequest("/openai/deployments/x/chat/completions?api-version=1", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"a trailing slash", ModeBlock, nil, llmRequest("/v1/chat/completions/", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"case-insensitive", ModeBlock, nil, llmRequest("/V1/Chat/Completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"anthropic", ModeBlock, nil, llmRequest("/v1/messages", `{"model":"llama-3","system":"s","messages":[]}`), ActionDeny, 400, llm.CheckClientRole},
		{"not an endpoint", ModeBlock, nil, llmRequest("/v1/models", bigChat), ActionAllow, 0, llm.CheckNone},
		{"a GET without a body", ModeBlock, nil, &request.Request{Method: "GET", RawURI: "/v1/chat/completions", Headers: http.Header{}}, ActionAllow, 0, llm.CheckNone},
		{"a GET with a body", ModeBlock, nil, &request.Request{Method: "GET", RawURI: "/v1/chat/completions", Headers: http.Header{}, Body: []byte(bigChat)}, ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"an encoded body", ModeBlock, nil, func() *request.Request {
			r := llmRequest("/v1/chat/completions", goodChat)
			r.Headers.Set("Content-Encoding", "gzip")
			return r
		}(), ActionDeny, 400, llm.CheckMalformed},
		{"identity encoding", ModeBlock, nil, func() *request.Request {
			r := llmRequest("/v1/chat/completions", goodChat)
			r.Headers.Set("Content-Encoding", "identity")
			return r
		}(), ActionAllow, 0, llm.CheckNone},
		// Paths the application may read another way are checked as every
		// format of the policy: this chat body is a valid Anthropic one,
		// and refused as chat.
		{"an ambiguous path", ModeBlock, nil, llmRequest("/v1/chat%2fcompletions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"a dot segment", ModeBlock, nil, llmRequest("/v1/x/../chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"a double slash", ModeBlock, nil, llmRequest("//v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		// An exact path wins over a prefix.
		{"exact over prefix", ModeBlock, func(c *LLMConfig) {
			c.Endpoints = []LLMEndpoint{{Paths: []string{"/v1/*"}, Format: llm.OpenAIEmbeddings}, {Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"the longest prefix", ModeBlock, func(c *LLMConfig) {
			c.Endpoints = []LLMEndpoint{{Paths: []string{"/v1/*"}, Format: llm.OpenAIEmbeddings}, {Paths: []string{"/v1/chat/*"}, Format: llm.OpenAIChat}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		// A format this engine doesn't know: checked as every one it does.
		{"an unknown format", ModeBlock, func(c *LLMConfig) {
			c.Endpoints = []LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.Format(99)}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		// Exclusions by the checks' rule IDs.
		{"excluded on its path", ModeBlock, func(c *LLMConfig) {
			c.Exclusions = []LLMExclusion{{Path: "/v1/chat/*", Checks: llm.CheckSet(0).With(llm.CheckMaxOutputTokens)}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionAllow, 0, llm.CheckNone},
		{"excluded on another path", ModeBlock, func(c *LLMConfig) {
			c.Exclusions = []LLMExclusion{{Path: "/v2/*", Checks: llm.CheckSet(0).With(llm.CheckMaxOutputTokens)}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
		{"excluded everywhere", ModeBlock, func(c *LLMConfig) {
			c.Exclusions = []LLMExclusion{{Checks: llm.CheckSet(0).With(llm.CheckMaxOutputTokens)}}
		}, llmRequest("/v1/chat/completions", bigChat), ActionAllow, 0, llm.CheckNone},
		{"an ambiguous path gets no path exclusion", ModeBlock, func(c *LLMConfig) {
			c.Exclusions = []LLMExclusion{{Path: "/v1/chat/*", Checks: llm.CheckSet(0).With(llm.CheckMaxOutputTokens)}}
		}, llmRequest("/v1/chat/x/../completions", bigChat), ActionDeny, 400, llm.CheckMaxOutputTokens},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eval := &recordingEvaluator{}
			p := New(eval, Config{Mode: tc.mode, LLM: chatEndpoints(t, tc.mod)})
			v := p.Check(context.Background(), tc.req)
			if v.Action != tc.action || v.Status != tc.status {
				t.Fatalf("%s %d (%s), want %s %d", v.Action, v.Status, v.Reason, tc.action, tc.status)
			}
			if tc.check == llm.CheckNone {
				if v.Reason != ReasonNone || v.LLM != nil {
					t.Errorf("reason %s, %+v", v.Reason, v.LLM)
				}
				return
			}
			if v.Reason != ReasonLLM || v.LLM == nil || v.LLM.Check != tc.check {
				t.Fatalf("reason %s, %+v", v.Reason, v.LLM)
			}
			id := tc.check.RuleID()
			if len(v.Matches) != 1 || v.Matches[0].RuleID != id || v.Matches[0].Value != "" || len(v.RuleIDs) != 1 || v.RuleIDs[0] != id {
				t.Errorf("matches %+v, rule IDs %v", v.Matches, v.RuleIDs)
			}
			if tc.action == ActionDeny && v.InterruptingRuleID != id {
				t.Errorf("interrupting rule %d", v.InterruptingRuleID)
			}
			// Denied: the rules never ran. Logged: they did.
			if (eval.got != nil) != (tc.action != ActionDeny) {
				t.Errorf("rules ran: %v", eval.got != nil)
			}
		})
	}
}

// TestLLMRuleSetBody: the rules get an endpoint's body only with
// ruleSetBody: Inspect, and the policy inspecting bodies.
func TestLLMRuleSetBody(t *testing.T) {
	for _, tc := range []struct {
		inspect, bodies, wantBody bool
	}{{false, true, false}, {true, true, true}, {true, false, false}} {
		eval := &recordingEvaluator{}
		p := New(eval, Config{Mode: ModeBlock, LLM: chatEndpoints(t, func(c *LLMConfig) { c.RuleSetBody, c.RulesReadBodies = tc.inspect, tc.bodies })})
		v := p.Check(context.Background(), llmRequest("/v1/chat/completions", goodChat))
		if v.Action != ActionAllow || eval.got == nil || (eval.got.Body != nil) != tc.wantBody {
			t.Errorf("ruleSetBody %v, bodies %v: %s, rules got body %v", tc.inspect, tc.bodies, v.Action, eval.got != nil && eval.got.Body != nil)
		}
		// Other paths keep their bodies.
		eval.got = nil
		p.Check(context.Background(), llmRequest("/v1/other", goodChat))
		if eval.got == nil || eval.got.Body == nil {
			t.Errorf("another path lost its body")
		}
	}
}

// TestLLMOrder: IP lists, skipped paths and rate limits come first; a
// skip.bodyPaths body isn't read, so isn't checked; a body over the limit
// is oversized, not malformed; the rules' reason wins over a logged check.
func TestLLMOrder(t *testing.T) {
	table, err := router.New([]string{"/v1/skipped"}, []string{"/v1/chat/completions"})
	if err != nil {
		t.Fatal(err)
	}
	l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/*"}, Format: llm.OpenAIChat}}, Checks: llm.Config{MaxOutputTokens: 10}})
	p := New(&recordingEvaluator{}, Config{Mode: ModeBlock, Routes: table, LLM: l, Oversize: OversizeDeny})
	if v := p.Check(context.Background(), llmRequest("/v1/skipped", bigChat)); v.Reason != ReasonSkipped {
		t.Errorf("skipped path: %s", v.Reason)
	}
	r := llmRequest("/v1/chat/completions", bigChat)
	r.Body = nil // the adapter read no body: BodyLimit was 0
	if v := p.Check(context.Background(), r); v.Action != ActionAllow {
		t.Errorf("skip.bodyPaths: %s %s", v.Action, v.Reason)
	}
	cut := llmRequest("/v1/x", bigChat[:20])
	cut.BodyTruncated = true
	if v := p.Check(context.Background(), cut); v.Reason != ReasonOversize || v.Status != 413 {
		t.Errorf("over the body limit: %s %d", v.Reason, v.Status)
	}

	// Detect: a rule's reason wins, and the check is still counted.
	m := llm.NewMetrics()
	l = compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/*"}, Format: llm.OpenAIChat}}, Checks: llm.Config{MaxOutputTokens: 10}, Metrics: m})
	p = New(&recordingEvaluator{res: blocked}, Config{Mode: ModeDetect, LLM: l})
	if v := p.Check(context.Background(), llmRequest("/v1/x", bigChat)); v.Reason != ReasonRule || v.Action != ActionLog || v.LLM != nil {
		t.Errorf("rule and check in detect mode: %s %s", v.Action, v.Reason)
	}

	// Rate limits first: a request over one isn't parsed.
	store := ratelimit.New(1024, 0)
	limits, err := CompileRateLimits(store, ratelimit.NewLive(), "p", []RateLimitConfig{{Name: "one", Requests: 1, Period: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	p = New(&recordingEvaluator{}, Config{Mode: ModeBlock, LLM: l, RateLimits: limits})
	p.Check(context.Background(), llmRequest("/v1/x", goodChat))
	if v := p.Check(context.Background(), llmRequest("/v1/x", bigChat)); v.Reason != ReasonRateLimit {
		t.Errorf("over a rate limit: %s", v.Reason)
	}
}

// TestLLMBodyLimit: an endpoint reads maxBodyBytes, also when the
// policy's rules read no body; other paths don't.
func TestLLMBodyLimit(t *testing.T) {
	l := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}}, MaxBodyBytes: 4 << 20})
	p := New(&recordingEvaluator{}, Config{Mode: ModeBlock, LLM: l})
	for _, tc := range []struct {
		r    *request.Request
		want int64
	}{
		{&request.Request{Method: "POST", RawURI: "/v1/chat/completions"}, 4 << 20},
		{&request.Request{Method: "GET", RawURI: "/v1/chat/completions"}, 4 << 20},
		{&request.Request{Method: "POST", RawURI: "/v1/chat%2fcompletions"}, 4 << 20},
		{&request.Request{Method: "POST", RawURI: "/v1/models"}, 0},
	} {
		if got := p.LLMBodyLimit(tc.r); got != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.r.Method, tc.r.RawURI, got, tc.want)
		}
	}
	if n := compileLLM(t, LLMConfig{Endpoints: []LLMEndpoint{{Paths: []string{"/a"}}}}).maxBody; n != DefaultLLMBodyBytes {
		t.Errorf("default %d", n)
	}
}

// TestLLMResponses: with ruleSetBody: Skip, an endpoint's response is
// inspected without its body, and its streams aren't split into events
// for the rules; with Inspect, as any response.
func TestLLMResponses(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		eval := &exchangeEvaluator{}
		l := chatEndpoints(t, func(c *LLMConfig) { c.RuleSetBody = inspect })
		p := New(eval, Config{Mode: ModeBlock, LLM: l, Responses: ResponseConfig{Inspect: true, MaxBytes: 1 << 20, Streams: true}})
		v, x := p.CheckExchange(context.Background(), llmRequest("/v1/chat/completions", goodChat))
		if v.Action != ActionAllow || x == nil {
			t.Fatalf("%s, exchange %v", v.Action, x != nil)
		}
		if got := x.BodyLimit() > 0; got != inspect {
			t.Errorf("inspect %v: body limit %d", inspect, x.BodyLimit())
		}
		if x.Streams() != inspect {
			t.Errorf("inspect %v: streams %v", inspect, x.Streams())
		}
		resp := &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"choices":[{"message":{"content":"LEAK"}}]}`)}
		v = x.CheckResponse(context.Background(), resp)
		x.Close()
		if want := map[bool]Action{false: ActionAllow, true: ActionDeny}[inspect]; v.Action != want {
			t.Errorf("inspect %v: response %s, want %s", inspect, v.Action, want)
		}
		if len(eval.got) != 1 || (eval.got[0].Body != nil) != inspect {
			t.Errorf("inspect %v: the rules got %d responses", inspect, len(eval.got))
		}
	}
}

func TestCompileLLM(t *testing.T) {
	for _, cfg := range []LLMConfig{
		{},
		{Endpoints: make([]LLMEndpoint, MaxLLMEndpoints+1)},
		{Endpoints: []LLMEndpoint{{Format: llm.OpenAIChat}}},
		{Endpoints: []LLMEndpoint{{Paths: []string{"v1"}}}},
		{Endpoints: []LLMEndpoint{{Paths: []string{"/a*b"}}}},
		{Endpoints: []LLMEndpoint{{Paths: []string{"/a"}}, {Paths: []string{"/A/"}}}},
		{Endpoints: []LLMEndpoint{{Paths: []string{"/a"}}}, Checks: llm.Config{Tools: llm.ToolsListed}},
	} {
		if _, err := CompileLLM(&cfg); err == nil {
			t.Errorf("%+v compiles", cfg)
		}
	}
	if l, err := CompileLLM(nil); l != nil || err != nil {
		t.Errorf("nil: %v, %v", l, err)
	}
}

// TestLLMAllocations: checking a request on an endpoint allocates no more
// than the request without its body (the copy the rules get).
func TestLLMAllocations(t *testing.T) {
	p := New(fakeEvaluator{}, Config{Mode: ModeBlock, LLM: chatEndpoints(t, nil)})
	r := llmRequest("/v1/chat/completions", goodChat)
	base := testing.AllocsPerRun(100, func() { p.Check(context.Background(), llmRequest("/v1/other", goodChat)) })
	got := testing.AllocsPerRun(100, func() { p.Check(context.Background(), r) })
	if got > base+1 {
		t.Errorf("%v allocations on an endpoint, %v elsewhere", got, base)
	}
}
