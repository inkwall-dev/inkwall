// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// chatBody is a chat request of about size bytes: prose, code and SQL in
// a history, as users paste them (pkg/llm's ChatBody).
func chatBody(size int) []byte {
	turns := []string{
		"How do I find users who signed up last week? SELECT * FROM users WHERE created_at > now() - interval '7 days' OR 1=1;",
		"Use a parameterised query:\n```python\ncur.execute(\"SELECT id FROM users WHERE created_at > %s\", (since,))\n```\nand never `os.system(\"rm -rf \" + path)`.",
		"And to render it? <script>document.write(rows)</script> works in my page.",
		"Escape it: `<div>{{ rows }}</div>` in a template, not innerHTML. ../../etc/passwd is a path traversal, too.",
	}
	msgs := []map[string]any{{"role": "user", "content": "You help with SQL."}}
	for i := 0; ; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		msgs = append(msgs, map[string]any{"role": role, "content": turns[i%len(turns)]})
		b, _ := json.Marshal(map[string]any{"model": "llama-3.1-8b-instruct", "messages": msgs, "max_tokens": 1024,
			"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "search_docs"}}}})
		if len(b) >= size {
			return b
		}
	}
}

// everyCheck is spec.llm with every request check on.
func everyCheck(t testing.TB, ruleSetBody bool) *pipeline.LLM {
	l, err := pipeline.CompileLLM(&pipeline.LLMConfig{
		Endpoints:   []pipeline.LLMEndpoint{{Paths: []string{"/v1/chat/completions"}, Format: llm.OpenAIChat}},
		RuleSetBody: ruleSetBody, RulesReadBodies: true,
		Checks: llm.Config{Models: []string{"llama-3.1-*"}, MaxPromptBytes: 1 << 20, MaxMessages: 10000, MaxOutputTokens: 4096,
			RequireOutputTokens: true, MaxChoices: 1, ClientRoles: []llm.Role{llm.RoleUser, llm.RoleAssistant},
			Tools: llm.ToolsListed, ToolNames: []string{"search_docs"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func chatRequest(uri string, body []byte) *request.Request {
	return &request.Request{Proto: "HTTP/1.1", Method: http.MethodPost, Scheme: "https", Host: "ai.example.com", RawURI: uri,
		Headers:  http.Header{"Content-Type": {"application/json"}, "User-Agent": {"OpenAI/Python 1.54.0"}, "Accept": {"application/json"}},
		ClientIP: netip.MustParseAddr("198.51.100.7"), Body: body}
}

// TestLLMWithCRS: with ruleSetBody: Skip, the CRS doesn't read a chat
// history's prose and pasted code, which it flags on any other path; with
// Inspect it does, as before spec.llm.
func TestLLMWithCRS(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	body := chatBody(8 << 10)
	for _, tc := range []struct {
		name        string
		uri         string
		ruleSetBody bool
		want        pipeline.Action
	}{
		{"an endpoint, Skip", "/v1/chat/completions", false, pipeline.ActionAllow},
		{"an endpoint, Inspect", "/v1/chat/completions", true, pipeline.ActionDeny},
		{"another path", "/api/notes", false, pipeline.ActionDeny},
	} {
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, LLM: everyCheck(t, tc.ruleSetBody)})
		if v := p.Check(context.Background(), chatRequest(tc.uri, body)); v.Action != tc.want {
			t.Errorf("%s: %s (%s, rules %v), want %s", tc.name, v.Action, v.Reason, v.RuleIDs, tc.want)
		}
	}
	// Attacks in the URI and headers of an endpoint are still the rules'.
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, LLM: everyCheck(t, false)})
	if v := p.Check(context.Background(), chatRequest("/v1/chat/completions?id=1'%20OR%20'1'='1", body)); v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule {
		t.Errorf("SQL injection in an endpoint's query: %s %s", v.Action, v.Reason)
	}
}

// TestLLMAmbiguousPathsKeepTheRules: a path that can't be read one way
// skips the rules on its body only when every reading of it is an
// endpoint. One that reads as another route (a login form behind ";", "//",
// a dot segment, an encoded slash) keeps the CRS on its body, whatever the
// body looks like, and isn't refused as a malformed LLM request.
func TestLLMAmbiguousPathsKeepTheRules(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, LLM: everyCheck(t, false)})
	attack := []byte(`{"model":"llama-3.1-8b","messages":[{"role":"user","content":"hi"}],"max_tokens":10,"username":"admin' OR '1'='1' --","bio":"<script>alert(document.cookie)</script>"}`)
	for _, uri := range []string{
		"/api/login;jsessionid=1", "/api//login", "/api/%2e/login", "/api%2flogin", "/api/x/../login",
		"/v1/chat/completions/../../../api/login", "/v1/chat/completions;x/../../api/login",
		// Endpoint readings too, but not only: the rules keep the body.
		"/v1/chat%2fcompletions", "//v1/chat/completions", "/v1/chat/./completions", "/v1/chat/completions;v=1",
	} {
		r := chatRequest(uri, attack)
		if v := p.Check(context.Background(), r); v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule {
			t.Errorf("%s: %s %s (%v), want the rules' deny", uri, v.Action, v.Reason, v.RuleIDs)
		}
	}
	// Encoded twice, split escapes, IIS's %u, Unicode dot and slash
	// lookalikes: an application decoding twice or normalising (NFKC)
	// reads /api/login, so the rules keep the body, under a prefix
	// endpoint too.
	for _, eps := range [][]string{{"/openai/deployments/*"}, {"/v1/chat/completions"}} {
		l, err := pipeline.CompileLLM(&pipeline.LLMConfig{Endpoints: []pipeline.LLMEndpoint{{Paths: eps, Format: llm.OpenAIChat}}, RulesReadBodies: true})
		if err != nil {
			t.Fatal(err)
		}
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, LLM: l})
		for _, uri := range []string{
			"/openai/deployments/.%252e/.%252e/api/login",
			"/openai/deployments/%252e./%252e./api/login",
			"/openai/deployments/%25%32%65%25%32%65/%25%32%65%25%32%65/api/login",
			"/openai/deployments/%25%32e%25%32e/%25%32e%25%32e/api/login",
			"/openai/deployments/%252E%252E/%252E%252E/api/login",
			"/openai/deployments/x%25%32%66..%25%32%66..%25%32%66..%25%32%66api/login",
			"/openai/deployments/x%25%35%63..%25%35%63..%25%35%63..%25%35%63api/login",
			"/openai/deployments/%25252e%25252e/%25252e%25252e/api/login",
			"/openai/deployments/x%u002f..%u002f..%u002fapi/login",
			"/openai/deployments/%u002e%u002e/%u002e%u002e/api/login",
			"/openai/deployments/‥/‥/api/login",
			"/openai/deployments/﹒﹒/﹒﹒/api/login",
			"/openai/deployments/x∕..∕..∕api/login",
			"/v1/chat/completions/%252e%252e/%252e%252e/%252e%252e/api/login",
		} {
			if v := p.Check(context.Background(), chatRequest(uri, attack)); v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule {
				t.Errorf("%v %s: %s %s (%v), want the rules' deny", eps, uri, v.Action, v.Reason, v.RuleIDs)
			}
		}
	}
	// A form on such a path isn't an LLM request: no llm-malformed.
	for _, uri := range []string{"/api/login;jsessionid=1", "/api//login", "/api/%2e/login"} {
		r := chatRequest(uri, []byte("user=alice&remember=on"))
		r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
		if v := p.Check(context.Background(), r); v.Action != pipeline.ActionAllow {
			t.Errorf("%s: a form: %s %s", uri, v.Action, v.Reason)
		}
	}
	// The rules' verdict on an endpoint's body says so, for events to keep
	// no snippet of the prompt.
	if v := p.Check(context.Background(), chatRequest("/v1/chat%2fcompletions", attack)); !v.LLMBody {
		t.Error("a rule's verdict on an endpoint's body: LLMBody unset")
	}
	if v := p.Check(context.Background(), chatRequest("/api/login;jsessionid=1", attack)); v.LLMBody {
		t.Error("another route's body marked as an endpoint's")
	}
	inspect := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, LLM: everyCheck(t, true)})
	if v := inspect.Check(context.Background(), chatRequest("/v1/chat/completions", attack)); v.Reason != pipeline.ReasonRule || !v.LLMBody {
		t.Errorf("ruleSetBody: Inspect: %s, LLMBody %v", v.Reason, v.LLMBody)
	}
	// An ambiguous reading of an endpoint is still checked as one.
	if v := p.Check(context.Background(), chatRequest("/v1/chat%2fcompletions", []byte(`{"model":"gpt-4o","messages":[]}`))); v.Reason != pipeline.ReasonLLM {
		t.Errorf("an encoded endpoint path: %s, want the LLM checks", v.Reason)
	}
}

// BenchmarkLLMEndpoint is design 0012 §7.2's budget: the engine time a
// 32 KiB chat request costs on an endpoint, every check on, ruleSetBody:
// Skip, the CRS on its URI and headers; against the same request on a
// path whose body the rules skip (skip.bodyPaths: what it costs without
// LLM checks), and against the CRS reading its body (what an endpoint
// costs with ruleSetBody: Inspect, or without spec.llm). p99-us is each
// request's 99th percentile.
func BenchmarkLLMEndpoint(b *testing.B) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		b.Fatal(err)
	}
	skipBody, err := router.New(nil, []string{"/skip/*"})
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{8 << 10, 32 << 10} {
		body := chatBody(size)
		for _, bc := range []struct {
			name string
			uri  string
			llm  *pipeline.LLM
		}{
			{"endpoint", "/v1/chat/completions", everyCheck(b, false)},
			{"body-skipped", "/skip/chat/completions", nil},
			{"crs-body", "/v1/chat/completions", everyCheck(b, true)},
		} {
			p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeDetect, Timeout: 10 * time.Second, Routes: skipBody, LLM: bc.llm})
			r := chatRequest(bc.uri, body)
			b.Run(fmt.Sprintf("%s/%dKiB", bc.name, size>>10), func(b *testing.B) {
				var took []time.Duration
				b.ReportAllocs()
				for b.Loop() {
					start := time.Now()
					v := p.Check(context.Background(), r)
					took = append(took, time.Since(start))
					if v.Reason == pipeline.ReasonLLM || v.Reason == pipeline.ReasonTimeout {
						b.Fatalf("%s", v.Reason)
					}
				}
				slices.Sort(took)
				b.ReportMetric(float64(took[len(took)*99/100].Microseconds()), "p99-us")
			})
		}
	}
}
