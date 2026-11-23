// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ChatBody returns a chat request of about size bytes: a system prompt and
// a history of user and assistant turns mixing prose, code, escapes and
// non-ASCII text, as a chat front end sends it.
func ChatBody(size int) []byte {
	turns := []string{
		"Can you explain how the token bucket in this rate limiter works? I keep getting 429s after a burst.",
		"Sure. Each key has a bucket holding at most `burst` tokens; a request takes one, and tokens come back at `requests / period`.\n\n```go\nfunc (b *bucket) take(now time.Time) bool {\n\tif b.tat.Before(now) {\n\t\tb.tat = now\n\t}\n\treturn true\n}\n```\n",
		"Merci ! Et pour les clés IPv6, pourquoi un /56 ? — « parce qu'un abonné en a au moins un »",
		"日本語でも説明してください。レート制限はエンジンごとに数えますか？",
		`Here's the JSON I send: {"model": "x", "messages": [{"role": "user"}]} and the "quoted" part \ with a backslash.`,
	}
	msgs := []map[string]any{{"role": "system", "content": "You are a helpful assistant for the Inkwall project. Answer briefly and cite the docs."}}
	for i := 0; ; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		msgs = append(msgs, map[string]any{"role": role, "content": turns[i%len(turns)]})
		b, _ := json.Marshal(map[string]any{"model": "llama-3.1-8b-instruct", "messages": msgs, "max_tokens": 1024, "temperature": 0.7, "stream": true,
			"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "search_docs", "parameters": map[string]any{"type": "object"}}}}})
		if len(b) >= size {
			return b
		}
	}
}

// checkAll is a config with every request check on.
var checkAll = Config{Models: []string{"llama-3.1-*", "qwen2.5-*"}, MaxPromptBytes: 2 << 20, MaxMessages: 100000, MaxOutputTokens: 4096,
	RequireOutputTokens: true, MaxChoices: 1, ClientRoles: []Role{RoleSystem, RoleUser, RoleAssistant},
	Tools: ToolsListed, ToolNames: []string{"search_docs", "get_weather"}}

// BenchmarkCheck: parsing a chat body and running every request check
// (design 0012 §7.2: ≤ 30 µs for 8 KiB, ≤ 2 ms for 1 MiB, no allocation).
func BenchmarkCheck(b *testing.B) {
	rules, err := Compile(checkAll)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{8 << 10, 32 << 10, 1 << 20} {
		body := ChatBody(size)
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			var req Request
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				Parse(body, OpenAIChat, &req)
				if f := rules.Check(body, &req, 0); f.Check != CheckNone {
					b.Fatalf("%s", f.Check)
				}
			}
		})
	}
}

// BenchmarkParseEncodingJSON is encoding/json reading the same 32 KiB
// body into a map, for scale.
func BenchmarkParseEncodingJSON(b *testing.B) {
	body := ChatBody(32 << 10)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			b.Fatal(err)
		}
	}
}

func TestChatBody(t *testing.T) {
	body := ChatBody(32 << 10)
	var req Request
	if !Parse(body, OpenAIChat, &req) {
		t.Fatal(req.Why)
	}
	if len(body) < 32<<10 || len(body) > 34<<10 || req.Messages < 50 || !strings.Contains(string(body), `<`) && !strings.Contains(string(body), "日本語") {
		t.Errorf("%d bytes, %d messages", len(body), req.Messages)
	}
	rules, _ := Compile(checkAll)
	if f := rules.Check(body, &req, 0); f.Check != CheckNone {
		t.Errorf("%s", f.Check)
	}
}
