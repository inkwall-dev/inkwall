// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParseUsage(t *testing.T) {
	for _, tc := range []struct {
		format Format
		body   string
		want   Usage
		ok     bool
	}{
		{OpenAIChat, `{"id":"c","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":0}}}`, Usage{12, 3}, true},
		{OpenAIEmbeddings, `{"data":[{"embedding":[0.1,-2e-3]}],"usage":{"prompt_tokens":8,"total_tokens":8}}`, Usage{8, 0}, true},
		{OpenAIResponses, `{"output":[],"usage":{"input_tokens":30,"output_tokens":7,"output_tokens_details":{"reasoning_tokens":4}}}`, Usage{30, 7}, true},
		{AnthropicMessages, `{"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":10,"cache_creation_input_tokens":100,"cache_read_input_tokens":5,"output_tokens":2}}`, Usage{115, 2}, true},
		{AnthropicMessages, `{"usage":{"input_tokens":1,"output_tokens":1e30}}`, Usage{1, math.MaxInt64}, true},
		// The other format's names aren't read.
		{OpenAIChat, `{"usage":{"input_tokens":30,"output_tokens":7}}`, Usage{}, false},
		{OpenAIChat, `{"choices":[]}`, Usage{}, false},
		{OpenAIChat, `{"usage":null}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":"12"}}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":-1}}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":1},"usage":{"prompt_tokens":100000}}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":1,"prompt_tokens":2}}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":1}`, Usage{}, false},
		{OpenAIChat, `<html>Bad Gateway</html>`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":1}} x`, Usage{}, false},
		// A key Go's encoding/json reads as one read, case-insensitively and
		// with Unicode folding, keeping the last: a client in Go would read
		// the other usage.
		{OpenAIChat, `{"usage":{"prompt_tokens":1},"Usage":{"prompt_tokens":100000}}`, Usage{}, false},
		{OpenAIChat, `{"USAGE":{"prompt_tokens":100000}}`, Usage{}, false},
		{OpenAIChat, `{"usage":{"prompt_tokens":1,"PROMPT_TOKENS":100000}}`, Usage{}, false},
		{OpenAIEmbeddings, `{"usage":{"Prompt_Tokens":8}}`, Usage{}, false},
		{OpenAIResponses, "{\"usage\":{\"input_tokens\":1,\"output_to\u212Aens\":9}}", Usage{}, false},
		{AnthropicMessages, `{"usage":{"input_tokens":1,"cache_read_input_tokenſ":9}}`, Usage{}, false},
		{AnthropicMessages, `{"usage":{"input_tokens":1,"Cache_Creation_Input_Tokens":9}}`, Usage{}, false},
		// Another format's key in another case isn't one read: skipped.
		{OpenAIChat, `{"usage":{"prompt_tokens":2,"Input_Tokens":9}}`, Usage{2, 0}, true},
	} {
		got, ok := ParseUsage([]byte(tc.body), tc.format)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s %s: %+v %v, want %+v %v", tc.format, tc.body, got, ok, tc.want, tc.ok)
		}
	}
	if n := (Usage{math.MaxInt64, 1}).Total(); n != math.MaxInt64 {
		t.Errorf("total %d", n)
	}
	body := []byte(`{"usage":{"prompt_tokens":12,"completion_tokens":3}}`)
	if a := testing.AllocsPerRun(100, func() { ParseUsage(body, OpenAIChat) }); a != 0 {
		t.Errorf("%v allocations", a)
	}
}

func FuzzParseUsage(f *testing.F) {
	f.Add([]byte(`{"usage":{"prompt_tokens":12,"completion_tokens":3}}`), uint8(0))
	f.Add([]byte(`{"usage":{"input_tokens":1,"cache_read_input_tokens":2,"output_tokens":3}}`), uint8(3))
	f.Add([]byte(`{"usage":{"prompt_tokens":1},"Usage":{"PROMPT_TOKENS":9}}`), uint8(0))
	f.Fuzz(func(t *testing.T, body []byte, format uint8) {
		fm := Formats[int(format)%len(Formats)]
		u, ok := ParseUsage(body, fm)
		if !ok && u != (Usage{}) || u.Input < 0 || u.Output < 0 {
			t.Fatalf("%+v %v", u, ok)
		}
		if ok {
			goUsageView(t, body, fm, u)
		}
	})
}

// goUsage is a response's usage as a client in Go decodes it into its
// structs: encoding/json matches keys case-insensitively, with Unicode
// folding, and keeps the last.
type goUsage struct {
	Usage *struct {
		PromptTokens        *json.Number `json:"prompt_tokens"`
		CompletionTokens    *json.Number `json:"completion_tokens"`
		InputTokens         *json.Number `json:"input_tokens"`
		OutputTokens        *json.Number `json:"output_tokens"`
		CacheCreationTokens *json.Number `json:"cache_creation_input_tokens"`
		CacheReadTokens     *json.Number `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

// goUsageView compares the usage ParseUsage read of body with what a Go
// client's structs read. It skips bodies such a client refuses.
func goUsageView(t *testing.T, body []byte, f Format, u Usage) {
	var g goUsage
	if err := json.Unmarshal(body, &g); err != nil || g.Usage == nil {
		return
	}
	var want Usage
	add := func(to *int64, n *json.Number) bool {
		if n == nil {
			return true
		}
		v, ok, err := refInt(*n)
		if err != nil { // errSkip, or a type a Go client refuses too
			return false
		}
		if ok {
			*to = min(*to, math.MaxInt64-v) + v
		}
		return true
	}
	gu := g.Usage
	var read bool
	switch f {
	case OpenAIChat:
		read = add(&want.Input, gu.PromptTokens) && add(&want.Output, gu.CompletionTokens)
	case OpenAIEmbeddings:
		read = add(&want.Input, gu.PromptTokens)
	case OpenAIResponses:
		read = add(&want.Input, gu.InputTokens) && add(&want.Output, gu.OutputTokens)
	case AnthropicMessages:
		read = add(&want.Input, gu.InputTokens) && add(&want.Input, gu.CacheCreationTokens) &&
			add(&want.Input, gu.CacheReadTokens) && add(&want.Output, gu.OutputTokens)
	}
	if read && want != u {
		t.Fatalf("a Go client reads usage %+v, ParseUsage %+v", want, u)
	}
}

// TestStreamUsage: a stream's usage events, as each API sends them.
func TestStreamUsage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		format    Format
		events    []string
		want      Usage
		ok, final bool
	}{
		{"chat, include_usage", OpenAIChat, []string{
			`{"id":"c","choices":[{"delta":{"content":"hi"}}],"usage":null}`,
			`{"id":"c","choices":[],"usage":{"prompt_tokens":150000,"completion_tokens":3}}`,
			`[DONE]`,
		}, Usage{150000, 3}, true, true},
		{"chat, no usage", OpenAIChat, []string{`{"choices":[{"delta":{"content":"hi"}}]}`, `[DONE]`}, Usage{}, false, false},
		{"responses, completed", OpenAIResponses, []string{
			`{"type":"response.created","response":{"id":"r","usage":null}}`,
			`{"type":"response.output_text.delta","delta":"hi"}`,
			`{"type":"response.completed","response":{"id":"r","output":[],"usage":{"input_tokens":40,"output_tokens":7}}}`,
		}, Usage{40, 7}, true, true},
		{"anthropic, start and delta", AnthropicMessages, []string{
			`{"type":"message_start","message":{"id":"m","usage":{"input_tokens":10,"cache_read_input_tokens":90,"output_tokens":1}}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25}}`,
			`{"type":"message_stop"}`,
		}, Usage{100, 25}, true, true},
		{"anthropic, a delta that counts input too", AnthropicMessages, []string{
			`{"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":1}}}`,
			`{"type":"message_delta","usage":{"input_tokens":12,"output_tokens":5}}`,
		}, Usage{12, 5}, true, true},
		{"anthropic, cut after the start", AnthropicMessages, []string{
			`{"type":"message_start","message":{"usage":{"input_tokens":5000,"output_tokens":1}}}`,
		}, Usage{5000, 1}, true, false},
		{"a folded usage key is ignored", OpenAIChat, []string{`{"usage":{"prompt_tokens":1},"Usage":{"prompt_tokens":100000}}`}, Usage{}, false, false},
		{"another format's usage isn't read", OpenAIChat, []string{`{"response":{"usage":{"input_tokens":5}}}`}, Usage{}, false, false},
	} {
		var s StreamUsage
		for _, ev := range tc.events {
			s.Event([]byte(ev), tc.format)
		}
		u, ok, final := s.Usage()
		if u != tc.want || ok != tc.ok || final != tc.final {
			t.Errorf("%s: %+v ok %v final %v, want %+v %v %v", tc.name, u, ok, final, tc.want, tc.ok, tc.final)
		}
	}
	if n := testing.AllocsPerRun(100, func() {
		var s StreamUsage
		s.Event([]byte(`{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":3}}`), OpenAIChat)
	}); n != 0 {
		t.Errorf("%v allocations an event", n)
	}
}
