// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
)

func parse(t *testing.T, f Format, body string) *Request {
	t.Helper()
	var r Request
	Parse([]byte(body), f, &r)
	return &r
}

func TestParseFormats(t *testing.T) {
	for _, tc := range []struct {
		name   string
		format Format
		body   string
		want   Request // the fields compared: model, prompt, messages, output, choices, stream, tools
		model  string
		roles  []Role
	}{
		{
			name:   "chat",
			format: OpenAIChat,
			body: `{"model":"gpt-4o","messages":[{"role":"system","content":"Be brief."},` +
				`{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":"https://x/y.png"}}]},` +
				`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]},` +
				`{"role":"tool","tool_call_id":"c1","content":"42"}],` +
				`"max_tokens":100,"n":2,"stream":true,"tools":[{"type":"function","function":{"name":"f","parameters":{}}}],"unknown":{"x":[1,2]}}`,
			want:  Request{PromptBytes: 9 + 5 + 7 + 2, Messages: 4, OutputTokens: 100, HasOutputTokens: true, Choices: 2, HasChoices: true, Stream: true, Tools: 1},
			model: "gpt-4o",
			roles: []Role{RoleSystem, RoleUser, RoleAssistant, RoleTool},
		},
		{
			name:   "chat, max_completion_tokens wins when larger",
			format: OpenAIChat,
			body:   `{"model":"m","messages":[],"max_tokens":10,"max_completion_tokens":500}`,
			want:   Request{OutputTokens: 500, HasOutputTokens: true},
			model:  "m",
		},
		{
			name:   "chat, the larger of both counts",
			format: OpenAIChat,
			body:   `{"messages":[],"max_tokens":900,"max_completion_tokens":5}`,
			want:   Request{OutputTokens: 900, HasOutputTokens: true},
		},
		{
			name:   "chat, nulls are absent",
			format: OpenAIChat,
			body:   `{"model":null,"messages":null,"max_tokens":null,"n":null,"stream":null,"tools":null}`,
		},
		{
			name:   "chat, function role and functions",
			format: OpenAIChat,
			body:   `{"messages":[{"role":"function","name":"f","content":"ok"},{"role":"assistant","function_call":{"name":"f","arguments":"xy"}}],"functions":[{"name":"f"},{"name":"g"}]}`,
			want:   Request{PromptBytes: 4, Messages: 2, Tools: 2},
			roles:  []Role{RoleAssistant, RoleTool},
		},
		{
			name:   "chat, escaped text counts unescaped",
			format: OpenAIChat,
			body:   `{"messages":[{"role":"user","content":"a\nbé😀\"é"}]}`,
			want:   Request{PromptBytes: 1 + 1 + 1 + 2 + 4 + 1 + 2, Messages: 1},
			roles:  []Role{RoleUser},
		},
		{
			name:   "chat, a part without a type counts, refusal does not",
			format: OpenAIChat,
			body:   `{"messages":[{"role":"user","content":[{"text":"abc"},{"type":"refusal","refusal":"no"},{"type":"input_audio","text":5}]}]}`,
			want:   Request{PromptBytes: 3, Messages: 1},
			roles:  []Role{RoleUser},
		},
		{
			name:   "chat, an unknown role",
			format: OpenAIChat,
			body:   `{"messages":[{"role":"wizard","content":"x"},{"content":"y"}]}`,
			want:   Request{PromptBytes: 2, Messages: 2},
			roles:  []Role{RoleOther},
		},
		{
			name:   "responses, string input",
			format: OpenAIResponses,
			body:   `{"model":"gpt-4.1","instructions":"Be kind.","input":"Hi there","max_output_tokens":64,"stream":false,"tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}]}`,
			want:   Request{PromptBytes: 8 + 8, Messages: 1, OutputTokens: 64, HasOutputTokens: true, Tools: 2},
			model:  "gpt-4.1",
			roles:  []Role{RoleSystem, RoleUser},
		},
		{
			name:   "responses, items",
			format: OpenAIResponses,
			body: `{"input":[{"role":"developer","content":"rules"},{"type":"message","role":"user","content":[{"type":"input_text","text":"q?"},{"type":"input_image","image_url":"data:"}]},` +
				`{"type":"function_call","call_id":"1","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"1","output":"result"},{"type":"reasoning","id":"r"}],"previous_response_id":"resp_1"}`,
			want:  Request{PromptBytes: 5 + 2 + 2 + 6, Messages: 5},
			roles: []Role{RoleDeveloper, RoleUser, RoleAssistant, RoleTool},
		},
		{
			name:   "embeddings, strings",
			format: OpenAIEmbeddings,
			body:   `{"model":"text-embedding-3-small","input":["one","three"],"dimensions":256}`,
			want:   Request{PromptBytes: 8, Messages: 2},
			model:  "text-embedding-3-small",
			roles:  []Role{RoleUser},
		},
		{
			name:   "embeddings, a string",
			format: OpenAIEmbeddings,
			body:   `{"input":"hello"}`,
			want:   Request{PromptBytes: 5, Messages: 1},
			roles:  []Role{RoleUser},
		},
		{
			name:   "embeddings, tokens",
			format: OpenAIEmbeddings,
			body:   `{"input":[1,2,3]}`,
			want:   Request{PromptBytes: 12, Messages: 1},
			roles:  []Role{RoleUser},
		},
		{
			name:   "embeddings, arrays of tokens",
			format: OpenAIEmbeddings,
			body:   `{"input":[[1,2],[3],[]]}`,
			want:   Request{PromptBytes: 12, Messages: 3},
			roles:  []Role{RoleUser},
		},
		{
			name:   "embeddings ignore chat fields",
			format: OpenAIEmbeddings,
			body:   `{"input":"x","messages":5,"max_tokens":"a","n":[],"stream":{}}`,
			want:   Request{PromptBytes: 1, Messages: 1},
			roles:  []Role{RoleUser},
		},
		{
			name:   "anthropic",
			format: AnthropicMessages,
			body: `{"model":"claude-sonnet-4-5","max_tokens":1024,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],` +
				`"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"f","input":{"q":"long text not counted"}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"done"}]},{"type":"tool_result","tool_use_id":"u","content":"ok"}]}],` +
				`"stream":true,"tools":[{"name":"f","input_schema":{}},{"type":"web_search_20250305","name":"web_search"}]}`,
			want:  Request{PromptBytes: 3 + 5 + 2 + 4 + 2, Messages: 3, OutputTokens: 1024, HasOutputTokens: true, Stream: true, Tools: 2},
			model: "claude-sonnet-4-5",
			roles: []Role{RoleSystem, RoleUser, RoleAssistant},
		},
		{
			name:   "anthropic, string system; n and functions are not read",
			format: AnthropicMessages,
			body:   `{"system":"you are","messages":[],"n":"x","functions":7,"max_completion_tokens":"y"}`,
			want:   Request{PromptBytes: 7},
			roles:  []Role{RoleSystem},
		},
		{
			name:   "white space everywhere",
			format: OpenAIChat,
			body:   " \t\n{ \"model\" : \"m\" ,\r\n \"messages\" : [ { \"role\" : \"user\" , \"content\" : \"x\" } ] , \"n\" : 1 } \n",
			want:   Request{PromptBytes: 1, Messages: 1, Choices: 1, HasChoices: true},
			model:  "m",
			roles:  []Role{RoleUser},
		},
		{
			name:   "an escaped key is read as its key",
			format: OpenAIChat,
			body:   `{"model":"m","max_tokens":7}`,
			want:   Request{OutputTokens: 7, HasOutputTokens: true},
			model:  "m",
		},
		{
			name:   "an escaped model",
			format: OpenAIChat,
			body:   `{"model":"gpt-4"}`,
			model:  "gpt-4",
		},
		{
			name:   "integral floats are counts",
			format: OpenAIChat,
			body:   `{"max_tokens":4096.0,"n":1e0}`,
			want:   Request{OutputTokens: 4096, HasOutputTokens: true, Choices: 1, HasChoices: true},
		},
		{
			name:   "exponents",
			format: OpenAIChat,
			body:   `{"max_tokens":4.096E+3,"n":100e-2}`,
			want:   Request{OutputTokens: 4096, HasOutputTokens: true, Choices: 1, HasChoices: true},
		},
		{
			name:   "huge numbers saturate",
			format: OpenAIChat,
			body:   `{"max_tokens":99999999999999999999999999,"n":1e400}`,
			want:   Request{OutputTokens: math.MaxInt64, HasOutputTokens: true, Choices: math.MaxInt64, HasChoices: true},
		},
		{
			name:   "minus zero",
			format: OpenAIChat,
			body:   `{"max_tokens":-0}`,
			want:   Request{HasOutputTokens: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := parse(t, tc.format, tc.body)
			if r.Malformed {
				t.Fatalf("malformed at %d: %s", r.Offset, r.Why)
			}
			got := Request{PromptBytes: r.PromptBytes, Messages: r.Messages, OutputTokens: r.OutputTokens, HasOutputTokens: r.HasOutputTokens,
				Choices: r.Choices, HasChoices: r.HasChoices, Stream: r.Stream, Tools: r.Tools}
			if got != tc.want {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
			if string(r.Model()) != tc.model || r.HasModel != (tc.model != "") {
				t.Errorf("model %q (%v), want %q", r.Model(), r.HasModel, tc.model)
			}
			var roles []Role
			for ro := RoleSystem; ro < numRoles; ro++ {
				if _, _, ok := r.FirstRole(ro); ok {
					roles = append(roles, ro)
				}
			}
			if !slices.Equal(roles, tc.roles) {
				t.Errorf("roles %v, want %v", roles, tc.roles)
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	deep := strings.Repeat("[", 64) + strings.Repeat("]", 64) // 64 more than the top level: 65 deep
	for _, tc := range []struct {
		name   string
		format Format
		body   string
	}{
		{"empty", OpenAIChat, ``},
		{"white space only", OpenAIChat, " \n"},
		{"not an object", OpenAIChat, `[]`},
		{"a string", OpenAIChat, `"x"`},
		{"truncated", OpenAIChat, `{"model":"m"`},
		{"truncated string", OpenAIChat, `{"model":"m`},
		{"trailing comma in object", OpenAIChat, `{"model":"m",}`},
		{"trailing comma in array", OpenAIChat, `{"messages":[{"role":"user"},]}`},
		{"trailing comma, skipped", OpenAIChat, `{"x":[1,2,]}`},
		{"trailing comma, skipped object", OpenAIChat, `{"x":{"a":1,}}`},
		{"leading comma", OpenAIChat, `{,"model":"m"}`},
		{"missing colon", OpenAIChat, `{"model" "m"}`},
		{"missing comma", OpenAIChat, `{"model":"m" "n":1}`},
		{"unquoted key", OpenAIChat, `{model:"m"}`},
		{"single quotes", OpenAIChat, `{'model':'m'}`},
		{"data after", OpenAIChat, `{"model":"m"} {}`},
		{"data after, garbage", OpenAIChat, `{"model":"m"}x`},
		{"NaN", OpenAIChat, `{"x":NaN}`},
		{"leading zero", OpenAIChat, `{"x":01}`},
		{"plus sign", OpenAIChat, `{"x":+1}`},
		{"bare dot", OpenAIChat, `{"x":1.}`},
		{"bare exponent", OpenAIChat, `{"x":1e}`},
		{"bad literal", OpenAIChat, `{"x":tru}`},
		{"comment", OpenAIChat, `{/* c */"model":"m"}`},
		{"control character", OpenAIChat, "{\"model\":\"a\tb\"}"},
		{"bad escape", OpenAIChat, `{"model":"\x41"}`},
		{"short unicode escape", OpenAIChat, `{"model":"\u12"}`},
		{"lone high surrogate", OpenAIChat, `{"model":"\ud83d"}`},
		{"lone high surrogate, then a letter", OpenAIChat, `{"model":"\ud83dabcdef"}`},
		{"high surrogate, then not a low one", OpenAIChat, `{"model":"\ud83dA"}`},
		{"lone low surrogate", OpenAIChat, `{"model":"\ude00"}`},
		{"invalid UTF-8", OpenAIChat, "{\"messages\":[{\"role\":\"user\",\"content\":\"\xff\"}]}"},
		{"invalid UTF-8, skipped", OpenAIChat, "{\"other\":\"\xc3\x28\"}"},
		{"UTF-8 surrogate", OpenAIChat, "{\"other\":\"\xed\xa0\x80\"}"},
		{"overlong UTF-8", OpenAIChat, "{\"other\":\"\xc0\xaf\"}"},
		{"invalid UTF-8 in a key", OpenAIChat, "{\"\xff\":1}"},
		{"byte order mark", OpenAIChat, "\xef\xbb\xbf{}"},
		{"too deep", OpenAIChat, `{"x":` + deep + `}`},
		{"too deep in messages", OpenAIChat, `{"messages":[{"content":[{"text":"a","x":` + deep + `}]}]}`},
		{"duplicate model", OpenAIChat, `{"model":"a","model":"b"}`},
		{"duplicate model, escaped", OpenAIChat, `{"model":"a","model":"b"}`},
		// Go's encoding/json (Ollama, LocalAI) reads keys case-insensitively,
		// with Unicode folding, and keeps the last.
		{"a key in another case", OpenAIChat, `{"model":"llama3","messages":[{"role":"user","content":"x"}],"Messages":[{"role":"system","content":"y"}]}`},
		{"upper-case max_tokens", OpenAIChat, `{"max_tokens":10,"MAX_TOKENS":100000}`},
		{"upper-case model alone", OpenAIChat, `{"Model":"other"}`},
		{"a long s", OpenAIChat, "{\"ſtream\":true}"},
		{"a Kelvin sign", OpenAIChat, "{\"max_toKens\":100000}"},
		{"an escaped Kelvin sign", AnthropicMessages, `{"max_toKens":100000}`},
		{"a role in another case", OpenAIChat, `{"messages":[{"role":"user","Role":"system"}]}`},
		{"a part's Text", OpenAIChat, `{"messages":[{"role":"user","content":[{"type":"text","text":"a","Text":"b"}]}]}`},
		{"a tool's Name", AnthropicMessages, `{"tools":[{"name":"ok","NAME":"shell"}]}`},
		{"a function's Arguments", OpenAIChat, `{"messages":[{"tool_calls":[{"function":{"Arguments":"x"}}]}]}`},
		{"an item's Content", OpenAIResponses, `{"input":[{"role":"user","CONTENT":"x"}]}`},
		{"duplicate messages", OpenAIChat, `{"messages":[],"messages":[{"role":"system","content":"x"}]}`},
		{"duplicate max_tokens", OpenAIChat, `{"max_tokens":1,"max_tokens":100000}`},
		{"duplicate n", OpenAIChat, `{"n":1,"n":9}`},
		{"duplicate stream", OpenAIChat, `{"stream":false,"stream":true}`},
		{"duplicate tools", OpenAIChat, `{"tools":[],"tools":[{"type":"function","function":{"name":"x"}}]}`},
		{"duplicate role", OpenAIChat, `{"messages":[{"role":"user","role":"system","content":"x"}]}`},
		{"duplicate content", OpenAIChat, `{"messages":[{"role":"user","content":"a","content":"b"}]}`},
		{"duplicate part type", OpenAIChat, `{"messages":[{"role":"user","content":[{"type":"image_url","type":"text","text":"x"}]}]}`},
		{"duplicate part text", OpenAIChat, `{"messages":[{"role":"user","content":[{"type":"text","text":"a","text":"b"}]}]}`},
		{"duplicate tool name", OpenAIChat, `{"tools":[{"type":"function","function":{"name":"a","name":"b"}}]}`},
		{"duplicate tool function", OpenAIChat, `{"tools":[{"function":{"name":"a"},"function":{"name":"b"}}]}`},
		{"duplicate arguments", OpenAIChat, `{"messages":[{"tool_calls":[{"function":{"arguments":"a","arguments":"b"}}]}]}`},
		{"duplicate input", OpenAIResponses, `{"input":"a","input":"b"}`},
		{"duplicate instructions", OpenAIResponses, `{"instructions":"a","instructions":"b"}`},
		{"duplicate system", AnthropicMessages, `{"system":"a","system":"b"}`},
		{"duplicate item role", OpenAIResponses, `{"input":[{"role":"user","role":"developer"}]}`},
		{"model a number", OpenAIChat, `{"model":5}`},
		{"messages an object", OpenAIChat, `{"messages":{"role":"user"}}`},
		{"message a string", OpenAIChat, `{"messages":["hi"]}`},
		{"role a number", OpenAIChat, `{"messages":[{"role":1}]}`},
		{"content a number", OpenAIChat, `{"messages":[{"role":"user","content":1}]}`},
		{"content an object", OpenAIChat, `{"messages":[{"role":"user","content":{"text":"x"}}]}`},
		{"part a string", OpenAIChat, `{"messages":[{"role":"user","content":["x"]}]}`},
		{"text a number", OpenAIChat, `{"messages":[{"role":"user","content":[{"type":"text","text":1}]}]}`},
		{"text an array", OpenAIChat, `{"messages":[{"role":"user","content":[{"text":["x"]}]}]}`},
		{"type a number", OpenAIChat, `{"messages":[{"role":"user","content":[{"type":1,"text":"x"}]}]}`},
		{"max_tokens a string", OpenAIChat, `{"max_tokens":"100"}`},
		{"max_tokens a fraction", OpenAIChat, `{"max_tokens":1.5}`},
		{"max_tokens a small fraction", OpenAIChat, `{"max_tokens":1e-3}`},
		{"max_tokens negative", OpenAIChat, `{"max_tokens":-1}`},
		{"max_completion_tokens a bool", OpenAIChat, `{"max_completion_tokens":true}`},
		{"n a string", OpenAIChat, `{"n":"2"}`},
		{"stream a string", OpenAIChat, `{"stream":"true"}`},
		{"stream a number", OpenAIChat, `{"stream":1}`},
		{"tools an object", OpenAIChat, `{"tools":{}}`},
		{"tool a string", OpenAIChat, `{"tools":["f"]}`},
		{"tool name a number", AnthropicMessages, `{"tools":[{"name":1}]}`},
		{"tool function a string", OpenAIChat, `{"tools":[{"type":"function","function":"f"}]}`},
		{"tool type a number", OpenAIResponses, `{"tools":[{"type":1}]}`},
		{"tool_calls an object", OpenAIChat, `{"messages":[{"tool_calls":{}}]}`},
		{"function arguments a number", OpenAIChat, `{"messages":[{"tool_calls":[{"function":{"arguments":1}}]}]}`},
		{"instructions a number", OpenAIResponses, `{"instructions":1}`},
		{"input a number", OpenAIResponses, `{"input":1}`},
		{"input item a string", OpenAIResponses, `{"input":["x"]}`},
		{"embedding input mixed", OpenAIEmbeddings, `{"input":["a",1]}`},
		{"embedding input mixed arrays", OpenAIEmbeddings, `{"input":[[1],"a"]}`},
		{"embedding input object", OpenAIEmbeddings, `{"input":{}}`},
		{"embedding input null element", OpenAIEmbeddings, `{"input":[null]}`},
		{"embedding token a string", OpenAIEmbeddings, `{"input":[["a"]]}`},
		{"embedding token negative", OpenAIEmbeddings, `{"input":[-1]}`},
		{"embedding token a fraction", OpenAIEmbeddings, `{"input":[1.5]}`},
		{"system a number", AnthropicMessages, `{"system":1}`},
		{"system block a string", AnthropicMessages, `{"system":["x"]}`},
		{"anthropic content a number", AnthropicMessages, `{"messages":[{"role":"user","content":5}]}`},
		{"tool_result content a number skipped, then bad", AnthropicMessages, `{"messages":[{"role":"user","content":[{"type":"tool_result","content":5},{"type":"text","text":7}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := parse(t, tc.format, tc.body)
			if !r.Malformed {
				t.Fatalf("not malformed: %+v", r)
			}
			if r.Why == "" || r.Offset < 0 || r.Offset > len(tc.body) {
				t.Errorf("why %q, offset %d", r.Why, r.Offset)
			}
		})
	}
}

// TestParseDepth: 64 levels in all read, 65 malformed, wherever they are.
func TestParseDepth(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	for _, tc := range []struct {
		prefix, suffix string
		levels         int // levels before the nest
	}{
		{`{"x":`, `}`, 1},
		{`{"messages":[{"role":"user","x":`, `}]}`, 3},
		{`{"messages":[{"role":"user","content":[{"type":"text","x":`, `}]}]}`, 5},
		{`{"tools":[{"function":{"x":`, `}}]}`, 4},
		{`{"messages":[{"tool_calls":[{"function":{"x":`, `}}]}]}`, 6},
	} {
		ok := parse(t, OpenAIChat, tc.prefix+nest(MaxDepth-tc.levels)+tc.suffix)
		if ok.Malformed {
			t.Errorf("%s: %d deep is malformed: %s", tc.prefix, MaxDepth, ok.Why)
		}
		bad := parse(t, OpenAIChat, tc.prefix+nest(MaxDepth-tc.levels+1)+tc.suffix)
		if !bad.Malformed || bad.Why != "nested too deep" {
			t.Errorf("%s: %d deep: %+v", tc.prefix, MaxDepth+1, bad.Why)
		}
	}
	// Deep nests of the read structures stop at the depth too.
	parts := `{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"tool_result","content":` + nest(70) + `}]}]}]}`
	if r := parse(t, AnthropicMessages, parts); !r.Malformed {
		t.Error("deep tool results not malformed")
	}
}

// TestParseHostile: bodies built to cost time or memory parse in linear
// time, without allocating.
func TestParseHostile(t *testing.T) {
	big := func(prefix, elem, sep, suffix string, n int) []byte {
		var b strings.Builder
		b.WriteString(prefix)
		for i := range n {
			if i > 0 {
				b.WriteString(sep)
			}
			b.WriteString(elem)
		}
		b.WriteString(suffix)
		return []byte(b.String())
	}
	for _, tc := range []struct {
		name     string
		format   Format
		body     []byte
		messages int64
		tools    int
	}{
		{"many messages", OpenAIChat, big(`{"messages":[`, `{"role":"user","content":"x"}`, ",", `]}`, 100000), 100000, 0},
		{"many tools", OpenAIChat, big(`{"tools":[`, `{"type":"function","function":{"name":"f"}}`, ",", `]}`, 50000), 0, 50000},
		{"many keys", OpenAIChat, big(`{`, `"k":1`, ",", `}`, 200000), 0, 0},
		{"many unknown elements", OpenAIChat, big(`{"x":[`, `0`, ",", `]}`, 500000), 0, 0},
		{"many parts", OpenAIChat, big(`{"messages":[{"role":"user","content":[`, `{"type":"text","text":"a"}`, ",", `]}]}`, 50000), 1, 0},
		{"long string", OpenAIChat, []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("a", 4<<20) + `"}]}`), 1, 0},
		{"many escapes", OpenAIChat, []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat(`é`, 500000) + `"}]}`), 1, 0},
		{"many embedding tokens", OpenAIEmbeddings, big(`{"input":[`, `1234`, ",", `]}`, 500000), 1, 0},
		{"long number", OpenAIChat, []byte(`{"max_tokens":` + strings.Repeat("9", 1<<20) + `}`), 0, 0},
		{"long zero exponent", OpenAIChat, []byte(`{"max_tokens":0e999999999999999999}`), 0, 0},
		{"long fraction", OpenAIChat, []byte(`{"max_tokens":1.` + strings.Repeat("0", 1<<20) + `}`), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r Request
			allocs := testing.AllocsPerRun(3, func() { Parse(tc.body, tc.format, &r) })
			if r.Malformed {
				t.Fatalf("malformed at %d: %s", r.Offset, r.Why)
			}
			if allocs != 0 {
				t.Errorf("%v allocations", allocs)
			}
			if r.Messages != tc.messages || r.Tools != tc.tools {
				t.Errorf("messages %d, tools %d", r.Messages, r.Tools)
			}
		})
	}
}

func TestParseOffsets(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"a"},{"content":"b","role":"system"}]}`
	r := parse(t, OpenAIChat, body)
	i, at, ok := r.FirstRole(RoleSystem)
	if !ok || i != 1 || !strings.HasPrefix(body[at:], `"role":"system"`) {
		t.Errorf("system: %d at %d (%q)", i, at, body[at:])
	}
	i, at, _ = r.FirstRole(RoleUser)
	if i != 0 || !strings.HasPrefix(body[at:], `"role":"user"`) {
		t.Errorf("user: %d at %d", i, at)
	}
	bad := `{"model":"m","messages":[{"role":"user","content":"` + "\xff" + `"}]}`
	r = parse(t, OpenAIChat, bad)
	if !r.Malformed || bad[r.Offset] != 0xff {
		t.Errorf("malformed at %d, want the invalid byte", r.Offset)
	}
	// A role and its index for the top-level system prompts.
	r = parse(t, OpenAIResponses, `{"instructions":"x"}`)
	if i, at, ok := r.FirstRole(RoleSystem); !ok || i != -1 || at != 1 {
		t.Errorf("instructions: %d at %d, %v", i, at, ok)
	}
}

func TestEachTool(t *testing.T) {
	for _, tc := range []struct {
		format Format
		body   string
		want   []string
	}{
		{OpenAIChat, `{"tools":[{"type":"function","function":{"name":"a"}},{"type":"custom","custom":{"name":"b"}},{"type":"x"}],"functions":[{"name":"c"}]}`, []string{"a", "b", "x", "c"}},
		{OpenAIChat, `{"tools":[{"function":{"name":"ab"},"type":"function"}]}`, []string{"ab"}},
		{OpenAIResponses, `{"tools":[{"type":"function","name":"lookup"},{"type":"file_search"},{"name":"n","type":"t"}]}`, []string{"lookup", "file_search", "n"}},
		{AnthropicMessages, `{"tools":[{"name":"get_weather"},{"type":"bash_20250124","name":"bash"}]}`, []string{"get_weather", "bash"}},
		{AnthropicMessages, `{"tools":[{"name":"` + strings.Repeat("x", maxName+1) + `"}]}`, []string{"<nil>"}},
		{AnthropicMessages, `{"tools":[{}]}`, []string{"<nil>"}},
	} {
		r := parse(t, tc.format, tc.body)
		if r.Malformed {
			t.Fatalf("%s: malformed: %s", tc.body, r.Why)
		}
		var got []string
		r.eachTool([]byte(tc.body), &toolSink{names: &got})
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: tools %q, want %q", tc.body, got, tc.want)
		}
		if r.Tools != len(tc.want) {
			t.Errorf("%s: %d tools", tc.body, r.Tools)
		}
	}
}

func TestModelTooLong(t *testing.T) {
	r := parse(t, OpenAIChat, `{"model":"`+strings.Repeat("m", MaxModelBytes+1)+`"}`)
	if r.Malformed || !r.HasModel || !r.ModelTooLong || len(r.Model()) != 0 {
		t.Errorf("%+v", r)
	}
	r = parse(t, OpenAIChat, `{"model":"`+strings.Repeat("m", MaxModelBytes)+`"}`)
	if r.ModelTooLong || len(r.Model()) != MaxModelBytes {
		t.Errorf("model of %d: too long", MaxModelBytes)
	}
}
