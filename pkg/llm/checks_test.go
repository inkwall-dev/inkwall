// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"math"
	"strings"
	"testing"
)

func check(t *testing.T, c Config, f Format, body string, off CheckSet) Finding {
	t.Helper()
	r, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	var req Request
	Parse([]byte(body), f, &req)
	return r.Check([]byte(body), &req, off)
}

func TestChecks(t *testing.T) {
	chat := func(extra string) string {
		return `{"model":"llama-3.1-8b-instruct","messages":[{"role":"system","content":"sys"},{"role":"user","content":"hello"}]` + extra + `}`
	}
	for _, tc := range []struct {
		name   string
		cfg    Config
		format Format
		body   string
		want   Check
		index  int
	}{
		{"nothing set", Config{}, OpenAIChat, chat(`,"max_tokens":99999999,"n":100`), CheckNone, 0},
		{"malformed", Config{}, OpenAIChat, `{"model":`, CheckMalformed, -1},
		{"model exact", Config{Models: []string{"llama-3.1-8b-instruct"}}, OpenAIChat, chat(""), CheckNone, 0},
		{"model case-insensitive", Config{Models: []string{"Llama-3.1-8B-Instruct"}}, OpenAIChat, chat(""), CheckNone, 0},
		{"model prefix", Config{Models: []string{"qwen2.5-*", "llama-3.1-*"}}, OpenAIChat, chat(""), CheckNone, 0},
		{"model prefix, exact length", Config{Models: []string{"llama-3.1-8b-instruct*"}}, OpenAIChat, chat(""), CheckNone, 0},
		{"model not listed", Config{Models: []string{"llama-3.1-8b"}}, OpenAIChat, chat(""), CheckModel, -1},
		{"model, a longer one isn't exact", Config{Models: []string{"llama"}}, OpenAIChat, chat(""), CheckModel, -1},
		{"model missing", Config{Models: []string{"m"}}, OpenAIChat, `{"messages":[]}`, CheckModel, -1},
		{"model null", Config{Models: []string{"m"}}, OpenAIChat, `{"model":null}`, CheckModel, -1},
		{"model too long", Config{Models: []string{"m*"}}, OpenAIChat, `{"model":"m` + strings.Repeat("x", MaxModelBytes) + `"}`, CheckModel, -1},
		{"model escaped", Config{Models: []string{"a-b"}}, OpenAIChat, `{"model":"a-b"}`, CheckNone, 0},
		{"model not ASCII-folded beyond ASCII", Config{Models: []string{"é"}}, OpenAIChat, `{"model":"É"}`, CheckModel, -1},
		{"prompt at the cap", Config{MaxPromptBytes: 8}, OpenAIChat, chat(""), CheckNone, 0},
		{"prompt over", Config{MaxPromptBytes: 7}, OpenAIChat, chat(""), CheckMaxPrompt, -1},
		{"messages at the cap", Config{MaxMessages: 2}, OpenAIChat, chat(""), CheckNone, 0},
		{"messages over", Config{MaxMessages: 1}, OpenAIChat, chat(""), CheckMaxMessages, 1},
		{"embedding inputs over", Config{MaxMessages: 1}, OpenAIEmbeddings, `{"input":["a","b"]}`, CheckMaxMessages, 1},
		{"choices at the cap", Config{MaxChoices: 1}, OpenAIChat, chat(`,"n":1`), CheckNone, 0},
		{"choices over", Config{MaxChoices: 1}, OpenAIChat, chat(`,"n":2`), CheckMaxChoices, -1},
		{"choices unset", Config{MaxChoices: 1}, OpenAIChat, chat(""), CheckNone, 0},
		{"output at the cap", Config{MaxOutputTokens: 4096}, OpenAIChat, chat(`,"max_tokens":4096`), CheckNone, 0},
		{"output over", Config{MaxOutputTokens: 4096}, OpenAIChat, chat(`,"max_tokens":4097`), CheckMaxOutputTokens, -1},
		{"output over, max_completion_tokens", Config{MaxOutputTokens: 4096}, OpenAIChat, chat(`,"max_completion_tokens":4097`), CheckMaxOutputTokens, -1},
		{"output over in either", Config{MaxOutputTokens: 4096}, OpenAIChat, chat(`,"max_completion_tokens":10,"max_tokens":5000`), CheckMaxOutputTokens, -1},
		{"output saturated", Config{MaxOutputTokens: MaxOutputCap}, OpenAIChat, chat(`,"max_tokens":1e30`), CheckMaxOutputTokens, -1},
		{"output unset, not required", Config{MaxOutputTokens: 4096}, OpenAIChat, chat(""), CheckNone, 0},
		{"output required", Config{RequireOutputTokens: true}, OpenAIChat, chat(""), CheckMaxOutputTokens, -1},
		{"output required, null", Config{RequireOutputTokens: true}, OpenAIChat, chat(`,"max_tokens":null`), CheckMaxOutputTokens, -1},
		{"output required, set", Config{RequireOutputTokens: true}, OpenAIChat, chat(`,"max_tokens":10`), CheckNone, 0},
		{"output required, responses", Config{RequireOutputTokens: true}, OpenAIResponses, `{"input":"x","max_output_tokens":1}`, CheckNone, 0},
		{"output required, anthropic", Config{RequireOutputTokens: true, MaxOutputTokens: 100}, AnthropicMessages, `{"messages":[],"max_tokens":101}`, CheckMaxOutputTokens, -1},
		{"output not required of embeddings", Config{RequireOutputTokens: true}, OpenAIEmbeddings, `{"input":"x"}`, CheckNone, 0},
		{"roles allowed", Config{ClientRoles: []Role{RoleSystem, RoleUser}}, OpenAIChat, chat(""), CheckNone, 0},
		// Only roles this engine doesn't know: none allowed, not every one.
		{"only unknown roles", Config{ClientRoles: []Role{RoleNone}}, OpenAIChat, chat(""), CheckClientRole, 0},
		{"unknown roles and user", Config{ClientRoles: []Role{RoleNone, RoleUser, RoleSystem}}, OpenAIChat, chat(""), CheckNone, 0},
		{"system refused", Config{ClientRoles: []Role{RoleUser, RoleAssistant}}, OpenAIChat, chat(""), CheckClientRole, 0},
		{"the first refused message", Config{ClientRoles: []Role{RoleSystem}}, OpenAIChat, chat(""), CheckClientRole, 1},
		{"an unknown role is refused", Config{ClientRoles: []Role{RoleUser}}, OpenAIChat, `{"messages":[{"role":"user"},{"role":"root"}]}`, CheckClientRole, 1},
		{"a message without a role is refused", Config{ClientRoles: []Role{RoleUser}}, OpenAIChat, `{"messages":[{"content":"x"}]}`, CheckClientRole, 0},
		{"instructions are system", Config{ClientRoles: []Role{RoleUser}}, OpenAIResponses, `{"instructions":"x","input":"y"}`, CheckClientRole, -1},
		{"anthropic system is system", Config{ClientRoles: []Role{RoleUser, RoleAssistant}}, AnthropicMessages, `{"system":"x","messages":[{"role":"user","content":"y"}]}`, CheckClientRole, -1},
		{"developer refused", Config{ClientRoles: []Role{RoleUser}}, OpenAIResponses, `{"input":[{"role":"user","content":"a"},{"role":"developer","content":"b"}]}`, CheckClientRole, 1},
		{"tool output is tool", Config{ClientRoles: []Role{RoleUser}}, OpenAIResponses, `{"input":[{"type":"function_call_output","output":"x"}]}`, CheckClientRole, 0},
		{"items without a role pass", Config{ClientRoles: []Role{RoleUser}}, OpenAIResponses, `{"input":[{"type":"reasoning"},{"role":"user","content":"x"}]}`, CheckNone, 0},
		{"tools any", Config{}, OpenAIChat, `{"tools":[{"function":{"name":"x"}}]}`, CheckNone, 0},
		{"tools none, none sent", Config{Tools: ToolsNone}, OpenAIChat, `{"tools":[]}`, CheckNone, 0},
		{"tools none", Config{Tools: ToolsNone}, OpenAIChat, `{"tools":[{"function":{"name":"x"}}]}`, CheckTools, 0},
		{"functions none", Config{Tools: ToolsNone}, OpenAIChat, `{"functions":[{"name":"x"}]}`, CheckTools, 0},
		{"tools listed", Config{Tools: ToolsListed, ToolNames: []string{"a", "b"}}, OpenAIChat, `{"tools":[{"function":{"name":"a"}},{"function":{"name":"b"}}],"functions":[{"name":"a"}]}`, CheckNone, 0},
		{"tools not listed", Config{Tools: ToolsListed, ToolNames: []string{"a"}}, OpenAIChat, `{"tools":[{"function":{"name":"a"}},{"function":{"name":"B"}}]}`, CheckTools, 1},
		{"functions not listed", Config{Tools: ToolsListed, ToolNames: []string{"a"}}, OpenAIChat, `{"tools":[{"function":{"name":"a"}}],"functions":[{"name":"c"}]}`, CheckTools, 1},
		{"a built-in tool by its type", Config{Tools: ToolsListed, ToolNames: []string{"web_search_preview"}}, OpenAIResponses, `{"tools":[{"type":"web_search_preview"}]}`, CheckNone, 0},
		{"a tool without a name", Config{Tools: ToolsListed, ToolNames: []string{"a"}}, AnthropicMessages, `{"tools":[{"input_schema":{}}]}`, CheckTools, 0},
		{"a tool's long name", Config{Tools: ToolsListed, ToolNames: []string{"a"}}, AnthropicMessages, `{"tools":[{"name":"` + strings.Repeat("a", 300) + `"}]}`, CheckTools, 0},
		{"order: model first", Config{Models: []string{"x"}, MaxPromptBytes: 1}, OpenAIChat, chat(""), CheckModel, -1},
		{"order: prompt before output", Config{MaxPromptBytes: 1, RequireOutputTokens: true}, OpenAIChat, chat(""), CheckMaxPrompt, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := check(t, tc.cfg, tc.format, tc.body, 0)
			if got.Check != tc.want {
				t.Fatalf("%s, want %s", got.Check, tc.want)
			}
			if got.Check != CheckNone && got.MessageIndex != tc.index {
				t.Errorf("message %d, want %d", got.MessageIndex, tc.index)
			}
		})
	}
}

func TestChecksOff(t *testing.T) {
	cfg := Config{MaxPromptBytes: 1, MaxOutputTokens: 1, Models: []string{"x"}}
	body := `{"model":"y","messages":[{"role":"user","content":"hello"}],"max_tokens":5}`
	off := CheckSet(0).With(CheckModel)
	if got := check(t, cfg, OpenAIChat, body, off); got.Check != CheckMaxPrompt {
		t.Errorf("model off: %s", got.Check)
	}
	off = off.With(CheckMaxPrompt)
	if got := check(t, cfg, OpenAIChat, body, off); got.Check != CheckMaxOutputTokens {
		t.Errorf("model, prompt off: %s", got.Check)
	}
	if got := check(t, cfg, OpenAIChat, body, off.With(CheckMaxOutputTokens)); got.Check != CheckNone {
		t.Errorf("all off: %s", got.Check)
	}
	if got := check(t, cfg, OpenAIChat, `{`, CheckSet(0).With(CheckMalformed)); got.Check != CheckNone {
		t.Errorf("malformed off: %s", got.Check)
	}
}

func TestFindingOffsets(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"x"},{"role":"system","content":"y"}],"tools":[{"name":"ok"},{"name":"bad"}]}`
	f := check(t, Config{ClientRoles: []Role{RoleUser}}, AnthropicMessages, body, 0)
	if f.Check != CheckClientRole || f.Role != RoleSystem || !strings.HasPrefix(body[f.Offset:], `"role":"system"`) {
		t.Errorf("%+v at %q", f, body[f.Offset:])
	}
	f = check(t, Config{Tools: ToolsListed, ToolNames: []string{"ok"}}, AnthropicMessages, body, 0)
	if f.Check != CheckTools || f.MessageIndex != 1 || !strings.HasPrefix(body[f.Offset:], `{"name":"bad"}`) {
		t.Errorf("%+v", f)
	}
}

func TestCompile(t *testing.T) {
	for _, c := range []Config{
		{Models: []string{""}},
		{Models: []string{"*"}},
		{Models: []string{"a*b"}},
		{Models: []string{"a**"}},
		{Models: make([]string, MaxModels+1)},
		{MaxPromptBytes: -1},
		{MaxPromptBytes: MaxPromptCap + 1},
		{MaxMessages: MaxMessagesCap + 1},
		{MaxOutputTokens: MaxOutputCap + 1},
		{MaxChoices: MaxChoicesCap + 1},
		{ClientRoles: []Role{RoleOther}},
		{Tools: ToolsListed},
		{Tools: ToolsNone, ToolNames: []string{"a"}},
		{Tools: ToolsListed, ToolNames: []string{""}},
		{Tools: 9},
	} {
		if _, err := Compile(c); err == nil {
			t.Errorf("%+v compiles", c)
		}
	}
}

func TestEstimatedTokens(t *testing.T) {
	for _, tc := range []struct {
		cfg    Config
		format Format
		body   string
		want   int64
	}{
		{Config{}, OpenAIChat, `{"messages":[{"role":"user","content":"abcd"}],"max_tokens":10}`, 2 + 10},
		{Config{}, OpenAIChat, `{"messages":[{"role":"user","content":"abc"}],"max_tokens":10}`, 1 + 10},
		{Config{}, OpenAIChat, `{"messages":[{"role":"user","content":"abc"}]}`, 1 + DefaultOutputTokens},
		{Config{MaxOutputTokens: 100}, OpenAIChat, `{"messages":[{"role":"user","content":"abc"}]}`, 1 + 100},
		{Config{}, OpenAIEmbeddings, `{"input":"abcdefg"}`, 3},
		{Config{}, OpenAIEmbeddings, `{"input":[1,2,3]}`, 4},
		{Config{}, OpenAIChat, `{"messages":[{"role":"user","content":"a"}],"max_tokens":1e30}`, math.MaxInt64},
		{Config{}, AnthropicMessages, `{"messages":[],"max_tokens":7}`, 7},
	} {
		r, err := Compile(tc.cfg)
		if err != nil {
			t.Fatal(err)
		}
		var req Request
		if !Parse([]byte(tc.body), tc.format, &req) {
			t.Fatalf("%s: %s", tc.body, req.Why)
		}
		if got := r.EstimatedTokens(&req); got != tc.want {
			t.Errorf("%s: %d tokens, want %d", tc.body, got, tc.want)
		}
	}
}

func TestCheckIDs(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range Checks {
		id := c.RuleID()
		if id < RuleIDMin || id > RuleIDMax || seen[id] {
			t.Errorf("%s: rule ID %d", c, id)
		}
		seen[id] = true
		if back, ok := CheckOf(id); !ok || back != c {
			t.Errorf("%s: CheckOf(%d) = %s", c, id, back)
		}
		if !strings.HasPrefix(c.String(), "llm-") {
			t.Errorf("%s", c)
		}
	}
	// The IDs are stable: exclusions name them.
	if CheckMalformed.RuleID() != 4800000 || CheckTools.RuleID() != 4800007 {
		t.Error("rule IDs changed")
	}
	for _, id := range []int{RuleIDMin - 1, RuleIDMax + 1, RuleIDMin + int(numChecks), RuleIDMax} {
		if _, ok := CheckOf(id); ok {
			t.Errorf("CheckOf(%d)", id)
		}
	}
}

// TestCheckAllocations: checking a request allocates nothing, tools
// included.
func TestCheckAllocations(t *testing.T) {
	r, err := Compile(Config{Models: []string{"m*"}, MaxPromptBytes: 1 << 20, ClientRoles: []Role{RoleUser, RoleAssistant},
		Tools: ToolsListed, ToolNames: []string{"a", "b"}, MaxOutputTokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"m1","messages":[{"role":"user","content":"x"}],"tools":[{"function":{"name":"a"}},{"function":{"name":"bb"}}],"max_tokens":5}`)
	var req Request
	allocs := testing.AllocsPerRun(100, func() {
		Parse(body, OpenAIChat, &req)
		r.Check(body, &req, 0)
	})
	if allocs != 0 {
		t.Errorf("%v allocations", allocs)
	}
}
