// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// ref is what a request holds, read with encoding/json: the reference the
// parser is compared with.
type ref struct {
	model        string
	hasModel     bool
	modelTooLong bool
	prompt       int64
	messages     int64
	output       int64
	hasOutput    bool
	choices      int64
	hasChoices   bool
	stream       bool
	tools        []string
	roles        [numRoles]int // first index + 2; 0: not seen
}

// errSkip: the body is valid, but too costly to read with math/big (a
// huge exponent).
var errSkip = errors.New("skip")

var errType = errors.New("wrong type")

// refRead reads body as f with encoding/json, by the rules Parse follows,
// for a body Parse accepted (so no key read is repeated).
func refRead(body []byte, f Format) (ref, error) {
	var out ref
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return out, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return out, errors.New("data after the object")
	}
	top, ok := v.(map[string]any)
	if !ok {
		return out, errType
	}
	role := func(r Role, index int64) {
		if r != RoleNone && out.roles[r] == 0 {
			out.roles[r] = int(index) + 2
		}
	}
	var maxTokens, maxCompletion int64
	var hasMaxTokens, hasMaxCompletion bool
	var err error
	for k, v := range top {
		switch {
		case k == "model":
			switch m := v.(type) {
			case nil:
			case string:
				out.hasModel = true
				if len(m) > MaxModelBytes {
					out.modelTooLong = true
				} else {
					out.model = m
				}
			default:
				return out, errType
			}
		case k == "stream" && f != OpenAIEmbeddings:
			switch s := v.(type) {
			case nil:
			case bool:
				out.stream = s
			default:
				return out, errType
			}
		case k == "messages" && (f == OpenAIChat || f == AnthropicMessages):
			if v == nil {
				break
			}
			msgs, ok := v.([]any)
			if !ok {
				return out, errType
			}
			for i, m := range msgs {
				r, err := refMessage(&out, m, f)
				if err != nil {
					return out, err
				}
				role(r, int64(i))
			}
			out.messages += int64(len(msgs))
		case k == "max_tokens" && (f == OpenAIChat || f == AnthropicMessages):
			if maxTokens, hasMaxTokens, err = refInt(v); err != nil {
				return out, err
			}
		case k == "max_completion_tokens" && f == OpenAIChat:
			if maxCompletion, hasMaxCompletion, err = refInt(v); err != nil {
				return out, err
			}
		case k == "max_output_tokens" && f == OpenAIResponses:
			if out.output, out.hasOutput, err = refInt(v); err != nil {
				return out, err
			}
		case k == "n" && f == OpenAIChat:
			if out.choices, out.hasChoices, err = refInt(v); err != nil {
				return out, err
			}
		case k == "tools" && f != OpenAIEmbeddings, k == "functions" && f == OpenAIChat:
			if v == nil {
				break
			}
			names, err := refTools(v)
			if err != nil {
				return out, err
			}
			out.tools = append(out.tools, names...)
		case k == "input" && f == OpenAIEmbeddings:
			switch in := v.(type) {
			case nil:
			case string:
				out.prompt += int64(len(in))
				out.messages++
				role(RoleUser, 0)
			case []any:
				var kind string
				for _, e := range in {
					var k string
					switch e := e.(type) {
					case string:
						k = "s"
						out.prompt += int64(len(e))
						out.messages++
					case json.Number:
						k = "n"
						if _, _, err := refInt(e); err != nil {
							return out, err
						}
						out.prompt += 4
					case []any:
						k = "a"
						for _, t := range e {
							if _, ok := t.(json.Number); !ok {
								return out, errType
							}
							if _, _, err := refInt(t); err != nil {
								return out, err
							}
							out.prompt += 4
						}
						out.messages++
					default:
						return out, errType
					}
					if kind != "" && kind != k {
						return out, errType
					}
					kind = k
				}
				if kind == "n" {
					out.messages++
				}
				if out.messages > 0 {
					role(RoleUser, 0)
				}
			default:
				return out, errType
			}
		case k == "input" && f == OpenAIResponses:
			switch in := v.(type) {
			case nil:
			case string:
				out.prompt += int64(len(in))
				out.messages++
				role(RoleUser, 0)
			case []any:
				for i, it := range in {
					r, err := refItem(&out, it)
					if err != nil {
						return out, err
					}
					role(r, int64(i))
				}
				out.messages += int64(len(in))
			default:
				return out, errType
			}
		case k == "instructions" && f == OpenAIResponses:
			switch s := v.(type) {
			case nil:
			case string:
				out.prompt += int64(len(s))
				role(RoleSystem, -1)
			default:
				return out, errType
			}
		case k == "system" && f == AnthropicMessages:
			if v == nil {
				break
			}
			role(RoleSystem, -1)
			if err := refContent(&out, v, false); err != nil {
				return out, err
			}
		}
	}
	switch {
	case hasMaxTokens && hasMaxCompletion:
		out.output, out.hasOutput = max(maxTokens, maxCompletion), true
	case hasMaxCompletion:
		out.output, out.hasOutput = maxCompletion, true
	case hasMaxTokens:
		out.output, out.hasOutput = maxTokens, true
	}
	return out, nil
}

func refInt(v any) (int64, bool, error) {
	if v == nil {
		return 0, false, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false, errType
	}
	s := strings.ToLower(n.String())
	if _, e, ok := strings.Cut(s, "e"); ok && len(strings.TrimLeft(strings.TrimLeft(e, "+-"), "0")) > 4 {
		return 0, false, errSkip
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return 0, false, errType
	}
	if !r.IsInt() || r.Sign() < 0 {
		return 0, false, errType
	}
	if r.Num().IsInt64() {
		return r.Num().Int64(), true, nil
	}
	return math.MaxInt64, true, nil
}

func refRole(v any, present bool, missing Role) (Role, error) {
	if !present {
		return missing, nil
	}
	s, ok := v.(string)
	if !ok {
		return RoleNone, errType
	}
	return roleOf([]byte(s)), nil
}

func refMessage(out *ref, m any, f Format) (Role, error) {
	msg, ok := m.(map[string]any)
	if !ok {
		return RoleNone, errType
	}
	rv, has := msg["role"]
	r, err := refRole(rv, has, RoleOther)
	if err != nil {
		return r, err
	}
	if c, ok := msg["content"]; ok && c != nil {
		if err := refContent(out, c, false); err != nil {
			return r, err
		}
	}
	if f != OpenAIChat {
		return r, nil
	}
	if tc, ok := msg["tool_calls"]; ok && tc != nil {
		calls, ok := tc.([]any)
		if !ok {
			return r, errType
		}
		for _, c := range calls {
			call, ok := c.(map[string]any)
			if !ok {
				return r, errType
			}
			if fn, ok := call["function"]; ok {
				if err := refFunction(out, fn); err != nil {
					return r, err
				}
			}
		}
	}
	if fn, ok := msg["function_call"]; ok {
		if err := refFunction(out, fn); err != nil {
			return r, err
		}
	}
	return r, nil
}

func refFunction(out *ref, fn any) error {
	if fn == nil {
		return nil
	}
	m, ok := fn.(map[string]any)
	if !ok {
		return errType
	}
	switch a := m["arguments"].(type) {
	case nil:
	case string:
		out.prompt += int64(len(a))
	default:
		return errType
	}
	return nil
}

// refContent reads a string or an array of parts.
func refContent(out *ref, c any, inner bool) error {
	switch c := c.(type) {
	case string:
		out.prompt += int64(len(c))
		return nil
	case []any:
		for _, p := range c {
			if err := refPart(out, p, inner); err != nil {
				return err
			}
		}
		return nil
	}
	return errType
}

func refPart(out *ref, p any, inner bool) error {
	part, ok := p.(map[string]any)
	if !ok {
		return errType
	}
	typ, typed := part["type"]
	text := true
	if typed {
		s, ok := typ.(string)
		if !ok {
			return errType
		}
		text = len(s) <= 16 && textType([]byte(s), true)
	}
	for _, k := range []string{"content", "output"} {
		c, ok := part[k]
		if !ok || inner {
			continue
		}
		switch c.(type) {
		case string, []any:
			if err := refContent(out, c, true); err != nil {
				return err
			}
		}
	}
	if !text {
		return nil
	}
	switch t := part["text"].(type) {
	case nil:
	case string:
		out.prompt += int64(len(t))
	default:
		return errType
	}
	return nil
}

func refItem(out *ref, it any) (Role, error) {
	item, ok := it.(map[string]any)
	if !ok {
		return RoleNone, errType
	}
	rv, has := item["role"]
	r, err := refRole(rv, has, RoleNone)
	if err != nil {
		return r, err
	}
	var typ string
	if t, ok := item["type"]; ok {
		s, ok := t.(string)
		if !ok {
			return r, errType
		}
		if len(s) <= 32 {
			typ = s
		}
	}
	if c, ok := item["content"]; ok && c != nil {
		if err := refContent(out, c, false); err != nil {
			return r, err
		}
	}
	if o, ok := item["output"]; ok {
		switch o.(type) {
		case string, []any:
			if err := refContent(out, o, true); err != nil {
				return r, err
			}
		}
	}
	if a, ok := item["arguments"].(string); ok {
		out.prompt += int64(len(a))
	}
	if r == RoleNone {
		switch typ {
		case "function_call_output", "custom_tool_call_output", "computer_call_output", "local_shell_call_output", "mcp_approval_response":
			r = RoleTool
		case "function_call", "custom_tool_call":
			r = RoleAssistant
		}
	}
	return r, nil
}

func refTools(v any) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, errType
	}
	var names []string
	for _, t := range list {
		tool, ok := t.(map[string]any)
		if !ok {
			return nil, errType
		}
		name, hasName := "", false
		str := func(v any) (string, error) {
			s, ok := v.(string)
			if !ok {
				return "", errType
			}
			if len(s) > maxName {
				return "<nil>", nil
			}
			return s, nil
		}
		typ := "<nil>"
		if v, ok := tool["type"]; ok {
			s, err := str(v)
			if err != nil {
				return nil, err
			}
			typ = s
		}
		if v, ok := tool["name"]; ok {
			s, err := str(v)
			if err != nil {
				return nil, err
			}
			name, hasName = s, true
		}
		for _, k := range []string{"function", "custom"} {
			v, ok := tool[k]
			if !ok || v == nil {
				continue
			}
			fn, ok := v.(map[string]any)
			if !ok {
				return nil, errType
			}
			if v, ok := fn["name"]; ok {
				s, err := str(v)
				if err != nil {
					return nil, err
				}
				// The last of name, function and custom in the body wins;
				// a body with both is rare, so the test bodies don't mix
				// them (seeds) and the comparison skips them.
				name, hasName = s, true
			}
		}
		if !hasName {
			name = typ
		}
		names = append(names, name)
	}
	return names, nil
}

// mixedToolNames reports whether body has a tool with more than one of
// name, function.name and custom.name, whose name is then the last one
// in the body, which encoding/json's maps don't keep.
func mixedToolNames(body []byte) bool {
	n := 0
	for _, k := range []string{`"name"`, `"function"`, `"custom"`} {
		if bytes.Contains(body, []byte(k)) {
			n++
		}
	}
	return n > 1 || bytes.Contains(body, []byte(`\u`))
}

func seeds() []string {
	return []string{
		`{"model":"gpt-4o","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":[{"type":"text","text":"hello"}]}],"max_tokens":100,"n":2,"stream":true}`,
		`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"function":{"arguments":"{}"}}]},{"role":"tool","content":"42"}],"tools":[{"type":"function","function":{"name":"f"}}]}`,
		`{"model":"m","instructions":"x","input":[{"role":"user","content":[{"type":"input_text","text":"q"}]},{"type":"function_call_output","output":"r"}],"max_output_tokens":5}`,
		`{"input":["a","b"]}`, `{"input":[[1,2],[3]]}`, `{"input":[1,2]}`, `{"input":"x"}`,
		`{"system":[{"type":"text","text":"s"}],"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"t"}]}]}],"max_tokens":9}`,
		`{"max_tokens":4.096e3,"n":1e30}`, `{"model":"a\u00e9\ud83d\ude00"}`, `{"x":[[[{"y":null}]]]}`,
		`{"model":"a","model":"b"}`, `{"max_tokens":1.5}`, `{"Model":"x","MESSAGES":[{"Role":"system"}],"Max_Tokens":5}`, "{\"\u017Ftream\":true,\"max_to\u212Aens\":9}", "{\"model\":\"\xff\"}", `{"a":[1,]}`,
	}
}

// goRequest is a request as a model server in Go decodes it into its
// structs (Ollama, LocalAI): encoding/json matches keys case-insensitively,
// with Unicode folding, and keeps the last.
type goRequest struct {
	Model               *string           `json:"model"`
	Messages            []json.RawMessage `json:"messages"`
	MaxTokens           *json.Number      `json:"max_tokens"`
	MaxCompletionTokens *json.Number      `json:"max_completion_tokens"`
	MaxOutputTokens     *json.Number      `json:"max_output_tokens"`
	N                   *json.Number      `json:"n"`
	Stream              *bool             `json:"stream"`
}

// goView compares what Parse read of body with what a Go server's structs
// read: the same model, messages, output limit, n and stream. It skips
// bodies such a server refuses (a type its struct can't take).
func goView(t *testing.T, body []byte, f Format, r *Request) {
	var g goRequest
	if err := json.Unmarshal(body, &g); err != nil {
		return
	}
	if g.Model != nil && len(*g.Model) <= MaxModelBytes && (!r.HasModel || string(r.Model()) != *g.Model) {
		t.Fatalf("a Go server reads model %q, Parse %q", *g.Model, r.Model())
	}
	if (f == OpenAIChat || f == AnthropicMessages) && int64(len(g.Messages)) != r.Messages {
		t.Fatalf("a Go server reads %d messages, Parse %d", len(g.Messages), r.Messages)
	}
	limit := map[Format]*json.Number{OpenAIResponses: g.MaxOutputTokens, AnthropicMessages: g.MaxTokens}[f]
	if f == OpenAIChat {
		limit = g.MaxCompletionTokens
		if limit == nil {
			limit = g.MaxTokens
		}
	}
	if limit != nil {
		if v, ok, err := refInt(*limit); err == nil && ok && (!r.HasOutputTokens || r.OutputTokens < v) {
			t.Fatalf("a Go server reads an output limit of %d, Parse %d (%v)", v, r.OutputTokens, r.HasOutputTokens)
		}
	}
	if f == OpenAIChat && g.N != nil {
		if v, ok, err := refInt(*g.N); err == nil && ok && r.Choices != v {
			t.Fatalf("a Go server reads n %d, Parse %d", v, r.Choices)
		}
	}
	if f != OpenAIEmbeddings && g.Stream != nil && *g.Stream != r.Stream {
		t.Fatalf("a Go server reads stream %v, Parse %v", *g.Stream, r.Stream)
	}
}

// FuzzParse: Parse never panics nor reads out of its bounds, refuses what
// encoding/json refuses, and on a body it accepts reads what encoding/json
// reads, into a map and into a Go server's structs.
func FuzzParse(f *testing.F) {
	for _, s := range seeds() {
		for _, format := range Formats {
			f.Add([]byte(s), uint8(format))
		}
	}
	f.Fuzz(func(t *testing.T, body []byte, format uint8) {
		fm := Formats[int(format)%len(Formats)]
		var r Request
		ok := Parse(body, fm, &r)
		if !ok {
			if !r.Malformed || r.Why == "" || r.Offset < 0 || r.Offset > len(body) {
				t.Fatalf("refused without a reason: %+v", r)
			}
			return
		}
		if !json.Valid(body) || !utf8.Valid(body) {
			t.Fatalf("accepted an invalid body")
		}
		if bytes.Count(body, []byte("[")) > 10000 {
			return // encoding/json's recursion, not ours
		}
		goView(t, body, fm, &r)
		want, err := refRead(body, fm)
		if errors.Is(err, errSkip) {
			return
		}
		if err != nil {
			t.Fatalf("accepted what encoding/json reads as %v", err)
		}
		var names []string
		r.eachTool(body, &toolSink{names: &names})
		var roles [numRoles]int
		for ro := RoleSystem; ro < numRoles; ro++ {
			if i, _, ok := r.FirstRole(ro); ok {
				roles[ro] = i + 2
			}
		}
		got := ref{model: string(r.Model()), hasModel: r.HasModel, modelTooLong: r.ModelTooLong, prompt: r.PromptBytes,
			messages: r.Messages, output: r.OutputTokens, hasOutput: r.HasOutputTokens, choices: r.Choices,
			hasChoices: r.HasChoices, stream: r.Stream, tools: names, roles: roles}
		if mixedToolNames(body) {
			got.tools, want.tools = nil, nil
		}
		if len(got.tools) == 0 {
			got.tools = nil
		}
		if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", want) {
			t.Fatalf("%s:\nparsed    %+v\nreference %+v", fm, got, want)
		}
		if r.Tools != len(names) {
			t.Fatalf("%d tools, %d names", r.Tools, len(names))
		}
		// The checks never panic either.
		rules, err := Compile(Config{Models: []string{"m*"}, MaxPromptBytes: 10, MaxMessages: 1, MaxOutputTokens: 10,
			RequireOutputTokens: true, MaxChoices: 1, ClientRoles: []Role{RoleUser}, Tools: ToolsListed, ToolNames: []string{"f"}})
		if err != nil {
			t.Fatal(err)
		}
		if f := rules.Check(body, &r, 0); f.Offset < 0 || f.Offset > len(body) {
			t.Fatalf("finding at %d", f.Offset)
		}
	})
}

// TestReference: the reference reads the parser's test bodies as the
// parser does, so FuzzParse's comparison means something.
func TestReference(t *testing.T) {
	for _, s := range seeds() {
		for _, f := range Formats {
			var r Request
			if !Parse([]byte(s), f, &r) {
				continue
			}
			if _, err := refRead([]byte(s), f); err != nil && !errors.Is(err, errSkip) {
				t.Errorf("%s %s: %v", f, s, err)
			}
		}
	}
	if !slices.Contains(seeds(), `{"input":"x"}`) {
		t.Fatal("seeds changed")
	}
}
