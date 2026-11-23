// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// ToolsAllow is which tools a client may define.
type ToolsAllow uint8

const (
	// ToolsAny allows any tool (the default).
	ToolsAny ToolsAllow = iota
	// ToolsNone allows none.
	ToolsNone
	// ToolsListed allows the tools Config.ToolNames lists.
	ToolsListed
)

// DefaultOutputTokens is a request's output tokens, for its token
// estimate, when neither the request nor its policy sets a limit.
const DefaultOutputTokens = 4096

// Limits of a Config, as WAFPolicy's spec.llm.request allows them.
const (
	MaxModels       = 64
	MaxToolNames    = 128
	MaxPromptCap    = 10 << 20
	MaxMessagesCap  = 100000
	MaxOutputCap    = 10000000
	MaxChoicesCap   = 128
	maxModelPattern = MaxModelBytes
)

// Config is a policy's request checks; the zero value checks nothing but
// that a body is well-formed.
type Config struct {
	// Models are the models allowed: exact, or a prefix ending in "*",
	// compared in ASCII lower case. Empty: any, and a request without one.
	Models []string
	// MaxPromptBytes caps Request.PromptBytes; 0: no cap.
	MaxPromptBytes int64
	// MaxMessages caps Request.Messages; 0: no cap.
	MaxMessages int64
	// MaxOutputTokens caps the output limit; 0: no cap.
	MaxOutputTokens int64
	// RequireOutputTokens refuses a request that sets no output limit.
	RequireOutputTokens bool
	// MaxChoices caps n; 0: no cap.
	MaxChoices int64
	// ClientRoles are the roles a client may send; empty: every role.
	// RoleNone stands for a role this engine doesn't know (of a newer
	// operator): it allows nothing, but makes the list one, so a list of
	// unknown roles only allows none rather than every role.
	ClientRoles []Role
	// Tools is which tools a client may define, ToolNames the ones
	// allowed with ToolsListed.
	Tools     ToolsAllow
	ToolNames []string
}

// Rules are a compiled Config. They are immutable and safe for concurrent
// use.
type Rules struct {
	models        []modelPattern
	maxPrompt     int64
	maxMessages   int64
	maxOutput     int64
	requireOutput bool
	maxChoices    int64
	roles         uint8 // allowed, by bit; 0: all
	tools         ToolsAllow
	toolNames     map[string]struct{}
}

type modelPattern struct {
	value  string // lower case
	prefix bool
}

// Compile checks and compiles c.
func Compile(c Config) (*Rules, error) {
	r := &Rules{maxPrompt: c.MaxPromptBytes, maxMessages: c.MaxMessages, maxOutput: c.MaxOutputTokens,
		requireOutput: c.RequireOutputTokens, maxChoices: c.MaxChoices, tools: c.Tools}
	if len(c.Models) > MaxModels {
		return nil, fmt.Errorf("%d models, at most %d", len(c.Models), MaxModels)
	}
	for _, m := range c.Models {
		value, prefix := strings.CutSuffix(m, "*")
		if value == "" || len(value) > maxModelPattern || strings.Contains(value, "*") {
			return nil, fmt.Errorf("model %q: want a model, or a prefix ending in *", m)
		}
		r.models = append(r.models, modelPattern{value: strings.ToLower(value), prefix: prefix})
	}
	for _, f := range []struct {
		name   string
		v, max int64
	}{
		{"maxPromptBytes", c.MaxPromptBytes, MaxPromptCap},
		{"maxMessages", c.MaxMessages, MaxMessagesCap},
		{"maxOutputTokens", c.MaxOutputTokens, MaxOutputCap},
		{"maxChoices", c.MaxChoices, MaxChoicesCap},
	} {
		if f.v < 0 || f.v > f.max {
			return nil, fmt.Errorf("%s %d: want 1 to %d", f.name, f.v, f.max)
		}
	}
	for _, ro := range c.ClientRoles {
		if ro >= RoleOther {
			return nil, fmt.Errorf("client role %d", ro)
		}
		r.roles |= 1 << ro
	}
	switch c.Tools {
	case ToolsAny, ToolsNone:
		if len(c.ToolNames) > 0 {
			return nil, errors.New("tool names need tools allowed Listed")
		}
	case ToolsListed:
		if len(c.ToolNames) == 0 || len(c.ToolNames) > MaxToolNames {
			return nil, fmt.Errorf("%d tool names: want 1 to %d", len(c.ToolNames), MaxToolNames)
		}
		r.toolNames = make(map[string]struct{}, len(c.ToolNames))
		for _, n := range c.ToolNames {
			if n == "" || len(n) > maxName {
				return nil, fmt.Errorf("tool name %q", n)
			}
			r.toolNames[n] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("tools allowed %d", c.Tools)
	}
	return r, nil
}

// Finding is the check a request failed, and where.
type Finding struct {
	// Check failed; CheckNone: none did.
	Check Check
	// MessageIndex is the message the check is about (-1 for a top-level
	// field, the instructions or Anthropic's system); Role its role.
	MessageIndex int
	Role         Role
	// Offset is where in the body the check failed: the malformed byte,
	// the role, the tool; 0 for the request as a whole.
	Offset int
}

// Status is the HTTP status the request is denied with.
func (f Finding) Status() int { return f.Check.Status() }

// Check returns the first check, in Checks order, that req, which Parse
// read from body, fails; off are checks turned off (by exclusions). A
// malformed request fails llm-malformed, and isn't checked further.
func (r *Rules) Check(body []byte, req *Request, off CheckSet) Finding {
	if req.Malformed {
		if off.Has(CheckMalformed) {
			return Finding{}
		}
		return Finding{Check: CheckMalformed, MessageIndex: -1, Offset: req.Offset}
	}
	if r == nil {
		return Finding{}
	}
	fail := func(c Check) bool { return !off.Has(c) }
	if len(r.models) > 0 && fail(CheckModel) && !r.modelAllowed(req) {
		return Finding{Check: CheckModel, MessageIndex: -1}
	}
	if r.maxPrompt > 0 && req.PromptBytes > r.maxPrompt && fail(CheckMaxPrompt) {
		return Finding{Check: CheckMaxPrompt, MessageIndex: -1}
	}
	if r.maxMessages > 0 && req.Messages > r.maxMessages && fail(CheckMaxMessages) {
		return Finding{Check: CheckMaxMessages, MessageIndex: int(min(r.maxMessages, math.MaxInt32))}
	}
	if r.maxChoices > 0 && req.HasChoices && req.Choices > r.maxChoices && fail(CheckMaxChoices) {
		return Finding{Check: CheckMaxChoices, MessageIndex: -1}
	}
	if fail(CheckMaxOutputTokens) && req.Format != OpenAIEmbeddings {
		if r.maxOutput > 0 && req.HasOutputTokens && req.OutputTokens > r.maxOutput || r.requireOutput && !req.HasOutputTokens {
			return Finding{Check: CheckMaxOutputTokens, MessageIndex: -1}
		}
	}
	if r.roles != 0 && fail(CheckClientRole) {
		var found Finding
		for ro := RoleSystem; ro < numRoles; ro++ {
			if r.roles&(1<<ro) != 0 {
				continue
			}
			if i, at, ok := req.FirstRole(ro); ok && (found.Check == CheckNone || i < found.MessageIndex) {
				found = Finding{Check: CheckClientRole, MessageIndex: i, Role: ro, Offset: at}
			}
		}
		if found.Check != CheckNone {
			return found
		}
	}
	if r.tools != ToolsAny && req.Tools > 0 && fail(CheckTools) {
		sink := toolSink{rules: r}
		req.eachTool(body, &sink)
		if sink.found {
			return Finding{Check: CheckTools, MessageIndex: sink.index, Offset: sink.offset}
		}
	}
	return Finding{}
}

// listed reports whether the tool name is listed.
func (r *Rules) listed(name []byte) bool {
	if name == nil {
		return false
	}
	_, ok := r.toolNames[string(name)]
	return ok
}

// modelAllowed reports whether req's model is one of the models.
func (r *Rules) modelAllowed(req *Request) bool {
	if !req.HasModel || req.ModelTooLong {
		return false
	}
	m := req.Model()
	for _, p := range r.models {
		if p.prefix && len(m) >= len(p.value) && equalFold(m[:len(p.value)], p.value) ||
			!p.prefix && equalFold(m, p.value) {
			return true
		}
	}
	return false
}

// equalFold reports whether b equals s, lower case, in ASCII lower case.
func equalFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != s[i] {
			return false
		}
	}
	return true
}

// OutputTokens is the output tokens a token estimate charges req: its
// output limit, else the policy's cap, else DefaultOutputTokens; none for
// embeddings.
func (r *Rules) OutputTokens(req *Request) int64 {
	switch {
	case req.Format == OpenAIEmbeddings:
		return 0
	case req.HasOutputTokens:
		return req.OutputTokens
	case r != nil && r.maxOutput > 0:
		return r.maxOutput
	}
	return DefaultOutputTokens
}

// EstimatedTokens is req's tokens as charged at request time: its prompt's
// bytes divided by 3, rounded up, plus its output tokens (OutputTokens),
// saturated at MaxInt64. Inkwall has no tokenizer: bytes ÷ 3 overestimates
// English (about 4 bytes a token) and is close for code and CJK text.
func (r *Rules) EstimatedTokens(req *Request) int64 {
	in := (req.PromptBytes + 2) / 3
	out := r.OutputTokens(req)
	if out > math.MaxInt64-in {
		return math.MaxInt64
	}
	return in + out
}
