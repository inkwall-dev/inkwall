// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package llm reads the requests of LLM APIs (OpenAI Chat Completions,
// Responses and Embeddings, Anthropic Messages) and checks them against a
// policy's caps (docs/design/0012): the model, the prompt's size, the
// messages, the choices, the output limit, the roles a client sends and
// the tools it defines.
//
// Parse reads a body once with a strict, bounded JSON reader: no
// reflection, no map, no recursion over the body, no allocation. It keeps
// what the checks need (the model, the numbers, the roles seen, where the
// tools are), never the prompt's text: the checks count its bytes. A body
// that isn't valid JSON or UTF-8, nests deeper than MaxDepth, gives a field
// read here another type, or repeats such a field is malformed: a model
// server that reads it differently would see another request than the one
// checked.
package llm

import "strings"

// Format is the shape of an LLM API's requests.
type Format uint8

const (
	// FormatUnknown is no format: an endpoint of a format this engine
	// doesn't know is checked as every format it knows.
	FormatUnknown Format = iota
	// OpenAIChat is OpenAI's Chat Completions (/v1/chat/completions), as
	// most OpenAI-compatible servers serve it.
	OpenAIChat
	// OpenAIResponses is OpenAI's Responses (/v1/responses).
	OpenAIResponses
	// OpenAIEmbeddings is OpenAI's Embeddings (/v1/embeddings).
	OpenAIEmbeddings
	// AnthropicMessages is Anthropic's Messages (/v1/messages).
	AnthropicMessages
	numFormats
)

// Formats are the formats this engine reads, in order.
var Formats = [...]Format{OpenAIChat, OpenAIResponses, OpenAIEmbeddings, AnthropicMessages}

// String is the format's name in the API (spec.llm.endpoints[].format).
func (f Format) String() string {
	switch f {
	case OpenAIChat:
		return "OpenAIChat"
	case OpenAIResponses:
		return "OpenAIResponses"
	case OpenAIEmbeddings:
		return "OpenAIEmbeddings"
	case AnthropicMessages:
		return "AnthropicMessages"
	}
	return "Unknown"
}

// label is the format's metric label.
func (f Format) label() string {
	switch f {
	case OpenAIChat:
		return "openai_chat"
	case OpenAIResponses:
		return "openai_responses"
	case OpenAIEmbeddings:
		return "openai_embeddings"
	case AnthropicMessages:
		return "anthropic_messages"
	}
	return "unknown"
}

// Role is who wrote a message: the roles a client may send are a check
// (Config.ClientRoles).
type Role uint8

const (
	// RoleNone is no role: a field that isn't a message.
	RoleNone Role = iota
	// RoleSystem is the system prompt: a system message, the Responses
	// API's instructions, Anthropic's system.
	RoleSystem
	// RoleDeveloper is OpenAI's developer message, the system prompt of
	// its newer models.
	RoleDeveloper
	// RoleUser is the user's message.
	RoleUser
	// RoleAssistant is the model's earlier answer, sent back as history.
	RoleAssistant
	// RoleTool is a tool's result (and OpenAI's older function role).
	RoleTool
	// RoleOther is a role none of the above: allowed only when every role
	// is.
	RoleOther
	numRoles
)

// String is the role's name, as the APIs write it.
func (r Role) String() string {
	switch r {
	case RoleSystem:
		return "system"
	case RoleDeveloper:
		return "developer"
	case RoleUser:
		return "user"
	case RoleAssistant:
		return "assistant"
	case RoleTool:
		return "tool"
	case RoleOther:
		return "other"
	}
	return ""
}

// ParseRole returns the role named s (spec.llm.request.clientRoles).
func ParseRole(s string) (Role, bool) {
	switch strings.ToLower(s) {
	case "system":
		return RoleSystem, true
	case "developer":
		return RoleDeveloper, true
	case "user":
		return RoleUser, true
	case "assistant":
		return RoleAssistant, true
	case "tool":
		return RoleTool, true
	}
	return RoleNone, false
}

// roleOf is the role a message names.
func roleOf(s []byte) Role {
	switch string(s) {
	case "system":
		return RoleSystem
	case "developer":
		return RoleDeveloper
	case "user":
		return RoleUser
	case "assistant":
		return RoleAssistant
	case "tool", "function":
		return RoleTool
	}
	return RoleOther
}

// Check is one of the request checks, with a stable name and rule ID.
type Check uint8

const (
	// CheckNone is no check: the request passed.
	CheckNone Check = iota
	// CheckMalformed fails when the body isn't one the parser reads one way.
	CheckMalformed
	// CheckModel fails when the model is missing or not allowed.
	CheckModel
	// CheckMaxPrompt fails when the prompt's text is over its cap.
	CheckMaxPrompt
	// CheckMaxMessages fails on more messages, input items or inputs than the cap.
	CheckMaxMessages
	// CheckMaxChoices fails when n is over its cap.
	CheckMaxChoices
	// CheckMaxOutputTokens fails when the output limit is over its cap, or missing
	// where one is required.
	CheckMaxOutputTokens
	// CheckClientRole fails on a message of a role clients may not send.
	CheckClientRole
	// CheckTools fails on tools the client may not define.
	CheckTools
	numChecks
)

// Checks are the request checks in the order they're decided: the first
// that fails decides.
var Checks = [...]Check{CheckMalformed, CheckModel, CheckMaxPrompt, CheckMaxMessages, CheckMaxChoices,
	CheckMaxOutputTokens, CheckClientRole, CheckTools}

// RuleIDMin and RuleIDMax bound the rule IDs reserved for the LLM checks,
// which exclusions name (spec.exclusions[].ruleIDs): rule sets may not use
// them.
const (
	RuleIDMin = 4800000
	RuleIDMax = 4800999
)

// String is the check's name, as events and metrics name it.
func (c Check) String() string {
	switch c {
	case CheckMalformed:
		return "llm-malformed"
	case CheckModel:
		return "llm-model"
	case CheckMaxPrompt:
		return "llm-max-prompt"
	case CheckMaxMessages:
		return "llm-max-messages"
	case CheckMaxChoices:
		return "llm-max-choices"
	case CheckMaxOutputTokens:
		return "llm-max-output-tokens"
	case CheckClientRole:
		return "llm-client-role"
	case CheckTools:
		return "llm-tools"
	}
	return ""
}

// RuleID is the check's reserved rule ID, 0 for CheckNone.
func (c Check) RuleID() int {
	if c == CheckNone || c >= numChecks {
		return 0
	}
	return RuleIDMin + int(c) - 1
}

// CheckOf returns the check whose rule ID is id.
func CheckOf(id int) (Check, bool) {
	if id < RuleIDMin || id > RuleIDMax {
		return CheckNone, false
	}
	c := Check(id - RuleIDMin + 1) // #nosec G115 -- id is in the reserved range, checked above
	if c >= numChecks {
		return CheckNone, false
	}
	return c, true
}

// Status is the HTTP status a request the check fails is denied with: 413
// for the size caps, 400 for the others.
func (c Check) Status() int {
	switch c {
	case CheckMaxPrompt, CheckMaxMessages:
		return 413
	}
	return 400
}

// CheckSet is a set of checks.
type CheckSet uint16

// Has reports whether c is in s.
func (s CheckSet) Has(c Check) bool { return s&(1<<c) != 0 }

// With returns s with c.
func (s CheckSet) With(c Check) CheckSet { return s | 1<<c }
