// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import "math"

// Usage is the tokens a whole response says the request used.
type Usage struct {
	Input, Output int64
}

// Total is Input plus Output, saturated.
func (u Usage) Total() int64 {
	if u.Output > math.MaxInt64-u.Input {
		return math.MaxInt64
	}
	return u.Input + u.Output
}

// ParseUsage reads the usage a whole (not streamed) response of format f
// reports (design 0012 §6): usage.prompt_tokens and completion_tokens
// (OpenAI Chat and Embeddings), usage.input_tokens and output_tokens
// (Responses, Anthropic, whose cache_creation_input_tokens and
// cache_read_input_tokens count as input). It reports false for a body
// that isn't valid JSON, has no usage, gives it another type, repeats it,
// or has a key that differs from one it reads only in case (a client in Go
// would read "Usage" or "PROMPT_TOKENS" as it, as the request parser
// refuses them): the request's estimate then stands. It doesn't allocate.
func ParseUsage(body []byte, f Format) (Usage, bool) {
	var scratch Request
	p := parser{b: body, out: &scratch, format: f}
	var u Usage
	found := false
	p.ws()
	if !p.open('{', 1) {
		return Usage{}, false
	}
	var seen uint32
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return Usage{}, false
		}
		switch {
		case string(k) != "usage":
			p.unread(k, 2, usageTopKeys)
		case !p.once(&seen, fInput):
			return Usage{}, false
		default:
			found = p.usage(&u)
		}
		if p.err {
			return Usage{}, false
		}
	}
	if p.ws(); p.err || p.i != len(p.b) || !found {
		return Usage{}, false
	}
	return u, true
}

// The keys ParseUsage reads, at the top and in usage, which a key Go's
// encoding/json would read as one of them may not imitate (unread).
var (
	usageTopKeys = []string{"usage"}
	usageKeys    = [numFormats][]string{
		OpenAIChat:        {"prompt_tokens", "completion_tokens"},
		OpenAIResponses:   {"input_tokens", "output_tokens"},
		OpenAIEmbeddings:  {"prompt_tokens"},
		AnthropicMessages: {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"},
	}
)

// usage fields, by bit.
const (
	uPrompt uint32 = 1 << iota
	uCompletion
	uInput
	uOutput
	uCacheCreation
	uCacheRead
)

// usage reads the usage object.
func (p *parser) usage(u *Usage) bool {
	if p.isNull() {
		return false
	}
	if !p.open('{', 2) {
		return false
	}
	var seen uint32
	read := false
	add := func(to *int64, bit uint32) {
		if !p.once(&seen, bit) {
			return
		}
		if n, ok := p.integer(); ok {
			if n > math.MaxInt64-*to {
				n = math.MaxInt64 - *to
			}
			*to += n
			read = true
		}
	}
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return false
		}
		switch f := p.format; {
		case string(k) == "prompt_tokens" && (f == OpenAIChat || f == OpenAIEmbeddings):
			add(&u.Input, uPrompt)
		case string(k) == "completion_tokens" && f == OpenAIChat:
			add(&u.Output, uCompletion)
		case string(k) == "input_tokens" && (f == OpenAIResponses || f == AnthropicMessages):
			add(&u.Input, uInput)
		case string(k) == "output_tokens" && (f == OpenAIResponses || f == AnthropicMessages):
			add(&u.Output, uOutput)
		case string(k) == "cache_creation_input_tokens" && f == AnthropicMessages:
			add(&u.Input, uCacheCreation)
		case string(k) == "cache_read_input_tokens" && f == AnthropicMessages:
			add(&u.Input, uCacheRead)
		default:
			p.unread(k, 3, usageKeys[p.format])
		}
		if p.err {
			return false
		}
	}
	return read && !p.err
}
