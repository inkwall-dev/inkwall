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
	var seen uint64
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
			_, found = p.usage(&u, 2)
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
	uPrompt uint64 = 1 << iota
	uCompletion
	uInput
	uOutput
	uCacheCreation
	uCacheRead
)

// usage reads the usage object at depth, and returns the fields it read.
func (p *parser) usage(u *Usage, depth int) (uint64, bool) {
	if p.isNull() {
		return 0, false
	}
	if !p.open('{', depth) {
		return 0, false
	}
	var seen uint64
	read := false
	add := func(to *int64, bit uint64) {
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
			return 0, false
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
			p.unread(k, depth+1, usageKeys[p.format])
		}
		if p.err {
			return 0, false
		}
	}
	return seen, read && !p.err
}

// StreamUsage is the usage a streamed response (Server-Sent Events)
// reports, event by event (Event): OpenAI Chat's last chunk's usage (sent
// when the request sets stream_options.include_usage), the Responses
// API's response.completed (or incomplete, failed) response's usage,
// Anthropic's message_start message's usage and message_delta's, which
// counts the output so far and replaces the start's. Its zero value is
// ready; it doesn't allocate.
type StreamUsage struct {
	u             Usage
	input, output bool
	final         bool
}

// Event reads one event's data, of a stream of format f. An event that
// isn't valid JSON, or reads as ParseUsage refuses, is ignored.
func (s *StreamUsage) Event(data []byte, f Format) {
	var scratch Request
	p := parser{b: data, out: &scratch, format: f}
	var u Usage
	var seen uint64
	found, final := false, false
	p.ws()
	if !p.open('{', 1) {
		return
	}
	var keys uint64
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return
		}
		switch {
		case string(k) == "usage" && (f == OpenAIChat || f == AnthropicMessages):
			if !p.once(&keys, fInput) {
				return
			}
			seen, found = p.usage(&u, 2)
			final = true
		case string(k) == "response" && f == OpenAIResponses || string(k) == "message" && f == AnthropicMessages:
			if !p.once(&keys, fMessages) {
				return
			}
			seen, found = p.inner(&u)
			final = f == OpenAIResponses
		default:
			p.unread(k, 2, eventKeys[f])
		}
		if p.err {
			return
		}
	}
	if p.ws(); p.err || p.i != len(p.b) || !found {
		return
	}
	if seen&(uPrompt|uInput|uCacheCreation|uCacheRead) != 0 {
		s.u.Input, s.input = u.Input, true
	}
	if seen&(uCompletion|uOutput) != 0 {
		s.u.Output, s.output = u.Output, true
	}
	s.final = s.final || final
}

// inner reads the object an event wraps its usage in (the Responses
// API's response, Anthropic's message) at depth 2, for its usage.
func (p *parser) inner(u *Usage) (seen uint64, found bool) {
	if p.isNull() || !p.open('{', 2) {
		return 0, false
	}
	var keys uint64
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return 0, false
		}
		if string(k) == "usage" {
			if !p.once(&keys, fInput) {
				return 0, false
			}
			seen, found = p.usage(u, 3)
		} else {
			p.unread(k, 3, usageTopKeys)
		}
		if p.err {
			return 0, false
		}
	}
	return seen, found && !p.err
}

// Usage returns the usage the events read reported, whether any did,
// and whether it is final: the stream's last usage came (OpenAI's, or
// Anthropic's message_delta), so it is the whole request's, not the
// part so far.
func (s *StreamUsage) Usage() (u Usage, ok, final bool) {
	return s.u, s.input || s.output, s.final
}

// eventKeys are the keys StreamUsage reads at the top of an event.
var eventKeys = [numFormats][]string{
	OpenAIChat:        {"usage"},
	OpenAIResponses:   {"response"},
	AnthropicMessages: {"usage", "message"},
}
