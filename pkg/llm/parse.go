// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"math"
	"unicode/utf8"
)

// MaxDepth is how deep a body may nest arrays and objects; the top-level
// object is at depth 1.
const MaxDepth = 64

// MaxModelBytes is the longest model a request is compared with the
// allowed models by; a longer one matches none.
const MaxModelBytes = 256

// MaxBodyBytes is the largest body Parse reads (offsets are int32).
const MaxBodyBytes = 1 << 30

// maxKey is the longest key, as sent, that is read: the longest key read
// is 21 bytes, at most 6 bytes each when escaped.
const maxKey = 128

// maxName is the longest tool name compared with the listed ones; a longer
// one is never listed.
const maxName = 256

// roleSeen is where a role was first seen.
type roleSeen struct {
	index  int32 // the message's index, -1 for a top-level field
	offset int32
}

// span is a part of the body, by offsets.
type span struct{ start, end int32 }

// Request is what Parse read of a request. Its zero value is ready for
// Parse, which resets it; Parse doesn't allocate.
type Request struct {
	// Format is the format the body was read as.
	Format Format

	// Model is the model the request names, unescaped (Model); HasModel
	// whether it names one, ModelTooLong whether it was longer than
	// MaxModelBytes (then Model is empty).
	model        [MaxModelBytes]byte
	modelLen     int
	HasModel     bool
	ModelTooLong bool

	// PromptBytes are the UTF-8 bytes of the prompt's text, every message
	// together (token arrays count 4 bytes a token).
	PromptBytes int64
	// Messages are the messages, input items or embedding inputs.
	Messages int64
	// OutputTokens is the output limit the request sets, if HasOutputTokens
	// (the larger of max_tokens and max_completion_tokens when a chat
	// request sets both).
	OutputTokens    int64
	HasOutputTokens bool
	// Choices is n, if HasChoices.
	Choices    int64
	HasChoices bool
	// Stream is whether the request asks for a streamed answer.
	Stream bool
	// Tools are the tools the request defines.
	Tools int

	roles [numRoles]roleSeen
	seen  uint8 // roles seen, by bit
	// toolSpans are the arrays of tool definitions (tools, and chat's
	// older functions), which the tools check reads again.
	toolSpans [2]span
	nTools    int

	// Malformed: the body isn't one Parse reads one way, for Why, at byte
	// Offset.
	Malformed bool
	Offset    int
	Why       string
}

// Model returns the model, unescaped.
func (r *Request) Model() []byte { return r.model[:r.modelLen] }

// FirstRole reports whether the request has a message of role ro, and the
// first one's index (-1 for a top-level field: the Responses API's
// instructions, Anthropic's system) and offset in the body.
func (r *Request) FirstRole(ro Role) (index, offset int, ok bool) {
	if ro >= numRoles || r.seen&(1<<ro) == 0 {
		return 0, 0, false
	}
	return int(r.roles[ro].index), int(r.roles[ro].offset), true
}

func (r *Request) addRole(ro Role, index int64, offset int) {
	if ro == RoleNone || r.seen&(1<<ro) != 0 {
		return
	}
	r.seen |= 1 << ro
	r.roles[ro] = roleSeen{index: int32(min(index, math.MaxInt32)), offset: int32(offset)} // #nosec G115 -- bounded
}

// parser reads one body. It lives on the stack.
type parser struct {
	b      []byte
	i      int
	err    bool
	at     int
	why    string
	out    *Request
	format Format
	keyb   [maxKey]byte
}

// Parse reads body as f into out. It returns false when body is malformed
// (out.Malformed, Offset and Why say where and why).
func Parse(body []byte, f Format, out *Request) bool {
	*out = Request{Format: f}
	if len(body) > MaxBodyBytes {
		out.Malformed, out.Why = true, "body too large"
		return false
	}
	p := parser{b: body, out: out, format: f}
	p.top()
	if p.err {
		out.Malformed, out.Offset, out.Why = true, p.at, p.why
		return false
	}
	return true
}

func (p *parser) fail(why string) {
	if !p.err {
		p.err, p.at, p.why = true, min(p.i, len(p.b)), why
	}
}

// ws skips white space.
func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// peek returns the next byte after white space, 0 at the end.
func (p *parser) peek() byte {
	p.ws()
	if p.i >= len(p.b) {
		return 0
	}
	return p.b[p.i]
}

// next steps through a container's members or elements: it returns
// whether another one follows (and consumes the comma before it), or
// consumes the closing byte. first is true before the first.
func (p *parser) next(first *bool, closing byte) bool {
	c := p.peek()
	if *first {
		*first = false
		if c == closing {
			p.i++
			return false
		}
		if c == 0 {
			p.fail("unexpected end")
			return false
		}
		return true
	}
	switch c {
	case closing:
		p.i++
		return false
	case ',':
		p.i++
		p.ws()
		return true
	case 0:
		p.fail("unexpected end")
	default:
		p.fail("expected , or " + string(closing))
	}
	return false
}

// open consumes c, which opens a container at depth.
func (p *parser) open(c byte, depth int) bool {
	if p.peek() != c {
		p.fail("wrong type")
		return false
	}
	if depth > MaxDepth {
		p.fail("nested too deep")
		return false
	}
	p.i++
	return true
}

// isNull consumes a null, if one is next.
func (p *parser) isNull() bool {
	if p.peek() == 'n' {
		p.literal("null")
		return true
	}
	return false
}

func (p *parser) literal(lit string) {
	if len(p.b)-p.i < len(lit) || string(p.b[p.i:p.i+len(lit)]) != lit {
		p.fail("invalid literal")
		return
	}
	p.i += len(lit)
}

// plain marks the bytes a string's fast path stops at: quote, backslash,
// control characters and non-ASCII.
var plain = func() (t [256]bool) {
	for c := 0x20; c < 0x80; c++ {
		t[c] = c != '"' && c != '\\'
	}
	return t
}()

// str reads a string, at its opening quote. It returns its contents as
// sent (start, end), its length unescaped in UTF-8, and whether it has
// escapes. A string must be valid UTF-8 and escape no lone surrogate.
func (p *parser) str() (start, end int, n int64, esc bool) {
	if p.peek() != '"' {
		p.fail("wrong type")
		return
	}
	p.i++
	start = p.i
	b := p.b
	i := p.i
	for {
		for i < len(b) && plain[b[i]] {
			i++
		}
		if i >= len(b) {
			p.i = i
			p.fail("unterminated string")
			return
		}
		switch c := b[i]; {
		case c == '"':
			p.i = i + 1
			return start, i, n + int64(i-start), esc
		case c == '\\':
			l, m := p.escape(i)
			if m == 0 {
				return
			}
			esc = true
			// m bytes as sent stand for l unescaped: count the difference
			// now, the rest as sent at the end.
			n += int64(l - m)
			i += m
		case c < 0x20:
			p.i = i
			p.fail("control character in string")
			return
		default:
			r, size := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && size == 1 {
				p.i = i
				p.fail("invalid UTF-8")
				return
			}
			i += size
		}
	}
}

// escape reads the escape at b[i] ('\\'). It returns its length unescaped
// in UTF-8 and as sent; m is 0 for an invalid one.
func (p *parser) escape(i int) (l, m int) {
	b := p.b
	if i+1 >= len(b) {
		p.i = i
		p.fail("unterminated string")
		return 0, 0
	}
	switch b[i+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return 1, 2
	case 'u':
		r, ok := hex4(b, i+2)
		if !ok {
			p.i = i
			p.fail("invalid escape")
			return 0, 0
		}
		switch {
		case r >= 0xD800 && r < 0xDC00:
			// A high surrogate needs its low one.
			lo, ok := hex4(b, i+8)
			if !ok || b[i+6] != '\\' || b[i+7] != 'u' || lo < 0xDC00 || lo > 0xDFFF {
				p.i = i
				p.fail("lone surrogate")
				return 0, 0
			}
			return 4, 12
		case r >= 0xDC00 && r <= 0xDFFF:
			p.i = i
			p.fail("lone surrogate")
			return 0, 0
		}
		return utf8.RuneLen(r), 6
	}
	p.i = i
	p.fail("invalid escape")
	return 0, 0
}

// hex4 reads 4 hex digits at b[i].
func hex4(b []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[i : i+4] {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// unescape appends the unescaped form of src, a string's contents that
// str found valid, to dst.
func unescape(dst, src []byte) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c != '\\' {
			dst = append(dst, c)
			continue
		}
		i++
		switch src[i] {
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case 't':
			dst = append(dst, '\t')
		case 'u':
			r, _ := hex4(src, i+1)
			i += 4
			if r >= 0xD800 && r < 0xDC00 {
				lo, _ := hex4(src, i+3)
				r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
				i += 6
			}
			dst = utf8.AppendRune(dst, r)
		default: // " \ /
			dst = append(dst, src[i])
		}
	}
	return dst
}

// key reads a member's key and its colon. It returns the key unescaped, or
// nil for a key too long to be one that is read.
func (p *parser) key() []byte {
	start, end, _, esc := p.str()
	if p.err {
		return nil
	}
	if p.peek() != ':' {
		p.fail("expected :")
		return nil
	}
	p.i++
	if !esc {
		return p.b[start:end]
	}
	if end-start > maxKey {
		return nil
	}
	return unescape(p.keyb[:0], p.b[start:end])
}

// text reads a string value, or skips a null: n is its length unescaped.
func (p *parser) text() (n int64, ok bool) {
	if p.isNull() {
		return 0, false
	}
	_, _, n, _ = p.str()
	return n, !p.err
}

// integer reads a non-negative integer value, or a null: a number with a
// fraction or a negative one is the wrong type. A float that is an integer
// (4096.0, 4.096e3) reads as one, as servers in Python read it. A value
// over MaxInt64 reads as MaxInt64.
func (p *parser) integer() (v int64, ok bool) {
	if p.isNull() {
		return 0, false
	}
	c := p.peek()
	if c != '-' && (c < '0' || c > '9') {
		p.fail("wrong type")
		return 0, false
	}
	n := p.number()
	if p.err {
		return 0, false
	}
	v, integral, neg := n.value(p.b)
	if !integral || neg && v != 0 {
		p.i = n.start
		p.fail("not a count")
		return 0, false
	}
	return v, true
}

// boolean reads true or false, or a null.
func (p *parser) boolean() (v, ok bool) {
	switch p.peek() {
	case 't':
		p.literal("true")
		return true, !p.err
	case 'f':
		p.literal("false")
		return false, !p.err
	case 'n':
		p.literal("null")
		return false, false
	}
	p.fail("wrong type")
	return false, false
}

// num is a number's parts, by offset: its integer and fraction digits and
// its exponent.
type num struct {
	start, intStart, intEnd, fracStart, fracEnd int
	exp                                         int
	neg                                         bool
}

// maxExp bounds the exponents counted: a larger one saturates the value.
const maxExp = 1 << 20

// number reads a number, checking JSON's grammar.
func (p *parser) number() num {
	b := p.b
	n := num{start: p.i}
	i := p.i
	if i < len(b) && b[i] == '-' {
		n.neg = true
		i++
	}
	n.intStart = i
	switch {
	case i < len(b) && b[i] == '0':
		i++
	case i < len(b) && b[i] >= '1' && b[i] <= '9':
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
	default:
		p.i = i
		p.fail("invalid number")
		return n
	}
	n.intEnd = i
	n.fracStart, n.fracEnd = i, i
	if i < len(b) && b[i] == '.' {
		i++
		n.fracStart = i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == n.fracStart {
			p.i = i
			p.fail("invalid number")
			return n
		}
		n.fracEnd = i
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		sign := 1
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			if b[i] == '-' {
				sign = -1
			}
			i++
		}
		d := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			if n.exp < maxExp {
				n.exp = n.exp*10 + int(b[i]-'0')
			}
			i++
		}
		if i == d {
			p.i = i
			p.fail("invalid number")
			return n
		}
		n.exp = min(n.exp, maxExp) * sign
	}
	p.i = i
	return n
}

// value returns the number's value when it is an integer, saturated at
// MaxInt64.
func (n num) value(b []byte) (v int64, integral, neg bool) {
	ni := n.intEnd - n.intStart
	nd := ni + n.fracEnd - n.fracStart
	digit := func(k int) byte {
		if k < ni {
			return b[n.intStart+k]
		}
		return b[n.fracStart+k-ni]
	}
	point := ni + n.exp
	integral = true
	for k := max(point, 0); k < nd; k++ {
		if digit(k) != '0' {
			integral = false
			break
		}
	}
	for k := 0; k < point; k++ {
		if k >= nd && v == 0 {
			break
		}
		var d int64
		if k < nd {
			d = int64(digit(k) - '0')
		}
		if v > (math.MaxInt64-d)/10 {
			v = math.MaxInt64
			break
		}
		v = v*10 + d
	}
	return v, integral, n.neg
}

// skip reads any value, at depth (a container it opens is at depth),
// checking it without recursion.
func (p *parser) skip(depth int) {
	// stack holds, by bit, whether each container open is an object.
	var stack uint64
	n := 0
	for {
		c := p.peek()
		switch {
		case c == '{' || c == '[':
			if depth+n > MaxDepth {
				p.fail("nested too deep")
				return
			}
			p.i++
			closing := byte(']')
			if c == '{' {
				stack |= 1 << n
				closing = '}'
			} else {
				stack &^= 1 << n
			}
			n++
			if p.peek() == closing {
				p.i++
				n--
				break
			}
			if c == '{' {
				p.key()
				if p.err {
					return
				}
			}
			continue
		case c == '"':
			p.str()
		case c == 't':
			p.literal("true")
		case c == 'f':
			p.literal("false")
		case c == 'n':
			p.literal("null")
		case c == '-' || c >= '0' && c <= '9':
			p.number()
		case c == 0:
			p.fail("unexpected end")
		default:
			p.fail("invalid value")
		}
		// After a value: close the containers it ends, or go on with the
		// next member or element.
		for !p.err && n > 0 {
			obj := stack&(1<<(n-1)) != 0
			closing := byte(']')
			if obj {
				closing = '}'
			}
			c := p.peek()
			if c == closing {
				p.i++
				n--
				continue
			}
			if c != ',' {
				p.fail("expected , or " + string(closing))
				return
			}
			p.i++
			if obj {
				p.key()
			}
			break
		}
		if p.err || n == 0 {
			return
		}
	}
}

// fields are the keys read, by bit, to refuse a key twice.
const (
	fModel uint32 = 1 << iota
	fMessages
	fMaxTokens
	fMaxCompletionTokens
	fN
	fStream
	fTools
	fFunctions
	fInput
	fInstructions
	fMaxOutputTokens
	fSystem
	fRole
	fContent
	fToolCalls
	fFunctionCall
	fType
	fText
	fOutput
	fArguments
	fFunction
	fName
	fCustom
	fReasoning
	fReasoningContent
	fRefusal
	fThinking
)

// The keys each object read has, which a key Go's encoding/json would
// read as one of them may not imitate (unread).
var (
	topKeys = [numFormats][]string{
		OpenAIChat:        {"model", "messages", "max_tokens", "max_completion_tokens", "n", "stream", "tools", "functions"},
		OpenAIResponses:   {"model", "input", "instructions", "max_output_tokens", "stream", "tools"},
		OpenAIEmbeddings:  {"model", "input"},
		AnthropicMessages: {"model", "messages", "max_tokens", "stream", "tools", "system"},
	}
	messageKeys  = []string{"role", "content", "tool_calls", "function_call", "reasoning", "reasoning_content", "refusal"}
	partKeys     = []string{"type", "text", "content", "output", "thinking", "refusal"}
	toolCallKeys = []string{"function"}
	functionKeys = []string{"arguments"}
	itemKeys     = []string{"role", "type", "content", "output", "arguments"}
	toolKeys     = []string{"name", "type", "function", "custom"}
	nestedKeys   = []string{"name"}
)

// unread skips the value of k, a key the object's reading doesn't read,
// at depth, unless Go's encoding/json would read it as one of the keys
// read: its decoders match keys case-insensitively, with Unicode folding
// (the Kelvin sign for k, the long s for s), and keep the last, so a
// server in Go (Ollama, LocalAI) would read "Messages" or "MAX_TOKENS"
// after this parser read "messages" and "max_tokens". Such a key is
// malformed.
func (p *parser) unread(k []byte, depth int, keys []string) {
	for _, known := range keys {
		if foldsTo(k, known) {
			p.fail("a key differing only in case from one read")
			return
		}
	}
	p.skip(depth)
}

// foldsTo reports whether k isn't known, an ASCII key, but equals it in
// Unicode simple case folding, as encoding/json compares keys.
func foldsTo(k []byte, known string) bool {
	if string(k) == known || len(k) < len(known) {
		return false
	}
	i := 0
	for _, c := range []byte(known) {
		if i >= len(k) {
			return false
		}
		r, size := rune(k[i]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(k[i:])
		}
		i += size
		switch {
		case r == rune(c):
		case 'a' <= c && c <= 'z' && r == rune(c-'a'+'A'):
		case c == 'k' && r == '\u212A', c == 's' && r == '\u017F':
		default:
			return false
		}
	}
	return i == len(k)
}

// once refuses a key read twice in one object: parsers keep the first or
// the last, so a server could read the one this parser didn't.
func (p *parser) once(seen *uint32, f uint32) bool {
	if *seen&f != 0 {
		p.fail("duplicate key")
		return false
	}
	*seen |= f
	return true
}

func (p *parser) top() {
	p.ws()
	if !p.open('{', 1) {
		if !p.err {
			p.fail("not a JSON object")
		}
		return
	}
	var seen uint32
	var maxTokens, maxCompletion int64
	var hasMaxTokens, hasMaxCompletion bool
	out := p.out
	first := true
	for p.next(&first, '}') {
		keyAt := p.i
		k := p.key()
		if p.err {
			return
		}
		f := p.format
		switch {
		case string(k) == "model":
			if !p.once(&seen, fModel) {
				return
			}
			p.model()
		case string(k) == "stream" && f != OpenAIEmbeddings:
			if !p.once(&seen, fStream) {
				return
			}
			out.Stream, _ = p.boolean()
		case string(k) == "messages" && (f == OpenAIChat || f == AnthropicMessages):
			if !p.once(&seen, fMessages) {
				return
			}
			p.messages()
		case string(k) == "max_tokens" && (f == OpenAIChat || f == AnthropicMessages):
			if !p.once(&seen, fMaxTokens) {
				return
			}
			maxTokens, hasMaxTokens = p.integer()
		case string(k) == "max_completion_tokens" && f == OpenAIChat:
			if !p.once(&seen, fMaxCompletionTokens) {
				return
			}
			maxCompletion, hasMaxCompletion = p.integer()
		case string(k) == "max_output_tokens" && f == OpenAIResponses:
			if !p.once(&seen, fMaxOutputTokens) {
				return
			}
			out.OutputTokens, out.HasOutputTokens = p.integer()
		case string(k) == "n" && f == OpenAIChat:
			if !p.once(&seen, fN) {
				return
			}
			out.Choices, out.HasChoices = p.integer()
		case string(k) == "tools" && f != OpenAIEmbeddings:
			if !p.once(&seen, fTools) {
				return
			}
			p.tools(0)
		case string(k) == "functions" && f == OpenAIChat:
			if !p.once(&seen, fFunctions) {
				return
			}
			p.tools(1)
		case string(k) == "input" && (f == OpenAIResponses || f == OpenAIEmbeddings):
			if !p.once(&seen, fInput) {
				return
			}
			if f == OpenAIEmbeddings {
				p.embeddingInput()
			} else {
				p.responsesInput()
			}
		case string(k) == "instructions" && f == OpenAIResponses:
			if !p.once(&seen, fInstructions) {
				return
			}
			if n, ok := p.text(); ok {
				out.PromptBytes += n
				out.addRole(RoleSystem, -1, keyAt)
			}
		case string(k) == "system" && f == AnthropicMessages:
			if !p.once(&seen, fSystem) {
				return
			}
			if p.isNull() {
				break
			}
			out.addRole(RoleSystem, -1, keyAt)
			p.content(2, false)
		default:
			p.unread(k, 2, topKeys[p.format])
		}
		if p.err {
			return
		}
	}
	if p.err {
		return
	}
	if p.ws(); p.i != len(p.b) {
		p.fail("data after the object")
		return
	}
	switch {
	case hasMaxTokens && hasMaxCompletion:
		out.OutputTokens, out.HasOutputTokens = max(maxTokens, maxCompletion), true
	case hasMaxCompletion:
		out.OutputTokens, out.HasOutputTokens = maxCompletion, true
	case hasMaxTokens:
		out.OutputTokens, out.HasOutputTokens = maxTokens, true
	}
}

// roleValue is the role of a message whose role, as sent, is
// b[start:end].
func (p *parser) roleValue(start, end int, esc bool) Role {
	if !esc {
		return roleOf(p.b[start:end])
	}
	if end-start > maxKey {
		return RoleOther
	}
	return roleOf(unescape(p.keyb[:0], p.b[start:end]))
}

// model reads the model, a string or null.
func (p *parser) model() {
	if p.isNull() {
		return
	}
	start, end, n, esc := p.str()
	if p.err {
		return
	}
	out := p.out
	out.HasModel = true
	if n > MaxModelBytes {
		out.ModelTooLong = true
		return
	}
	if esc {
		out.modelLen = len(unescape(out.model[:0], p.b[start:end]))
	} else {
		out.modelLen = copy(out.model[:], p.b[start:end])
	}
}

// messages reads chat's or Anthropic's messages: an array of objects.
func (p *parser) messages() {
	if p.isNull() {
		return
	}
	if !p.open('[', 2) {
		return
	}
	out := p.out
	first := true
	for p.next(&first, ']') {
		p.message(out.Messages)
		if p.err {
			return
		}
		out.Messages++
	}
}

// message reads one message, the index-th, at depth 3.
func (p *parser) message(index int64) {
	if !p.open('{', 3) {
		return
	}
	var seen uint32
	role, roleAt := RoleOther, p.i-1
	first := true
	for p.next(&first, '}') {
		at := p.i
		k := p.key()
		if p.err {
			return
		}
		switch {
		case string(k) == "role":
			if !p.once(&seen, fRole) {
				return
			}
			start, end, _, esc := p.str()
			if p.err {
				return
			}
			roleAt = at
			role = p.roleValue(start, end, esc)
		case string(k) == "content":
			if !p.once(&seen, fContent) {
				return
			}
			if p.isNull() {
				break
			}
			p.content(4, false)
		case string(k) == "tool_calls" && p.format == OpenAIChat:
			if !p.once(&seen, fToolCalls) {
				return
			}
			p.toolCalls()
		case string(k) == "function_call" && p.format == OpenAIChat:
			if !p.once(&seen, fFunctionCall) {
				return
			}
			p.function(4)
		case p.format == OpenAIChat && (string(k) == "reasoning" || string(k) == "reasoning_content" || string(k) == "refusal"):
			// Text servers give the model back with the history: Ollama's
			// reasoning, vLLM's reasoning_content, a refusal. Counted when
			// a string, skipped otherwise (no server reads another type).
			bit := fRefusal
			switch string(k) {
			case "reasoning":
				bit = fReasoning
			case "reasoning_content":
				bit = fReasoningContent
			}
			if !p.once(&seen, bit) {
				return
			}
			if p.peek() == '"' {
				_, _, n, _ := p.str()
				p.out.PromptBytes += n
			} else {
				p.skip(4)
			}
		default:
			p.unread(k, 4, messageKeys)
		}
		if p.err {
			return
		}
	}
	if !p.err {
		p.out.addRole(role, index, roleAt)
	}
}

// content reads a message's content at depth: a string, or an array of
// parts, whose text counts. A null is the caller's to skip. inner: the
// content of a part (a tool's result), whose parts nest no further.
func (p *parser) content(depth int, inner bool) {
	if p.peek() == '"' {
		_, _, n, _ := p.str()
		p.out.PromptBytes += n
		return
	}
	if !p.open('[', depth) {
		return
	}
	first := true
	for p.next(&first, ']') {
		p.part(depth+1, inner)
		if p.err {
			return
		}
	}
}

// textType reports whether a part of this type holds text: the chat API's
// text, the Responses API's input_text and output_text, Anthropic's text,
// or a part without a type.
func textType(t []byte, typed bool) bool {
	if !typed {
		return true
	}
	switch string(t) {
	case "text", "input_text", "output_text":
		return true
	}
	return false
}

// part reads a content part at depth: a text part's text counts, as do a
// tool result's contents (Anthropic's tool_result), and the Responses
// API's tool outputs, unless inner: the parts of those are read for their
// text only, so reading never recurses more than once. Other parts
// (images, audio, files) are skipped.
func (p *parser) part(depth int, inner bool) {
	if !p.open('{', depth) {
		return
	}
	var seen uint32
	var typ [16]byte
	typLen, typed, longType := 0, false, false
	var textLen, thinkingLen, refusalLen int64
	hasText, badText := false, false
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return
		}
		switch string(k) {
		case "type":
			if !p.once(&seen, fType) {
				return
			}
			start, end, n, esc := p.str()
			if p.err {
				return
			}
			typed = true
			switch {
			case n > int64(len(typ)):
				longType = true
			case esc:
				typLen = len(unescape(typ[:0], p.b[start:end]))
			default:
				typLen = copy(typ[:], p.b[start:end])
			}
		case "text":
			if !p.once(&seen, fText) {
				return
			}
			if p.peek() == '"' {
				_, _, textLen, _ = p.str()
				hasText = true
			} else {
				badText = !p.isNull()
				if badText {
					p.skip(depth + 1)
				}
			}
		case "thinking", "refusal":
			// An Anthropic thinking block's, a chat refusal part's text,
			// counted when the part is of that type.
			bit := fThinking
			if string(k) == "refusal" {
				bit = fRefusal
			}
			if !p.once(&seen, bit) {
				return
			}
			if p.peek() == '"' {
				_, _, n, _ := p.str()
				if string(k) == "thinking" {
					thinkingLen = n
				} else {
					refusalLen = n
				}
			} else {
				p.skip(depth + 1)
			}
		case "content", "output":
			// A tool result's contents (Anthropic's tool_result, the
			// Responses API's function_call_output): a string or parts, as
			// a message's.
			bit := fContent
			if string(k) == "output" {
				bit = fOutput
			}
			if !p.once(&seen, bit) {
				return
			}
			if c := p.peek(); !inner && (c == '"' || c == '[') {
				p.content(depth+1, true)
			} else {
				p.skip(depth + 1)
			}
		default:
			p.unread(k, depth+1, partKeys)
		}
		if p.err {
			return
		}
	}
	if p.err {
		return
	}
	if !longType {
		switch string(typ[:typLen]) {
		case "thinking":
			p.out.PromptBytes += thinkingLen
		case "refusal":
			p.out.PromptBytes += refusalLen
		}
	}
	if !longType && textType(typ[:typLen], typed) {
		if badText {
			p.fail("text is not a string")
			return
		}
		if hasText {
			p.out.PromptBytes += textLen
		}
	}
}

// toolCalls reads a chat message's tool_calls: their functions' arguments
// count.
func (p *parser) toolCalls() {
	if p.isNull() {
		return
	}
	if !p.open('[', 4) {
		return
	}
	first := true
	for p.next(&first, ']') {
		if !p.open('{', 5) {
			return
		}
		var seen uint32
		f := true
		for p.next(&f, '}') {
			k := p.key()
			if p.err {
				return
			}
			if string(k) == "function" {
				if !p.once(&seen, fFunction) {
					return
				}
				p.function(6)
			} else {
				p.unread(k, 6, toolCallKeys)
			}
			if p.err {
				return
			}
		}
		if p.err {
			return
		}
	}
}

// function reads a function call at depth: its arguments count.
func (p *parser) function(depth int) {
	if p.isNull() {
		return
	}
	if !p.open('{', depth) {
		return
	}
	var seen uint32
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return
		}
		if string(k) == "arguments" {
			if !p.once(&seen, fArguments) {
				return
			}
			if n, ok := p.text(); ok {
				p.out.PromptBytes += n
			}
		} else {
			p.unread(k, depth+1, functionKeys)
		}
		if p.err {
			return
		}
	}
}

// responsesInput reads the Responses API's input: a string (a user
// message) or an array of items.
func (p *parser) responsesInput() {
	out := p.out
	switch p.peek() {
	case 'n':
		p.literal("null")
		return
	case '"':
		at := p.i
		_, _, n, _ := p.str()
		out.PromptBytes += n
		out.Messages++
		out.addRole(RoleUser, 0, at)
		return
	}
	if !p.open('[', 2) {
		return
	}
	first := true
	for p.next(&first, ']') {
		p.item(out.Messages)
		if p.err {
			return
		}
		out.Messages++
	}
}

// item reads one input item of the Responses API, the index-th: a message
// (by its role), a tool's output (tool), a function call (assistant), or
// another item, which counts but has no role.
func (p *parser) item(index int64) {
	if !p.open('{', 3) {
		return
	}
	var seen uint32
	role, roleAt := RoleNone, p.i-1
	var typ [32]byte
	typLen := 0
	first := true
	for p.next(&first, '}') {
		at := p.i
		k := p.key()
		if p.err {
			return
		}
		switch string(k) {
		case "role":
			if !p.once(&seen, fRole) {
				return
			}
			start, end, _, esc := p.str()
			if p.err {
				return
			}
			roleAt = at
			role = p.roleValue(start, end, esc)
		case "type":
			if !p.once(&seen, fType) {
				return
			}
			start, end, n, esc := p.str()
			if p.err {
				return
			}
			if n <= int64(len(typ)) {
				if esc {
					typLen = len(unescape(typ[:0], p.b[start:end]))
				} else {
					typLen = copy(typ[:], p.b[start:end])
				}
			}
		case "content":
			if !p.once(&seen, fContent) {
				return
			}
			if p.isNull() {
				break
			}
			p.content(4, false)
		case "output":
			if !p.once(&seen, fOutput) {
				return
			}
			if c := p.peek(); c == '"' || c == '[' {
				p.content(4, true)
			} else {
				p.skip(4)
			}
		case "arguments":
			if !p.once(&seen, fArguments) {
				return
			}
			if c := p.peek(); c == '"' {
				_, _, n, _ := p.str()
				p.out.PromptBytes += n
			} else {
				p.skip(4)
			}
		default:
			p.unread(k, 4, itemKeys)
		}
		if p.err {
			return
		}
	}
	if p.err {
		return
	}
	if role == RoleNone {
		switch string(typ[:typLen]) {
		case "function_call_output", "custom_tool_call_output", "computer_call_output", "local_shell_call_output", "mcp_approval_response":
			role = RoleTool
		case "function_call", "custom_tool_call":
			role = RoleAssistant
		}
	}
	p.out.addRole(role, index, roleAt)
}

// embeddingInput reads Embeddings' input: a string, an array of strings,
// an array of tokens, or an array of arrays of tokens. A token counts as 4
// bytes.
func (p *parser) embeddingInput() {
	out := p.out
	switch p.peek() {
	case 'n':
		p.literal("null")
		return
	case '"':
		at := p.i
		_, _, n, _ := p.str()
		out.PromptBytes += n
		out.Messages++
		out.addRole(RoleUser, 0, at)
		return
	}
	at := p.i
	if !p.open('[', 2) {
		return
	}
	// kind is what the array holds: 0 not known yet, then strings ('"'),
	// tokens ('0') or arrays of tokens ('[').
	var kind byte
	first := true
	for p.next(&first, ']') {
		c := p.peek()
		switch {
		case c == '"', c == '[':
		case c == '-' || c >= '0' && c <= '9':
			c = '0'
		default:
			p.fail("wrong type")
			return
		}
		if kind == 0 {
			kind = c
		} else if kind != c {
			p.fail("mixed input")
			return
		}
		switch c {
		case '"':
			_, _, n, _ := p.str()
			out.PromptBytes += n
			out.Messages++
		case '0':
			if _, ok := p.integer(); ok {
				out.PromptBytes += 4
			}
		case '[':
			p.open('[', 3)
			f := true
			for p.next(&f, ']') {
				if c := p.peek(); c != '-' && (c < '0' || c > '9') {
					p.fail("wrong type")
					return
				}
				if _, ok := p.integer(); ok {
					out.PromptBytes += 4
				}
				if p.err {
					return
				}
			}
			out.Messages++
		}
		if p.err {
			return
		}
	}
	if kind == '0' {
		out.Messages++ // one input of tokens
	}
	if out.Messages > 0 {
		out.addRole(RoleUser, 0, at)
	}
}

// tools reads an array of tool definitions, the which-th kind (tools, or
// chat's older functions), and keeps where it is for the tools check.
func (p *parser) tools(which int) {
	if p.isNull() {
		return
	}
	start := p.i
	n := p.toolArray(nil)
	if p.err {
		return
	}
	p.out.Tools += n
	p.out.toolSpans[which] = span{int32(start), int32(p.i)} // #nosec G115 -- the body is at most MaxBodyBytes
	p.out.nTools = max(p.out.nTools, which+1)
}

// toolSink is told each tool's name (nil for a name longer than any listed
// one) and offset, until it returns false. A concrete type, not a func:
// the names stay on the stack.
type toolSink struct {
	// rules, if set, find the first tool not allowed: its index and
	// offset in found.
	rules  *Rules
	index  int
	found  bool
	offset int
	// names, if set, collect the names (tests).
	names *[]string
}

func (s *toolSink) add(name []byte, offset int) bool {
	if s.names != nil {
		if name == nil {
			*s.names = append(*s.names, "<nil>")
		} else {
			*s.names = append(*s.names, string(name))
		}
	}
	if s.rules != nil && (s.rules.tools == ToolsNone || !s.rules.listed(name)) {
		s.found, s.offset = true, offset
		return false
	}
	s.index++
	return true
}

// toolArray reads an array of tool definitions, telling each's name to
// sink, if set, and returns how many there are. A tool's name is its name
// (chat's function.name or custom.name), or its type for a built-in tool
// without one.
func (p *parser) toolArray(sink *toolSink) int {
	if !p.open('[', 2) {
		return 0
	}
	var nameb [maxName]byte
	count := 0
	first := true
	for p.next(&first, ']') {
		at := p.i
		if !p.open('{', 3) {
			return count
		}
		var seen uint32
		var name, typ []byte
		var hasName bool
		f := true
		for p.next(&f, '}') {
			k := p.key()
			if p.err {
				return count
			}
			switch string(k) {
			case "name":
				if !p.once(&seen, fName) {
					return count
				}
				name, hasName = p.name(nameb[:0])
			case "type":
				if !p.once(&seen, fType) {
					return count
				}
				if !hasName {
					typ, _ = p.name(nameb[:0])
				} else {
					p.str()
				}
			case "function", "custom":
				bit := fFunction
				if string(k) == "custom" {
					bit = fCustom
				}
				if !p.once(&seen, bit) {
					return count
				}
				if p.isNull() {
					break
				}
				if n, ok := p.nested(nameb[:0]); ok {
					name, hasName = n, true
				}
			default:
				p.unread(k, 4, toolKeys)
			}
			if p.err {
				return count
			}
		}
		if p.err {
			return count
		}
		count++
		if sink != nil {
			if !hasName {
				name = typ
			}
			if !sink.add(name, at) {
				return count
			}
		}
	}
	return count
}

// name reads a tool's name or type into buf; a name longer than maxName is
// returned as nil, which no listed name is.
func (p *parser) name(buf []byte) ([]byte, bool) {
	start, end, n, esc := p.str()
	if p.err {
		return nil, false
	}
	if n > maxName {
		return nil, true
	}
	if esc {
		return unescape(buf, p.b[start:end]), true
	}
	return append(buf, p.b[start:end]...), true
}

// nested reads a chat tool's function or custom object, at depth 4: its
// name.
func (p *parser) nested(buf []byte) ([]byte, bool) {
	if !p.open('{', 4) {
		return nil, false
	}
	var seen uint32
	var name []byte
	has := false
	first := true
	for p.next(&first, '}') {
		k := p.key()
		if p.err {
			return nil, false
		}
		if string(k) == "name" {
			if !p.once(&seen, fName) {
				return nil, false
			}
			name, has = p.name(buf)
		} else {
			p.unread(k, 5, nestedKeys)
		}
		if p.err {
			return nil, false
		}
	}
	return name, has && !p.err
}

// eachTool reads the tools r defines again from body, which Parse read
// into r, telling sink about each.
func (r *Request) eachTool(body []byte, sink *toolSink) {
	var scratch Request
	for _, s := range r.toolSpans[:r.nTools] {
		if s.end == 0 || sink.found {
			continue
		}
		p := parser{b: body[:s.end], i: int(s.start), out: &scratch, format: r.Format}
		p.toolArray(sink)
	}
}
