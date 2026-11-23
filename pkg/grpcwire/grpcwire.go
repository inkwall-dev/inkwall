// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcwire reads gRPC request messages without their schema: it
// splits a body into gRPC messages and finds the text in each protobuf
// message, for rules to inspect.
//
// Protobuf's wire format doesn't say which length-delimited fields are
// strings, bytes or nested messages. A field whose bytes are a whole
// protobuf message is read as one (its fields get their own names); a
// field whose bytes are UTF-8 is text, whatever its characters. Some bytes
// are both, and give both. A group is read as a nested message. Binary
// bytes give their runs of readable text.
// Numbers outside a length-delimited field and anything that fails to
// parse give nothing.
package grpcwire

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// FrameHeader is a gRPC message's prefix: a compressed flag (0 or 1) and
// the message length, 4 bytes big-endian.
const FrameHeader = 5

// Message is one gRPC message of a body.
type Message struct {
	// Compressed: the message is compressed with the call's grpc-encoding.
	Compressed bool
	// Data is the message, or as much of it as the body holds.
	Data []byte
	// Cut: the body ends inside the message.
	Cut bool
}

// Messages splits body into gRPC messages. ok is false when body isn't a
// sequence of messages: a bad flag, or a body that ends inside a prefix or
// a message while it is not truncated.
func Messages(body []byte, truncated bool) (msgs []Message, ok bool) {
	for len(body) > 0 {
		if len(body) < FrameHeader {
			return msgs, truncated
		}
		if body[0] > 1 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(body[1:FrameHeader]))
		m := Message{Compressed: body[0] == 1}
		body = body[FrameHeader:]
		if n > uint64(len(body)) {
			if !truncated {
				return nil, false
			}
			m.Data, m.Cut = body, true
			return append(msgs, m), true
		}
		m.Data = body[:n]
		body = body[n:]
		msgs = append(msgs, m)
	}
	return msgs, true
}

// Field is text found in a message: Name is the path of field numbers
// from the message, dot-separated ("2.1": field 1 of the message in
// field 2).
type Field struct {
	Name  string
	Value string
}

// Limits bound the work on one body.
type Limits struct {
	// Depth is how deep nested messages are read.
	Depth int
	// Fields is how many text fields are returned.
	Fields int
}

// DefaultLimits are those the pipeline uses.
var DefaultLimits = Limits{Depth: 16, Fields: 1024}

// Strings returns the text fields of a protobuf message, appended to out,
// and reports whether the message parsed whole and stayed within lim.
// A message that doesn't parse gives what was found before the error. A
// panic while reading (it runs on an adapter's goroutine, which nothing
// else recovers) is a message not read whole, as one that doesn't parse.
func Strings(msg []byte, lim Limits, out []Field) (fields []Field, ok bool) {
	w := walker{lim: lim, out: out}
	defer func() {
		if recover() != nil {
			fields, ok = w.out, false
		}
	}()
	ok, _ = w.message(msg, "", 0)
	return w.out, ok && !w.over
}

type walker struct {
	lim  Limits
	out  []Field
	over bool
}

// message walks msg, a message at depth whose fields are named under
// prefix. It reports whether msg is a valid message, and whether its tags,
// lengths and numbers, and those of the messages read in it, are blank:
// control characters and spaces only.
func (w *walker) message(msg []byte, prefix string, depth int) (ok, blank bool) {
	blank = true
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return false, false
		}
		blank = blank && isBlank(msg[:n])
		msg = msg[n:]
		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(msg)
			if n < 0 {
				return false, false
			}
			blank = blank && isBlank(msg[:n-len(v)])
			msg = msg[n:]
			blank = w.field(v, fieldName(prefix, num), depth) && blank
		case protowire.StartGroupType:
			// A group (proto2, or editions' DELIMITED encoding): a nested
			// message between a start and an end tag. One that doesn't end,
			// or ends with another field's tag, doesn't parse.
			v, n := protowire.ConsumeGroup(num, msg)
			if n < 0 {
				return false, false
			}
			blank = blank && isBlank(msg[len(v):n])
			msg = msg[n:]
			blank = w.group(v, fieldName(prefix, num), depth) && blank
		default:
			// Numbers; an end tag without its start doesn't parse.
			n = protowire.ConsumeFieldValue(num, typ, msg)
			if n < 0 {
				return false, false
			}
			blank = blank && isBlank(msg[:n])
			msg = msg[n:]
		}
	}
	return true, blank
}

// isBlank reports whether b has only control characters and spaces.
func isBlank(b []byte) bool {
	for _, c := range b {
		if c > ' ' && c != 0x7f {
			return false
		}
	}
	return true
}

// fieldName is the name of field num of a message whose fields are named
// under prefix.
func fieldName(prefix string, num protowire.Number) string {
	name := strconv.Itoa(int(num))
	if prefix != "" {
		name = prefix + "." + name
	}
	return name
}

// field reads the bytes of a length-delimited field: as text, and as a
// nested message. No character or byte keeps a field from the rules:
//
//   - UTF-8 that isn't a message is text, whatever its characters: a
//     control character is a space (see spaced), the rest as it is;
//   - a message is read as one, and as text too: as it is when it is
//     printable; else whole (flat) when it is UTF-8 whose tags, lengths
//     and numbers (its own and its messages') are blank; and the readable
//     runs of its own bytes, those between its length-delimited fields
//     (tags, lengths, numbers), where text could otherwise hide;
//   - any other bytes (binary) give their readable runs.
func (w *walker) field(v []byte, name string, depth int) (blank bool) {
	if len(v) == 0 {
		return true
	}
	nested, numbersRun := valid(v, minNumbersRun)
	if nested {
		// UTF-8 that also parses as a message, with no readable character
		// in its tags, lengths and numbers or its messages', gives both:
		// its fields, and its whole text (unless nested gives it,
		// printable), so that the whitespace and control characters there
		// can't split words between its fields; within the depth read.
		// Tags and lengths that read as text would join field names and
		// values into words no one sent (false positives): those messages
		// give their fields alone.
		// A printable message is text as it is, to its parent too.
		blank = w.nested(v, name, depth, numbersRun)
		if printable(v) {
			return true
		}
		if blank && depth < w.lim.Depth && utf8.Valid(v) {
			w.text(flat(v), name)
		}
		return blank
	}
	if utf8.Valid(v) {
		w.text(spaced(v), name)
	} else {
		w.text(runs(v, minBinaryRun), name)
	}
	return true
}

// group reads a group's fields v, a valid message, as a nested message's:
// its text, and its fields under name, within the same limits. It reports
// whether v is blank (message).
func (w *walker) group(v []byte, name string, depth int) bool {
	if len(v) == 0 {
		return true
	}
	_, numbersRun := valid(v, minNumbersRun)
	return w.nested(v, name, depth, numbersRun)
}

// nested reads v, a valid message at depth+1 named name, as text (see
// field), then its fields; numbersRun: between(v) may hold a run (valid).
// It reports whether v, read whole, is blank (message).
func (w *walker) nested(v []byte, name string, depth int, numbersRun bool) bool {
	var value string
	if printable(v) {
		value = string(v)
	} else if numbersRun {
		value = runs(between(v), minNumbersRun)
	}
	if !w.text(value, name) {
		return false
	}
	if depth+1 > w.lim.Depth {
		w.over = true
		return false
	}
	_, blank := w.message(v, name, depth+1)
	return blank
}

// text adds value, unless it is empty, as the text of field name. It
// reports false when the fields are over the limit.
func (w *walker) text(value, name string) bool {
	if value == "" {
		return true
	}
	if len(w.out) >= w.lim.Fields {
		w.over = true
		return false
	}
	w.out = append(w.out, Field{Name: name, Value: value})
	return true
}

// between returns the bytes of msg, a valid message, but the contents of
// its length-delimited fields: its tags, lengths and numbers, those of its
// groups too (whose text fields are read as theirs). It reads msg once,
// tag by tag: a group's start and end tags are tags like any other, so
// that groups nested however deep cost no more than their bytes.
func between(msg []byte) []byte {
	var out []byte
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return out
		}
		skip := 0 // the contents of a length-delimited field
		switch typ {
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(msg[n:])
			if m < 0 {
				return out
			}
			n, skip = n+m-len(v), len(v)
		case protowire.StartGroupType, protowire.EndGroupType:
		default:
			m := protowire.ConsumeFieldValue(num, typ, msg[n:])
			if m < 0 {
				return out
			}
			n += m
		}
		out = append(out, msg[:n]...)
		msg = msg[n+skip:]
	}
	return out
}

// valid reports whether v parses as a protobuf message, one level deep,
// and whether between(v) may hold a run of at least minRun readable
// characters: one pass finds both, so that runs builds between(v) only for
// the few messages whose tags, lengths and numbers may hold text. It counts
// each byte from 0x80 as a character, so it may say yes where runs finds
// none, never no where it finds one.
func valid(v []byte, minRun int) (ok, run bool) {
	chars := 0
	for len(v) > 0 {
		_, typ, n := protowire.ConsumeField(v)
		if n < 0 {
			return false, false
		}
		end := n
		if typ == protowire.BytesType {
			_, _, tag := protowire.ConsumeTag(v)
			b, _ := protowire.ConsumeBytes(v[tag:])
			end = n - len(b)
		}
		for _, c := range v[:end] {
			if run {
				break
			}
			if control(rune(c)) {
				chars = 0
			} else if chars++; chars >= minRun {
				run = true
			}
		}
		v = v[n:]
	}
	return true, run
}

// Gunzip decompresses a message compressed with grpc-encoding gzip, up
// to limit bytes. ok is false when data isn't gzip, or decompresses to
// more than limit bytes: then out is what fit.
func Gunzip(data []byte, limit int64) (out []byte, ok bool) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	out, err = io.ReadAll(io.LimitReader(zr, limit+1))
	if int64(len(out)) > limit {
		return out[:limit], false
	}
	return out, err == nil
}

// printable reports whether v is printable UTF-8: no control characters
// but tab, newline and carriage return.
func printable(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// spaced returns v, valid UTF-8, with each control character but tab,
// newline and carriage return replaced by a space: the text around it is
// read as the application gets it, without the control character itself
// matching a rule (920270 on NUL) in the binary fields that happen to be
// UTF-8.
func spaced(v []byte) string {
	// Control characters are ASCII, never part of a multi-byte UTF-8
	// sequence: looking for them byte by byte is exact, and cheaper.
	if !slices.ContainsFunc(v, func(c byte) bool { return control(rune(c)) }) {
		return string(v)
	}
	return strings.Map(func(r rune) rune {
		if control(r) {
			return ' '
		}
		return r
	}, string(v))
}

// flat returns v, valid UTF-8, with every control character a space (tab,
// newline and carriage return too), trimmed: the text of a message, whose
// tags and lengths (newline is field 1's tag) aren't the application's
// line breaks.
func flat(v []byte) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(v)))
}

// control reports whether r is a C0 control character other than tab,
// newline and carriage return, or DEL.
func control(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f
}

// minBinaryRun is the shortest run of readable characters kept from
// binary bytes, and minNumbersRun from a nested message's tags, lengths and
// numbers. Random bytes are full of short runs, and one like `5b|W` or
// `"4_y#` matches a command or SQL injection rule: from runs of 4 or more,
// 16 messages in 5,000 with four short random fields were denied
// (TestGRPCMessagesFalsePositives), from 8 or more 1, as many as without
// them. The tags between a nested message's numbers break its text more
// often, and real messages give no false positive from runs of 4.
const (
	minBinaryRun  = 8
	minNumbersRun = 4
)

// runs returns the text in v, bytes that aren't a string: its runs of at
// least minRun readable characters, joined by spaces. A byte that isn't
// UTF-8, and a control character but tab, newline and carriage return,
// end a run.
func runs(v []byte, minRun int) string {
	var b strings.Builder
	start, chars := 0, 0
	flush := func(end int) {
		if chars >= minRun {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.Write(v[start:end])
		}
	}
	for i := 0; i < len(v); {
		r, n := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError && n == 1 || control(r) {
			flush(i)
			i += n
			start, chars = i, 0
			continue
		}
		i += n
		chars++
	}
	flush(len(v))
	return b.String()
}
