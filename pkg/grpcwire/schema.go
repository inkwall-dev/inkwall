// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// MaxName is the longest field path Fields gives, the longest an exclusion
// can name (ArgumentPattern): a longer one keeps its first MaxName bytes.
const MaxName = 256

// minBytesRun is the shortest run of readable characters a bytes field
// (or a packed repeated number) gives with its schema. Design 0013 expected
// minBinaryRun to do; measured, it doesn't: of 100,000 messages of four
// random 1 to 24 byte bytes fields, runs of 8 or more had 13 denied by the
// CRS (942100, 932250, 942190...), 10 or more 1, 12 or more none (16 none),
// and ASCII runs of 8 or more 8 (TestGRPCSchemaFalsePositives). Text an
// application keeps in bytes (JSON, a serialized message) comes in runs
// longer than that.
const minBytesRun = 12

// minBytesText is the shortest bytes field read whole when it is printable
// UTF-8, as text an application keeps in bytes: shorter, random bytes are
// printable often enough to match the CRS. Of 100,000 messages of four
// random 1 to 24 byte bytes fields, printable ones read whole at any
// length had 18 denied, from 8 bytes none (TestGRPCSchemaFalsePositives).
const minBytesText = 8

// Fields returns the text fields of msg, a protobuf message of type t of
// schema s, appended to out; unknown, the fields t doesn't describe; and
// whether the message parsed whole and stayed within lim (design 0013 §6).
//
// Each field t describes is read by its kind: a string as text (as
// Strings reads UTF-8, a byte that isn't UTF-8 a space), bytes whole when
// they are printable UTF-8 of at least 8 bytes (minBytesText), else by
// their runs of at least 12 readable characters (minBytesRun), a message
// or group by its type, one level deeper (a message also as text, as
// Strings reads one: whole when printable, else the runs between its
// fields), numbers as nothing, and a packed repeated number by its runs,
// as bytes. Fields are named by their proto names, joined by dots
// ("user.name"), without indexes; an extension "[package.extension]". An
// Any's value is read as the type its last type_url names, under the
// Any's name, when s has it, and as Strings reads it.
//
// What t doesn't describe is read as Strings reads it, named by number
// under the nearest name ("user.7"): a field number t doesn't have, a
// field sent with a wire type its kind doesn't take, and a message field
// whose bytes aren't a message. Every occurrence of a field is read, and
// every member of a oneof. The reading is charged against a budget of
// bytes read linear in msg (readBudget): past it, the message is over
// lim.
func Fields(msg []byte, s *grpcschema.Schema, t *grpcschema.Message, lim Limits, out []Field) (fields []Field, unknown int, ok bool) {
	w := schemaWalker{walker: walker{lim: lim, out: out}, s: s, budget: readBudget(len(msg))}
	defer func() {
		if recover() != nil {
			fields, unknown, ok = w.out, w.unknown, false
		}
	}()
	ok = w.message(msg, t, 0)
	return w.out, w.unknown, ok && !w.over
}

// schemaWalker walks a message with its schema; walker reads what the
// schema doesn't describe. prefix is the path of the message being walked.
type schemaWalker struct {
	walker
	s       *grpcschema.Schema
	prefix  string
	unknown int
	// budget is how many more bytes may be read (charge).
	budget int
}

// readBudget is how many bytes reading a message of n bytes may read in
// all, its nested values counted at each level they are read: a
// message's bytes are read once per level of nesting (16 at most) by
// their types, and once more without the schema where it reads them too
// (an Any's value, a field it doesn't describe). Past it, the message is
// over the limits, whatever its shape: the reading stays linear in the
// message, and so does its text.
func readBudget(n int) int { return 64*n + 64<<10 }

// charge counts n bytes read; past the budget, it reports false and the
// message is over the limits.
func (w *schemaWalker) charge(n int) bool {
	if w.budget -= n; w.budget < 0 {
		w.over = true
		return false
	}
	return true
}

// emit adds value as the text of path, cut to MaxName bytes. It reports
// false when the fields are over the limit.
func (w *schemaWalker) emit(value, path string) bool {
	return w.text(value, path[:min(len(path), MaxName)])
}

// message walks msg, a message of type t at depth named w.prefix. It
// reports whether msg is a valid message.
func (w *schemaWalker) message(msg []byte, t *grpcschema.Message, depth int) bool {
	if t.Any {
		return w.anyMessage(msg, t, depth)
	}
	for len(msg) > 0 {
		num, typ, v, ok := consume(&msg)
		if !ok {
			return false
		}
		f := t.Field(num)
		if f == nil || !takes(f, typ) {
			w.unknownField(num, typ, v, depth)
			continue
		}
		if !w.known(f, typ, v, depth) {
			return true
		}
	}
	return true
}

// consume reads the next field of *msg: its number, wire type, and the
// value of a length-delimited field or the fields of a group.
func consume(msg *[]byte) (protowire.Number, protowire.Type, []byte, bool) {
	num, typ, n := protowire.ConsumeTag(*msg)
	if n < 0 {
		return 0, 0, nil, false
	}
	*msg = (*msg)[n:]
	var v []byte
	switch typ {
	case protowire.BytesType:
		v, n = protowire.ConsumeBytes(*msg)
	case protowire.StartGroupType:
		v, n = protowire.ConsumeGroup(num, *msg)
	default:
		// Numbers; an end tag without its start doesn't parse.
		n = protowire.ConsumeFieldValue(num, typ, *msg)
	}
	if n < 0 {
		return 0, 0, nil, false
	}
	*msg = (*msg)[n:]
	return num, typ, v, true
}

// takes reports whether f's kind is sent with wire type typ: any other is
// what protobuf runtimes keep as an unknown field.
func takes(f *grpcschema.Field, typ protowire.Type) bool {
	switch f.Kind {
	case grpcschema.KindString, grpcschema.KindBytes, grpcschema.KindMessage:
		return typ == protowire.BytesType
	case grpcschema.KindGroup:
		return typ == protowire.StartGroupType
	case grpcschema.KindVarint:
		return typ == protowire.VarintType || f.Repeated && typ == protowire.BytesType
	case grpcschema.KindFixed32:
		return typ == protowire.Fixed32Type || f.Repeated && typ == protowire.BytesType
	case grpcschema.KindFixed64:
		return typ == protowire.Fixed64Type || f.Repeated && typ == protowire.BytesType
	}
	return false
}

// known reads v, the value of field f sent with wire type typ, which its
// kind takes. It reports false when the fields are over the limit.
func (w *schemaWalker) known(f *grpcschema.Field, typ protowire.Type, v []byte, depth int) bool {
	if len(v) == 0 {
		return true
	}
	if !w.charge(len(v)) {
		return false
	}
	path := f.Path(w.prefix)
	switch f.Kind {
	case grpcschema.KindString:
		return w.emit(stringText(v), path)
	case grpcschema.KindBytes:
		// Printable UTF-8 is read whole, as Strings reads it: an
		// application may keep text in bytes. Other bytes give their long
		// runs only.
		if len(v) >= minBytesText && printable(v) {
			return w.emit(string(v), path)
		}
		return w.emit(runs(v, minBytesRun), path)
	case grpcschema.KindMessage:
		ok, numbersRun := valid(v, minNumbersRun)
		if !ok {
			// Not a message: as Strings reads it (a newer application may
			// have made it a string). The message is still read whole.
			w.unknown++
			w.field(v, path[:min(len(path), MaxName)], depth)
			return !w.over
		}
		// As text too, as Strings reads a message: whole when printable (a
		// string declared a message can't split an attack across its
		// "fields"), else the runs between its fields, where text an
		// application reading it otherwise could hide.
		switch {
		case printableMessage(v):
			if !w.emit(string(v), path) {
				return false
			}
		case numbersRun:
			if !w.charge(len(v)) || !w.emit(runs(between(v), minNumbersRun), path) {
				return false
			}
		}
		return w.nested(v, f.Message, path, depth)
	case grpcschema.KindGroup:
		return w.nested(v, f.Message, path, depth)
	default:
		// A packed repeated number: its runs, as bytes. A string declared
		// a repeated number reads no less than one declared bytes.
		return w.emit(runs(v, minBytesRun), path)
	}
}

// nested walks v, a valid message (or group fields) of type t named
// prefix, one level below depth.
func (w *schemaWalker) nested(v []byte, t *grpcschema.Message, prefix string, depth int) bool {
	if depth+1 > w.lim.Depth {
		w.over = true
		return false
	}
	parent := w.prefix
	w.prefix = prefix
	w.message(v, t, depth+1)
	w.prefix = parent
	return !w.over
}

// unknownField reads field num, which the schema doesn't describe with
// wire type typ, as Strings does, named by its number.
func (w *schemaWalker) unknownField(num protowire.Number, typ protowire.Type, v []byte, depth int) {
	w.unknown++
	if len(v) > 0 && !w.charge(2*len(v)) {
		return
	}
	switch typ {
	case protowire.BytesType:
		w.field(v, fieldName(w.prefix, num), depth)
	case protowire.StartGroupType:
		w.group(v, fieldName(w.prefix, num), depth)
	}
}

// anyMessage walks msg, a google.protobuf.Any: its type_urls (1) as text,
// its values (2) as the type its last type_url names (the one the
// application unpacks by) and without the schema, and anything else as
// unknown.
func (w *schemaWalker) anyMessage(msg []byte, t *grpcschema.Message, depth int) bool {
	var named *grpcschema.Message
	for rest := msg; len(rest) > 0; {
		num, typ, v, ok := consume(&rest)
		if !ok {
			return false
		}
		if num == 1 && typ == protowire.BytesType {
			named = w.s.AnyType(string(v))
		}
	}
	for len(msg) > 0 {
		num, typ, v, _ := consume(&msg)
		switch {
		case num == 1 && typ == protowire.BytesType:
			if !w.emit(stringText(v), t.Field(1).Path(w.prefix)) {
				return true
			}
		case num == 2 && typ == protowire.BytesType:
			if !w.anyValue(v, t.Field(2).Path(w.prefix), named, depth) {
				return true
			}
		default:
			w.unknownField(num, typ, v, depth)
		}
		if w.over {
			return true
		}
	}
	return true
}

// anyValue reads an Any's value: as t, the type its last type_url names
// (nil: none the schema has), its fields under the Any's name; and as
// Strings does, named path ("payload.value"), whatever the type_url says:
// an application may unpack it without checking.
func (w *schemaWalker) anyValue(v []byte, path string, t *grpcschema.Message, depth int) bool {
	if len(v) == 0 {
		return true
	}
	if !w.charge(2 * len(v)) {
		return false
	}
	if t != nil && parses(v) && !w.nested(v, t, w.prefix, depth) {
		return false
	}
	w.field(v, path[:min(len(path), MaxName)], depth)
	return !w.over
}

// parses reports whether v is a protobuf message, one level deep.
func parses(v []byte) bool {
	for len(v) > 0 {
		_, _, n := protowire.ConsumeField(v)
		if n < 0 {
			return false
		}
		v = v[n:]
	}
	return true
}

// printableMessage is printable(v) for v, a message, which is seldom
// printable: a tag or a length is mostly a control character, found first.
func printableMessage(v []byte) bool {
	for _, c := range v {
		if control(rune(c)) {
			return false
		}
	}
	return printable(v)
}

// stringText is a string field's text, whatever its bytes: as spaced,
// with each byte that isn't UTF-8 a space too, since a proto2 or non-Go
// application takes such a string.
func stringText(v []byte) string {
	if utf8.Valid(v) {
		return spaced(v)
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); {
		r, n := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError && n == 1 || control(r) {
			b.WriteByte(' ')
		} else {
			b.Write(v[i : i+n])
		}
		i += n
	}
	return b.String()
}
