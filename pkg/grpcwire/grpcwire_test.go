// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"compress/gzip"
	"math"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func frame(flag byte, msg string) string {
	n := len(msg)
	return string([]byte{flag, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}) + msg
}

func TestMessages(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		truncated bool
		want      []Message
		ok        bool
	}{
		{"empty", "", false, nil, true},
		{"one", frame(0, "ab"), false, []Message{{Data: []byte("ab")}}, true},
		{"empty message", frame(0, ""), false, []Message{{Data: []byte{}}}, true},
		{"compressed", frame(1, "ab") + frame(0, "c"), false, []Message{{Compressed: true, Data: []byte("ab")}, {Data: []byte("c")}}, true},
		{"bad flag", frame(2, "ab"), false, nil, false},
		{"short prefix", "\x00\x00", false, nil, false},
		{"short message", frame(0, "abc")[:6], false, nil, false},
		{"cut prefix", frame(0, "ab") + "\x00\x00", true, []Message{{Data: []byte("ab")}}, true},
		{"cut message", frame(0, "abc")[:6], true, []Message{{Data: []byte("a"), Cut: true}}, true},
	}
	for _, tt := range tests {
		got, ok := Messages([]byte(tt.body), tt.truncated)
		if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: Messages = %+v, %v; want %+v, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

// pb builds a message: pairs of a field number and a string, or a nested
// message ([]byte).
func pb(fields ...any) []byte {
	var b []byte
	for i := 0; i+1 < len(fields); i += 2 {
		num := protowire.Number(fields[i].(int))
		switch v := fields[i+1].(type) {
		case string:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendString(b, v)
		case []byte:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, v)
		case uint64:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, v)
		}
	}
	return b
}

func TestStrings(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want []Field
		ok   bool
	}{
		{"empty", nil, nil, true},
		{"string", pb(1, "world"), []Field{{"1", "world"}}, true},
		{"numbers", pb(1, uint64(42), 2, "x"), []Field{{"2", "x"}}, true},
		// A nested message, UTF-8 whose tags, lengths and numbers are
		// control characters, gives its fields, then its whole text (flat).
		{"nested", pb(2, pb(1, "inner", 3, uint64(7)), 4, "outer"), []Field{{"2.1", "inner"}, {"2", "inner"}, {"4", "outer"}}, true},
		// A word split between nested fields by their tags and lengths
		// is in the field's text whole.
		{"split between fields", pb(1, "\n\x05UNION\n\x07 SELECT\n\x09 password"),
			[]Field{{"1.1", "UNION"}, {"1.1", " SELECT"}, {"1.1", " password"}, {"1", "UNION   SELECT   password"}}, true},
		// Not UTF-8 (a number from 0x80), or readable tags, lengths or
		// numbers (field 13 is "j", length 0x41 "A"): its fields, and the
		// readable runs of its own bytes.
		{"nested binary", pb(2, pb(1, "inner", 3, uint64(1<<20)), 4, "outer"), []Field{{"2.1", "inner"}, {"4", "outer"}}, true},
		{"readable tags", pb(2, pb(13, "a", 1, strings.Repeat("b", 0x41))), []Field{{"2.13", "a"}, {"2.1", strings.Repeat("b", 0x41)}}, true},
		{"printable nested", pb(2, []byte(" (")), []Field{{"2", " ("}}, true},
		// Text in a nested message's numbers: fixed64 field 2 (tag 0x11).
		{"text in numbers", pb(1, []byte("\x11' OR 1=1\x11 -- abcd\x08\x00")), []Field{{"1", "' OR 1=1  -- abcd"}}, true},
		{"binary", pb(1, []byte{0, 1, 2, 0xff}), nil, true},
		{"binary with text", pb(1, []byte("\xff\x00ab\xfe<script>\x00abcdefg")), []Field{{"1", "<script>"}}, true},
		{"unicode", pb(1, "Zoë 李\n\ttab"), []Field{{"1", "Zoë 李\n\ttab"}}, true},
		{"control", pb(1, "a\x00b\x1bc\x7f"), []Field{{"1", "a b c "}}, true},
		{"format", pb(1, "a\u200bb\ufeff"), []Field{{"1", "a\u200bb\ufeff"}}, true},
		{"invalid utf-8", pb(1, "a\xffbcdefgh\n"), []Field{{"1", "bcdefgh\n"}}, true},
		// " (" is field 4 varint 0x28: both text and a message, which has
		// no text field.
		{"text that parses", pb(1, " ("), []Field{{"1", " ("}}, true},
		{"not protobuf", []byte{0xff, 0xff, 0xff}, nil, false},
		{"cut", pb(1, "world", 2, "again")[:9], []Field{{"1", "world"}}, false},
	}
	for _, tt := range tests {
		got, ok := Strings(tt.msg, DefaultLimits, nil)
		if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: Strings = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

// group builds group num of fields (a message): between a start and an
// end tag.
func group(num int, fields []byte) []byte {
	b := protowire.AppendTag(nil, protowire.Number(num), protowire.StartGroupType)
	b = append(b, fields...)
	return protowire.AppendTag(b, protowire.Number(num), protowire.EndGroupType)
}

// TestStringsGroups: a group (proto2, editions' DELIMITED encoding) is read
// as a nested message: its fields, its text, within the same limits.
func TestStringsGroups(t *testing.T) {
	deep := func(levels int) []byte {
		m := pb(1, "bottom")
		for range levels {
			m = group(1, m)
		}
		return m
	}
	endTag := func(num int) []byte { return protowire.AppendTag(nil, protowire.Number(num), protowire.EndGroupType) }
	tests := []struct {
		name string
		msg  []byte
		want []Field
		ok   bool
	}{
		{"group", group(2, pb(1, "inner")), []Field{{"2.1", "inner"}}, true},
		{"nested groups", group(1, group(2, pb(3, "<script>"))), []Field{{"1.2.3", "<script>"}}, true},
		{"after a string", append(pb(1, "a"), group(2, pb(1, "b"))...), []Field{{"1", "a"}, {"2.1", "b"}}, true},
		{"empty group", group(1, nil), nil, true},
		// Text in a group's numbers: fixed64 field 2 (tag 0x11).
		{"text in numbers", group(1, []byte("\x11' OR 1=1")), []Field{{"1", "' OR 1=1"}}, true},
		// A group in a length-delimited field: the group's fields, then
		// the field's whole text.
		{"in a submessage", pb(1, group(2, pb(3, "x' OR 1=1"))), []Field{{"1.2.3", "x' OR 1=1"}, {"1", "x' OR 1=1"}}, true},
		// As deep as nested messages may be, and deeper.
		{"at the depth limit", deep(DefaultLimits.Depth), []Field{{strings.Repeat("1.", DefaultLimits.Depth) + "1", "bottom"}}, true},
		{"too deep", deep(DefaultLimits.Depth + 1), nil, false},
		{"no end", append(protowire.AppendTag(nil, 1, protowire.StartGroupType), pb(2, "x")...), nil, false},
		{"other end", append(append(protowire.AppendTag(nil, 1, protowire.StartGroupType), pb(2, "x")...), endTag(3)...), nil, false},
		{"stray end", append(pb(1, "a"), endTag(1)...), []Field{{"1", "a"}}, false},
	}
	for _, tt := range tests {
		got, ok := Strings(tt.msg, DefaultLimits, nil)
		if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: Strings = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
	var many []byte
	for i := range 20 {
		many = append(many, group(i+1, pb(1, "v"))...)
	}
	if got, ok := Strings(many, Limits{Depth: 4, Fields: 10}, nil); ok || len(got) != 10 {
		t.Errorf("too many: %d fields, %v; want 10, false", len(got), ok)
	}
}

func TestStringsLimits(t *testing.T) {
	deep := pb(1, "bottom")
	for range 20 {
		deep = pb(1, deep)
	}
	got, ok := Strings(deep, Limits{Depth: 4, Fields: 10}, nil)
	if ok || len(got) != 0 {
		t.Errorf("too deep: %q, %v; want nothing, false", got, ok)
	}
	var many []any
	for i := range 20 {
		many = append(many, i+1, "v")
	}
	got, ok = Strings(pb(many...), Limits{Depth: 4, Fields: 10}, nil)
	if ok || len(got) != 10 {
		t.Errorf("too many: %d fields, %v; want 10, false", len(got), ok)
	}
}

func TestGunzip(t *testing.T) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(strings.Repeat("a", 100)))
	_ = zw.Close()
	if out, ok := Gunzip(b.Bytes(), 100); !ok || len(out) != 100 {
		t.Errorf("Gunzip = %d bytes, %v", len(out), ok)
	}
	if out, ok := Gunzip(b.Bytes(), 99); ok || len(out) != 99 {
		t.Errorf("over the limit: %d bytes, %v; want 99, false", len(out), ok)
	}
	if _, ok := Gunzip([]byte("not gzip"), 100); ok {
		t.Error("not gzip: ok")
	}
	if _, ok := Gunzip(b.Bytes()[:b.Len()-4], 100); ok {
		t.Error("cut: ok")
	}
}

// TestGunzipLimitBounds: at the largest limit, a message is read whole;
// at a negative one, as at 0, nothing is.
func TestGunzipLimitBounds(t *testing.T) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte("' UNION SELECT password FROM users--"))
	_ = zw.Close()
	if out, ok := Gunzip(b.Bytes(), math.MaxInt64); !ok || string(out) != "' UNION SELECT password FROM users--" {
		t.Errorf("limit MaxInt64: %q, %v", out, ok)
	}
	if out, ok := Gunzip(b.Bytes(), -1); ok || len(out) != 0 {
		t.Errorf("limit -1: %q, %v", out, ok)
	}
}
