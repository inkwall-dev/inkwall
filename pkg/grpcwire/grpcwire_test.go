// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"compress/gzip"
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
		{"nested", pb(2, pb(1, "inner", 3, uint64(7)), 4, "outer"), []Field{{"2.1", "inner"}, {"4", "outer"}}, true},
		{"binary", pb(1, []byte{0, 1, 2, 0xff}), nil, true},
		{"unicode", pb(1, "Zoë 李\n\ttab"), []Field{{"1", "Zoë 李\n\ttab"}}, true},
		{"control", pb(1, "a\x00b"), nil, true},
		{"invalid utf-8", pb(1, "a\xffb"), nil, true},
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
