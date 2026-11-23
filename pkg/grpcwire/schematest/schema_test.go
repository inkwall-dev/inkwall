// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"

	"google.golang.org/protobuf/encoding/protowire"
)

// Wire types, short.
const (
	wBytes = protowire.BytesType
	wGroup = protowire.StartGroupType
	wVar   = protowire.VarintType
	wF32   = protowire.Fixed32Type
	wF64   = protowire.Fixed64Type
)

// fl is the fields of name and value pairs.
func fl(pairs ...string) []grpcwire.Field {
	var out []grpcwire.Field
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, grpcwire.Field{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

// f builds a message of fields: triples of number, wire type and value.
func f(fields ...any) []byte {
	var b []byte
	for i := 0; i+2 < len(fields); i += 3 {
		b = tagged(b, protowire.Number(fields[i].(int)), fields[i+1].(protowire.Type), fields[i+2])
	}
	return b
}

func TestFields(t *testing.T) {
	s := testSchema(t)
	req := s.Method("/t.S/Call")
	if req == nil {
		t.Fatal("/t.S/Call isn't described")
	}
	item := f(1, wBytes, "sku-1", 2, wVar, uint64(3))
	user := f(1, wBytes, "alice", 2, wBytes, "a@example.com")
	anyOf := func(typeURL string, value []byte) []byte { return f(1, wBytes, typeURL, 2, wBytes, value) }
	deep := f(1, wBytes, "x")
	for range 30 {
		deep = f(14, wBytes, deep)
	}
	tests := []struct {
		name    string
		msg     []byte
		want    []grpcwire.Field
		unknown int
		ok      bool
	}{
		{"empty", nil, nil, 0, true},
		{"string", f(1, wBytes, "world"), fl("name", "world"), 0, true},
		{"string with a control character", f(1, wBytes, "a\x00b\tc"), fl("name", "a b\tc"), 0, true},
		{"string not UTF-8", f(1, wBytes, "a\xffb"), fl("name", "a b"), 0, true},
		{"string that is a message", f(1, wBytes, "\x0a\x02ab"), fl("name", "\n ab"), 0, true},
		// bytes: runs of 12 or more readable characters only, never whole.
		{"printable bytes", f(2, wBytes, "' or 1=1#"), fl("blob", "' or 1=1#"), 0, true},
		{"binary bytes, a short run", f(2, wBytes, "\x00|W`W\xff"), nil, 0, true},
		{"bytes run under 12", f(2, wBytes, "\x00' OR 1=1--\xff"), nil, 0, true},
		{"bytes", f(2, wBytes, "\x00\x01'; DROP TABLE x--\xff"), fl("blob", "'; DROP TABLE x--"), 0, true},
		// Mostly printable UTF-8 of 8 bytes or more: whole, a control
		// character a space.
		{"bytes, a control character in text", f(2, wBytes, "1'/*\x01*/OR/*\x01*/'1'='1'--"), fl("blob", "1'/* */OR/* */'1'='1'--"), 0, true},
		{"bytes, a trailing NUL", f(2, wBytes, "' OR 1=1--\x00"), fl("blob", "' OR 1=1-- "), 0, true},
		{"bytes, mostly control characters", f(2, wBytes, "\x01\x02\x03\x04\x05ab=1"), nil, 0, true},
		{"bytes that are a message", f(2, wBytes, f(1, wBytes, "hidden attack text")), fl("blob", "\n hidden attack text"), 0, true},
		// A string whose bytes parse as a message with a printable tag ('r',
		// field 14): read whole by its type. Without the schema, the tag keeps
		// it from being read whole (#863's known gap).
		{"string with a printable tag", f(1, wBytes, "r\x06SELECT"), fl("name", "r SELECT"), 0, true},
		// A message whose tags, lengths and numbers are blank is also read
		// whole, flat, as Strings reads it (#863).
		{"nested", f(3, wBytes, user), fl("user.name", "alice", "user.email", "a@example.com", "user", "alice  a@example.com"), 0, true},
		// A string declared a message: its bytes, printable, are read whole.
		{"message printable", f(3, wBytes, "Hi"), fl("user", "Hi"), 1, true},
		{"message that isn't one", f(3, wBytes, "hello"), fl("user", "hello"), 1, true},
		{"repeated, no index", f(5, wBytes, item, 5, wBytes, f(1, wBytes, "sku-2")), fl("items.sku", "sku-1", "items", "sku-1", "items.sku", "sku-2", "items", "sku-2"), 0, true},
		{"packed numbers", f(4, wBytes, []byte{1, 2, 0x96, 0x01}), nil, 0, true},
		{"packed text", f(4, wBytes, "; cat /etc/passwd"), fl("ids", "; cat /etc/passwd"), 0, true},
		// Packed numbers are read as bytes: whole when printable.
		{"packed text, short", f(4, wBytes, "' OR 1=1--"), fl("ids", "' OR 1=1--"), 0, true},
		// Not a list of fixed32s (a length not a multiple of 4): unknown.
		{"packed fixed32s that aren't", f(15, wBytes, "' OR 1=1#"), fl("fixed", "' OR 1=1#"), 1, true},
		// A last byte from 0x80 doesn't end a varint: its runs of 8 or more,
		// as Strings reads binary.
		{"packed varints that aren't", f(4, wBytes, "' OR 1=1--\x80"), fl("ids", "' OR 1=1--"), 1, true},
		{"unpacked numbers", f(4, wVar, uint64(1), 4, wVar, uint64(2), 11, wF32, uint64(7), 12, wF64, uint64(9), 13, wVar, uint64(1)), nil, 0, true},
		{"map", f(6, wBytes, f(1, wBytes, "env", 2, wBytes, "prod")), fl("labels.key", "env", "labels.value", "prod", "labels", "env  prod"), 0, true},
		// An Any of a type the schema has: its value by that type only.
		{"Any", f(7, wBytes, anyOf("type.googleapis.com/t.Item", item)), fl("payload.type_url", "type.googleapis.com/t.Item", "payload.sku", "sku-1",
			"payload", "type.googleapis.com/t.Item    sku-1"), 0, true},
		{"Any, value first", f(7, wBytes, f(2, wBytes, item, 1, wBytes, "t.Item")), fl("payload.sku", "sku-1",
			"payload.type_url", "t.Item", "payload", "sku-1    t.Item"), 0, true},
		// Not a message: without the schema.
		{"Any of a known type, not a message", f(7, wBytes, anyOf("t.Item", []byte("\x0a\x05ab"))), fl("payload.type_url", "t.Item", "payload.value", "\n ab", "payload", "t.Item    ab"), 0, true},
		{"Any of an unknown type", f(7, wBytes, anyOf("type.googleapis.com/t.Nope", item)),
			fl("payload.type_url", "type.googleapis.com/t.Nope", "payload.value.1", "sku-1",
				"payload.value", "sku-1", "payload", "type.googleapis.com/t.Nope    sku-1"), 0, true},
		{"Any of two types: the last", f(7, wBytes, f(1, wBytes, "t.Item", 1, wBytes, "t.User", 2, wBytes, item)),
			fl("payload.type_url", "t.Item", "payload.type_url", "t.User", "payload.name", "sku-1",
				"payload", "t.Item  t.User    sku-1"), 1, true},
		{"Any, the last type_url unknown", f(7, wBytes, f(1, wBytes, "t.Item", 1, wBytes, "t.Nope", 2, wBytes, item)),
			fl("payload.type_url", "t.Item", "payload.type_url", "t.Nope", "payload.value.1", "sku-1",
				"payload.value", "sku-1", "payload", "t.Item  t.Nope    sku-1"), 0, true},
		{"Any's unknown field", f(7, wBytes, f(1, wBytes, "t.Item", 3, wBytes, "smuggled")), fl("payload.type_url", "t.Item", "payload.3", "smuggled", "payload", "t.Item  smuggled"), 1, true},
		{"group", f(8, wGroup, f(1, wBytes, "in a group")), fl("grp.g", "in a group"), 0, true},
		{"oneof, both members", f(9, wBytes, "first", 10, wBytes, "second"), fl("a", "first", "b", "second"), 0, true},
		{"singular twice", f(1, wBytes, "one", 1, wBytes, "two"), fl("name", "one", "name", "two"), 0, true},
		{"extension", f(100, wBytes, "noted"), fl("[t.note]", "noted"), 0, true},
		{"recursive", f(14, wBytes, f(14, wBytes, f(1, wBytes, "leaf"))), fl("children.children.name", "leaf", "children.children", "leaf"), 0, true},
		// The outer message's tag (field 14, 'r') is printable: no whole text there.
		// Unknown: read schema-less, named by number.
		{"unknown number", f(50, wBytes, "smuggled"), fl("50", "smuggled"), 1, true},
		{"unknown nested number", f(3, wBytes, f(7, wBytes, "smuggled")), fl("user.7", "smuggled"), 1, true},
		{"unknown nested message", f(50, wBytes, f(1, wBytes, "deep")), fl("50.1", "deep", "50", "deep"), 1, true},
		{"string sent as a number", f(1, wVar, uint64(5)), nil, 1, true},
		{"number sent as bytes", f(11, wBytes, "' OR 1"), fl("11", "' OR 1"), 1, true},
		{"message sent as a group", f(3, wGroup, f(1, wBytes, "alice")), fl("3.1", "alice"), 1, true},
		{"group sent as bytes", f(8, wBytes, "text"), fl("8", "text"), 1, true},
		{"bool sent as fixed64", f(13, wF64, uint64(1)), nil, 1, true},
		// Not read whole.
		{"not protobuf", []byte("\x0a\x05ab"), nil, 0, false},
		{"end group alone", []byte{0x0c}, nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unknown, ok := grpcwire.Fields(tt.msg, s, req, grpcwire.DefaultLimits, nil)
			if ok != tt.ok || unknown != tt.unknown || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Fields = %q, %d, %v; want %q, %d, %v", got, unknown, ok, tt.want, tt.unknown, tt.ok)
			}
		})
	}

	// A path over grpcwire.MaxName keeps its first grpcwire.MaxName-1
	// bytes and ends in grpcwire.LongPath, which no exclusion names.
	got, _, ok := grpcwire.Fields(deep, s, req, grpcwire.Limits{Depth: 64, Fields: 64}, nil)
	if last := got[len(got)-1]; !ok || len(got) == 0 || len(last.Name) != grpcwire.MaxName || !strings.HasPrefix(last.Name, "children.children.") ||
		!strings.HasSuffix(last.Name, grpcwire.LongPath) || last.Value != "x" {
		t.Errorf("a long path: %q, %v", got, ok)
	}
	if regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`).MatchString(grpcwire.LongPath) {
		t.Errorf("an exclusion (ArgumentPattern) can name %q", grpcwire.LongPath)
	}
	// Too deep, too many fields: not read whole, with what was read.
	if _, _, ok := grpcwire.Fields(deep, s, req, grpcwire.Limits{Depth: 16, Fields: 64}, nil); ok {
		t.Error("a message 31 deep read whole within a depth of 16")
	}
	many := f(1, wBytes, "a", 1, wBytes, "b", 1, wBytes, "c")
	if got, _, ok := grpcwire.Fields(many, s, req, grpcwire.Limits{Depth: 16, Fields: 2}, nil); ok || len(got) != 2 {
		t.Errorf("over the field limit: %q, %v", got, ok)
	}
	// Appends to out.
	if got, _, _ := grpcwire.Fields(f(1, wBytes, "x"), s, req, grpcwire.DefaultLimits, fl("k", "v")); len(got) != 2 || got[0].Name != "k" {
		t.Errorf("out not appended to: %q", got)
	}
}

// TestFieldsReadsWhatStringsReads: what the schema doesn't describe (a
// message of a type without fields) is read exactly as grpcwire.Strings reads it.
func TestFieldsReadsWhatStringsReads(t *testing.T) {
	s := testSchema(t)
	empty := s.Message("google.protobuf.Any") // has fields 1 and 2: use field numbers above them
	msg := f(3, wBytes, f(1, wBytes, "alice", 9, wGroup, f(2, wBytes, "in group")), 4, wBytes, "\x00\x01binary run here\x02", 5, wVar, uint64(9))
	want, wantOK := grpcwire.Strings(msg, grpcwire.DefaultLimits, nil)
	got, unknown, ok := grpcwire.Fields(msg, s, empty, grpcwire.DefaultLimits, nil)
	if ok != wantOK || unknown != 3 || !reflect.DeepEqual(got, want) {
		t.Errorf("Fields = %q, %d, %v; grpcwire.Strings = %q, %v", got, unknown, ok, want, wantOK)
	}
}
