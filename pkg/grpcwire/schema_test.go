// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"reflect"
	"strings"
	"testing"

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
		want    []Field
		unknown int
		ok      bool
	}{
		{"empty", nil, nil, 0, true},
		{"string", f(1, wBytes, "world"), []Field{{"name", "world"}}, 0, true},
		{"string with a control character", f(1, wBytes, "a\x00b\tc"), []Field{{"name", "a b\tc"}}, 0, true},
		{"string not UTF-8", f(1, wBytes, "a\xffb"), []Field{{"name", "a b"}}, 0, true},
		{"string that is a message", f(1, wBytes, "\x0a\x02ab"), []Field{{"name", "\n ab"}}, 0, true},
		// bytes: runs of 12 or more readable characters only, never whole.
		{"short bytes", f(2, wBytes, "|W`W"), nil, 0, true},
		{"bytes run under 12", f(2, wBytes, "\x00' OR 1=1--\xff"), nil, 0, true},
		{"bytes", f(2, wBytes, "\x00\x01'; DROP TABLE x--\xff"), []Field{{"blob", "'; DROP TABLE x--"}}, 0, true},
		{"bytes that are a message", f(2, wBytes, f(1, wBytes, "hidden attack text")), []Field{{"blob", "hidden attack text"}}, 0, true},
		{"nested", f(3, wBytes, user), []Field{{"user.name", "alice"}, {"user.email", "a@example.com"}}, 0, true},
		// A string declared a message: its bytes, printable, are read whole.
		{"message printable", f(3, wBytes, "Hi"), []Field{{"user", "Hi"}}, 1, true},
		{"message that isn't one", f(3, wBytes, "hello"), []Field{{"user", "hello"}}, 1, true},
		{"repeated, no index", f(5, wBytes, item, 5, wBytes, f(1, wBytes, "sku-2")), []Field{{"items.sku", "sku-1"}, {"items.sku", "sku-2"}}, 0, true},
		{"packed numbers", f(4, wBytes, []byte{1, 2, 0x96, 0x01}), nil, 0, true},
		{"packed text", f(4, wBytes, "; cat /etc/passwd"), []Field{{"ids", "; cat /etc/passwd"}}, 0, true},
		{"unpacked numbers", f(4, wVar, uint64(1), 4, wVar, uint64(2), 11, wF32, uint64(7), 12, wF64, uint64(9), 13, wVar, uint64(1)), nil, 0, true},
		{"map", f(6, wBytes, f(1, wBytes, "env", 2, wBytes, "prod")), []Field{{"labels.key", "env"}, {"labels.value", "prod"}}, 0, true},
		{"Any", f(7, wBytes, anyOf("type.googleapis.com/t.Item", item)), []Field{{"payload.type_url", "type.googleapis.com/t.Item"}, {"payload.sku", "sku-1"}}, 0, true},
		{"Any, value first", f(7, wBytes, f(2, wBytes, item, 1, wBytes, "t.Item")), []Field{{"payload.sku", "sku-1"}, {"payload.type_url", "t.Item"}}, 0, true},
		{"Any of an unknown type", f(7, wBytes, anyOf("type.googleapis.com/t.Nope", item)),
			[]Field{{"payload.type_url", "type.googleapis.com/t.Nope"}, {"payload.value.1", "sku-1"}}, 0, true},
		{"Any of two types", f(7, wBytes, f(1, wBytes, "t.Item", 1, wBytes, "t.User", 2, wBytes, item)),
			[]Field{{"payload.type_url", "t.Item"}, {"payload.type_url", "t.User"}, {"payload.sku", "sku-1"}, {"payload.name", "sku-1"}}, 1, true},
		{"Any of a known and an unknown type", f(7, wBytes, f(1, wBytes, "t.Item", 1, wBytes, "t.Nope", 2, wBytes, item)),
			[]Field{{"payload.type_url", "t.Item"}, {"payload.type_url", "t.Nope"}, {"payload.sku", "sku-1"}, {"payload.value.1", "sku-1"}}, 0, true},
		{"Any's unknown field", f(7, wBytes, f(1, wBytes, "t.Item", 3, wBytes, "smuggled")), []Field{{"payload.type_url", "t.Item"}, {"payload.3", "smuggled"}}, 1, true},
		{"group", f(8, wGroup, f(1, wBytes, "in a group")), []Field{{"grp.g", "in a group"}}, 0, true},
		{"oneof, both members", f(9, wBytes, "first", 10, wBytes, "second"), []Field{{"a", "first"}, {"b", "second"}}, 0, true},
		{"singular twice", f(1, wBytes, "one", 1, wBytes, "two"), []Field{{"name", "one"}, {"name", "two"}}, 0, true},
		{"extension", f(100, wBytes, "noted"), []Field{{"[t.note]", "noted"}}, 0, true},
		{"recursive", f(14, wBytes, f(14, wBytes, f(1, wBytes, "leaf"))), []Field{{"children.children.name", "leaf"}}, 0, true},
		// Unknown: read schema-less, named by number.
		{"unknown number", f(50, wBytes, "smuggled"), []Field{{"50", "smuggled"}}, 1, true},
		{"unknown nested number", f(3, wBytes, f(7, wBytes, "smuggled")), []Field{{"user.7", "smuggled"}}, 1, true},
		{"unknown nested message", f(50, wBytes, f(1, wBytes, "deep")), []Field{{"50.1", "deep"}}, 1, true},
		{"string sent as a number", f(1, wVar, uint64(5)), nil, 1, true},
		{"number sent as bytes", f(11, wBytes, "' OR 1"), []Field{{"11", "' OR 1"}}, 1, true},
		{"message sent as a group", f(3, wGroup, f(1, wBytes, "alice")), []Field{{"3.1", "alice"}}, 1, true},
		{"group sent as bytes", f(8, wBytes, "text"), []Field{{"8", "text"}}, 1, true},
		{"bool sent as fixed64", f(13, wF64, uint64(1)), nil, 1, true},
		// Not read whole.
		{"not protobuf", []byte("\x0a\x05ab"), nil, 0, false},
		{"end group alone", []byte{0x0c}, nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unknown, ok := Fields(tt.msg, s, req, DefaultLimits, nil)
			if ok != tt.ok || unknown != tt.unknown || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Fields = %q, %d, %v; want %q, %d, %v", got, unknown, ok, tt.want, tt.unknown, tt.ok)
			}
		})
	}

	// A path over MaxName keeps its first MaxName bytes.
	got, _, ok := Fields(deep, s, req, Limits{Depth: 64, Fields: 64}, nil)
	if !ok || len(got) != 1 || len(got[0].Name) != MaxName || !strings.HasPrefix(got[0].Name, "children.children.") || got[0].Value != "x" {
		t.Errorf("a long path: %q, %v", got, ok)
	}
	// Too deep, too many fields: not read whole, with what was read.
	if _, _, ok := Fields(deep, s, req, Limits{Depth: 16, Fields: 64}, nil); ok {
		t.Error("a message 31 deep read whole within a depth of 16")
	}
	many := f(1, wBytes, "a", 1, wBytes, "b", 1, wBytes, "c")
	if got, _, ok := Fields(many, s, req, Limits{Depth: 16, Fields: 2}, nil); ok || len(got) != 2 {
		t.Errorf("over the field limit: %q, %v", got, ok)
	}
	// Appends to out.
	if got, _, _ := Fields(f(1, wBytes, "x"), s, req, DefaultLimits, []Field{{"k", "v"}}); len(got) != 2 || got[0].Name != "k" {
		t.Errorf("out not appended to: %q", got)
	}
}

// TestFieldsReadsWhatStringsReads: what the schema doesn't describe (a
// message of a type without fields) is read exactly as Strings reads it.
func TestFieldsReadsWhatStringsReads(t *testing.T) {
	s := testSchema(t)
	empty := s.Message("google.protobuf.Any") // has fields 1 and 2: use field numbers above them
	msg := f(3, wBytes, f(1, wBytes, "alice", 9, wGroup, f(2, wBytes, "in group")), 4, wBytes, "\x00\x01binary run here\x02", 5, wVar, uint64(9))
	want, wantOK := Strings(msg, DefaultLimits, nil)
	got, unknown, ok := Fields(msg, s, empty, DefaultLimits, nil)
	if ok != wantOK || unknown != 3 || !reflect.DeepEqual(got, want) {
		t.Errorf("Fields = %q, %d, %v; Strings = %q, %v", got, unknown, ok, want, wantOK)
	}
}
