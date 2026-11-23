// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcschema

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

const (
	kString  = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_STRING
	kBytes   = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_BYTES
	kMessage = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_MESSAGE
	kVarint  = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_VARINT
)

// valid is a small schema Load accepts: /p.S/M reads p.Req, whose field 3
// is a p.Inner, and an Any.
func valid() *bundlev1.GRPCSchema {
	return &bundlev1.GRPCSchema{
		Id: "id",
		Methods: []*bundlev1.GRPCMethod{
			{Path: "/p.S/A", Input: 1, Output: 1},
			{Path: "/p.S/M", Input: 2, Output: 1},
		},
		Messages: []*bundlev1.GRPCMessage{
			{FullName: "google.protobuf.Any", Any: true, Fields: []*bundlev1.GRPCField{
				{Number: 1, Name: "type_url", Kind: kString}, {Number: 2, Name: "value", Kind: kBytes}}},
			{FullName: "p.Inner", Fields: []*bundlev1.GRPCField{{Number: 1, Name: "text", Kind: kString}}},
			{FullName: "p.Req", Fields: []*bundlev1.GRPCField{
				{Number: 1, Name: "name", Kind: kString},
				{Number: 2, Name: "n", Kind: kVarint, Repeated: true},
				{Number: 3, Name: "inner", Kind: kMessage, Message: 1},
				{Number: 4, Name: "any", Kind: kMessage, Message: 0},
				{Number: 1000, Name: "[p.ext]", Kind: kString},
			}},
		},
	}
}

func TestLoad(t *testing.T) {
	s, err := Load(valid())
	if err != nil {
		t.Fatal(err)
	}
	req := s.Method("/p.S/M")
	if req == nil || req.FullName != "p.Req" || s.Methods() != 2 || s.ID() != "id" {
		t.Fatalf("Method = %+v", req)
	}
	if f := req.Field(3); f == nil || f.Message != s.Message("p.Inner") {
		t.Fatalf("field 3 = %+v", f)
	}
	// Field 1000 makes p.Req sparse: searched, not indexed.
	if req.dense != nil || req.Field(1000).Name != "[p.ext]" || req.Field(999) != nil || req.Field(5) != nil {
		t.Fatal("sparse lookup")
	}
	if in := s.Message("p.Inner"); in.dense == nil || in.Field(1).Name != "text" || in.Field(2) != nil || in.Field(0) != nil {
		t.Fatal("dense lookup")
	}
	if s.AnyType("type.googleapis.com/p.Inner") != s.Message("p.Inner") || s.AnyType("x/y") != nil {
		t.Fatal("AnyType")
	}
	var none *Schema
	if none.Method("/p.S/M") != nil || none.Message("p.Req") != nil {
		t.Fatal("a nil schema describes something")
	}
}

func TestLoadRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bundlev1.GRPCSchema)
		want   string
	}{
		{"no id", func(s *bundlev1.GRPCSchema) { s.Id = "" }, "no id"},
		{"no method", func(s *bundlev1.GRPCSchema) { s.Methods = nil }, "no method"},
		{"unsorted methods", func(s *bundlev1.GRPCSchema) { s.Methods[0].Path = "/p.S/Z" }, "not sorted"},
		{"duplicate method", func(s *bundlev1.GRPCSchema) { s.Methods[0].Path = "/p.S/M" }, "not sorted"},
		{"input out of range", func(s *bundlev1.GRPCSchema) { s.Methods[1].Input = 3 }, "out of range"},
		{"output out of range", func(s *bundlev1.GRPCSchema) { s.Methods[1].Output = 1 << 31 }, "out of range"},
		{"bad path", func(s *bundlev1.GRPCSchema) { s.Methods[1].Path = "p.S/M" }, "not /package"},
		{"path without method", func(s *bundlev1.GRPCSchema) { s.Methods[1].Path = "/p.S/" }, "not /package"},
		{"long path", func(s *bundlev1.GRPCSchema) { s.Methods[1].Path = "/p.S/" + strings.Repeat("m", MaxFullName) }, "over"},
		{"type out of range", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[2].Message = 9 }, "out of range"},
		{"type for a string", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Message = 1 }, "isn't a message"},
		{"unknown kind", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Kind = 42 }, "unknown kind"},
		{"unspecified kind", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Kind = 0 }, "unknown kind"},
		{"number 0", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Number = 0 }, "out of range"},
		{"number too large", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[4].Number = 1 << 29 }, "out of range"},
		{"unsorted fields", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Number = 2 }, "not sorted"},
		{"bad field name", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Name = "a b" }, "not an identifier"},
		{"empty field name", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Name = "" }, "not an identifier"},
		{"long field name", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[0].Name = strings.Repeat("n", MaxFieldName+1) }, "over"},
		{"bad extension name", func(s *bundlev1.GRPCSchema) { s.Messages[2].Fields[4].Name = "[p.ext" }, "extension name"},
		{"bad full name", func(s *bundlev1.GRPCSchema) { s.Messages[1].FullName = "p..Inner" }, "full name"},
		{"duplicate message", func(s *bundlev1.GRPCSchema) { s.Messages[1].FullName = "p.Req" }, "twice"},
		{"Any without type_url", func(s *bundlev1.GRPCSchema) { s.Messages[0].Fields[0].Kind = kBytes }, "type_url"},
		{"Any without value", func(s *bundlev1.GRPCSchema) { s.Messages[0].Fields = s.Messages[0].Fields[:1] }, "value"},
		{"too many methods", func(s *bundlev1.GRPCSchema) {
			s.Methods = nil
			for i := range MaxMethods + 1 {
				s.Methods = append(s.Methods, &bundlev1.GRPCMethod{Path: fmt.Sprintf("/p.S/M%05d", i)})
			}
		}, "methods, over"},
		{"too many messages", func(s *bundlev1.GRPCSchema) {
			for i := range MaxMessages {
				s.Messages = append(s.Messages, &bundlev1.GRPCMessage{FullName: fmt.Sprintf("p.M%d", i)})
			}
		}, "messages, over"},
		{"too many fields in a message", func(s *bundlev1.GRPCSchema) {
			s.Messages[1].Fields = nil
			for i := range MaxMessageFields + 1 {
				s.Messages[1].Fields = append(s.Messages[1].Fields, &bundlev1.GRPCField{Number: uint32(i + 1), Name: "f", Kind: kString})
			}
		}, "fields, over"},
		{"too many fields", func(s *bundlev1.GRPCSchema) {
			for i := range MaxFields/MaxMessageFields + 1 {
				m := &bundlev1.GRPCMessage{FullName: fmt.Sprintf("p.W%d", i)}
				for j := range MaxMessageFields {
					m.Fields = append(m.Fields, &bundlev1.GRPCField{Number: uint32(j + 1), Name: "f", Kind: kString})
				}
				s.Messages = append(s.Messages, m)
			}
		}, "over 65536 fields"},
		{"over 1 MiB", func(s *bundlev1.GRPCSchema) { s.Source = strings.Repeat("s", MaxCompiledBytes) }, "bytes, over"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := valid()
			c.mutate(s)
			if _, err := Load(s); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load = %v, want an error with %q", err, c.want)
			}
		})
	}
}

// FuzzLoad: any bytes give an error or a schema whose every reference
// resolves, never a panic.
func FuzzLoad(f *testing.F) {
	b, err := proto.Marshal(valid())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		var b bundlev1.GRPCSchema
		if proto.Unmarshal(data, &b) != nil {
			return
		}
		s, err := Load(&b)
		if err != nil {
			return
		}
		for _, m := range s.messages {
			for _, f := range m.Fields() {
				if got := m.Field(f.Number); got == nil || got.Number != f.Number {
					t.Fatalf("%s: field %d not found", m.FullName, f.Number)
				}
				if (f.Kind == KindMessage || f.Kind == KindGroup) != (f.Message != nil) {
					t.Fatalf("%s.%s: kind %d, type %v", m.FullName, f.Name, f.Kind, f.Message)
				}
			}
		}
		for _, bm := range b.GetMethods() {
			if s.Method(bm.GetPath()) == nil {
				t.Fatalf("method %s not found", bm.GetPath())
			}
		}
	})
}
