// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// benchFile describes BenchmarkGRPCMessages' messages:
//
//	message Req { string email = 1; int64 n = 2; Addr addr = 3; repeated Item items = 4; }
//	message Addr { string kind = 1; string street = 2; }
//	message Item { string name = 1; Desc desc = 2; int64 n = 3; }
//	message Desc { string text = 1; Deep deep = 2; }
//	message Deep { string text = 1; }
//	service B { rpc Call(Req) returns (Req); }
func benchFile() *descriptorpb.FileDescriptorProto {
	msg := func(name string, fields ...*fdp) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
	}
	return &descriptorpb.FileDescriptorProto{
		Name: proto.String("b.proto"), Package: proto.String("b"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			msg("Req", dfield("email", 1, tString, ""), dfield("n", 2, tInt64, ""), dfield("addr", 3, tMessage, ".b.Addr"),
				drepeated(dfield("items", 4, tMessage, ".b.Item"))),
			msg("Addr", dfield("kind", 1, tString, ""), dfield("street", 2, tString, "")),
			msg("Item", dfield("name", 1, tString, ""), dfield("desc", 2, tMessage, ".b.Desc"), dfield("n", 3, tInt64, "")),
			msg("Desc", dfield("text", 1, tString, ""), dfield("deep", 2, tMessage, ".b.Deep")),
			msg("Deep", dfield("text", 1, tString, "")),
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("B"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Call"), InputType: proto.String(".b.Req"), OutputType: proto.String(".b.Req"),
		}}}},
	}
}

// largestDescriptor is the largest file descriptor linked into the test,
// serialized: a large message with thousands of text fields (design 0013
// §6.6 measured a 33 KB one).
func largestDescriptor(t testing.TB) []byte {
	var largest []byte
	protoregistry.GlobalFiles.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		b, err := proto.Marshal(protodesc.ToFileDescriptorProto(f))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > len(largest) {
			largest = b
		}
		return true
	})
	return largest
}

type benchCase struct {
	name   string
	body   []byte
	schema *grpcschema.Schema
	typ    *grpcschema.Message
}

// benchCases are BenchmarkGRPCMessages' inputs, with their schema, and the
// largest linked descriptor with descriptor.proto's.
func benchCases(b testing.TB) []benchCase {
	small := pb(1, "alice@example.com", 2, uint64(42), 3, pb(1, "shipping", 2, "221B Baker Street"))
	var large []byte
	for i := range 50 {
		large = append(large, pb(4, pb(1, fmt.Sprintf("item-%d", i), 2, pb(1, "a description of the item", 2, pb(1, "deep")), 3, uint64(i)))...)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(large)
	_ = w.Close()
	s := schemaOf(b, benchFile())
	req := s.Method("/b.B/Call")
	ds, dmd := descriptorSchema(b)
	return []benchCase{
		{"small", prefixed(false, small), s, req},
		{"three_small", append(append(prefixed(false, small), prefixed(false, small)...), prefixed(false, small)...), s, req},
		{"large", prefixed(false, large), s, req},
		{"large_gzip", prefixed(true, gz.Bytes()), s, req},
		{"descriptor", prefixed(false, largestDescriptor(b)), ds, ds.Message(string(dmd.FullName()))},
	}
}

// read reads c's body, as the pipeline does, with the schema (or without:
// Strings).
func (c benchCase) read(b testing.TB, schema bool, out []Field) []Field {
	msgs, ok := Messages(c.body, false)
	if !ok {
		b.Fatal("not gRPC messages")
	}
	out = out[:0]
	for _, m := range msgs {
		data := m.Data
		if m.Compressed {
			if data, ok = Gunzip(data, 1<<20); !ok {
				b.Fatal("gunzip")
			}
		}
		if schema {
			out, _, ok = Fields(data, c.schema, c.typ, Limits{Depth: 16, Fields: 4096}, out)
		} else {
			out, ok = Strings(data, Limits{Depth: 16, Fields: 4096}, out)
		}
		if !ok {
			b.Fatal("not read whole")
		}
	}
	if len(out) == 0 {
		b.Fatal("no text")
	}
	return out
}

// BenchmarkGRPCFields (design 0013 §7): reading a call's messages with
// their schema, on BenchmarkGRPCMessages' inputs and the largest linked
// descriptor, against reading them without (strings).
func BenchmarkGRPCFields(b *testing.B) {
	for _, c := range benchCases(b) {
		for _, reader := range []string{"schema", "strings"} {
			b.Run(c.name+"/"+reader, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(c.body)))
				var out []Field
				for b.Loop() {
					out = c.read(b, reader == "schema", out)
				}
			})
		}
	}
}

// TestFieldsAllocatesLess holds Fields to design 0013 §7's budget where it
// is deterministic: on each benchmark input, at most 0.8 times the
// allocations of Strings (the times are BenchmarkGRPCFields'). Names are
// built once per field and prefix, not once per value.
func TestFieldsAllocatesLess(t *testing.T) {
	for _, c := range benchCases(t) {
		allocs := func(schema bool) float64 {
			var out []Field
			return testing.AllocsPerRun(50, func() { out = c.read(t, schema, out) })
		}
		fields, strings := allocs(true), allocs(false)
		if fields > 0.8*strings {
			t.Errorf("%s: Fields %.0f allocations, over 0.8 x Strings' %.0f", c.name, fields, strings)
		}
	}
}
