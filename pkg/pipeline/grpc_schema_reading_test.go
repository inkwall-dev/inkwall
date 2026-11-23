// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// TestGRPCSchemaHidesNothing: text the schema-less reader denies in a
// bytes field or a packed repeated number is denied with the schema too:
// a control character in it, a short value, a string sent where a
// repeated number is declared (a stale schema).
//
//	message Req { bytes blob = 1; repeated int64 ids = 2; }
//	service S { rpc Call(Req) returns (Req); }
func TestGRPCSchemaHidesNothing(t *testing.T) {
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	s := compiled(t, &descriptorpb.FileDescriptorProto{
		Name: proto.String("p.proto"), Package: proto.String("p"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Req"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("blob"), Number: proto.Int32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(), Label: opt},
				{Name: proto.String("ids"), Number: proto.Int32(2), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(), Label: rep},
			},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("S"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Call"), InputType: proto.String(".p.Req"), OutputType: proto.String(".p.Req")}}}},
	})
	with, without := schemaPipeline(t, s), schemaPipeline(t, nil)
	for _, c := range []struct {
		name string
		num  protowire.Number
		v    string
	}{
		{"bytes, a control character every few bytes", 1, "1'/*\x01*/OR/*\x01*/'1'='1'--"},
		{"bytes, a trailing NUL", 1, "' OR 1=1--\x00"},
		{"bytes, short", 1, "' OR 1=1--"},
		{"a repeated number sent as bytes", 2, "' OR 1=1--"},
		{"a repeated number sent as bytes, a command", 2, ";cat /etc/passwd"},
	} {
		msg := protowire.AppendString(protowire.AppendTag(nil, c.num, protowire.BytesType), c.v)
		call := func(p *pipeline.Pipeline) pipeline.Verdict {
			return p.Check(context.Background(), grpcCall("/p.S/Call", "application/grpc", grpcFrame(msg)))
		}
		if b := call(without); b.Action != pipeline.ActionDeny {
			t.Fatalf("%s: not denied without the schema: %+v", c.name, b)
		}
		if a := call(with); a.Action != pipeline.ActionDeny {
			t.Errorf("%s: the schema hides what the schema-less reader denies: %+v", c.name, a)
		}
	}
}

// TestGRPCSchemaAnyChainCost: Anys nested in Anys, of a type the schema
// has, cost about what the same message costs read without the schema:
// each value is read by its type, not also without it (that took 8 times
// as long with the CRS).
//
//	message Req { string s = 1; google.protobuf.Any p = 7; }
func TestGRPCSchemaAnyChainCost(t *testing.T) {
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	s := compiled(t, protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto), &descriptorpb.FileDescriptorProto{
		Name: proto.String("w.proto"), Package: proto.String("w"), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/any.proto"},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Req"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("s"), Number: proto.Int32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: opt},
				{Name: proto.String("p"), Number: proto.Int32(7), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), Label: opt, TypeName: proto.String(".google.protobuf.Any")},
			},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("S"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Call"), InputType: proto.String(".w.Req"), OutputType: proto.String(".w.Req")}}}},
	})
	inner := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), strings.Repeat("hello world ", 8300)) // 100 KB of text
	for range 7 {
		a := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "type.googleapis.com/w.Req")
		a = protowire.AppendBytes(protowire.AppendTag(a, 2, protowire.BytesType), inner)
		inner = protowire.AppendBytes(protowire.AppendTag(nil, 7, protowire.BytesType), a)
	}
	took := func(p *pipeline.Pipeline) time.Duration {
		start := time.Now()
		if v := p.Check(context.Background(), grpcCall("/w.S/Call", "application/grpc", grpcFrame(inner))); v.Action != pipeline.ActionAllow {
			t.Fatalf("text without an attack: %+v", v)
		}
		return time.Since(start)
	}
	with, without := took(schemaPipeline(t, s)), took(schemaPipeline(t, nil))
	t.Logf("%d bytes: %v with the schema, %v without", len(inner), with, without)
	if with > 3*without+time.Second {
		t.Errorf("%v with the schema, %v without", with, without)
	}
}
