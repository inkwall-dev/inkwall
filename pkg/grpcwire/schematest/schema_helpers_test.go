// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
)

type fdp = descriptorpb.FieldDescriptorProto

const (
	tString   = descriptorpb.FieldDescriptorProto_TYPE_STRING
	tBytes    = descriptorpb.FieldDescriptorProto_TYPE_BYTES
	tMessage  = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	tGroup    = descriptorpb.FieldDescriptorProto_TYPE_GROUP
	tInt64    = descriptorpb.FieldDescriptorProto_TYPE_INT64
	tInt32    = descriptorpb.FieldDescriptorProto_TYPE_INT32
	tBool     = descriptorpb.FieldDescriptorProto_TYPE_BOOL
	tFixed32  = descriptorpb.FieldDescriptorProto_TYPE_FIXED32
	tDouble   = descriptorpb.FieldDescriptorProto_TYPE_DOUBLE
	tEnum     = descriptorpb.FieldDescriptorProto_TYPE_ENUM
	lOptional = descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	lRepeated = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
)

func dfield(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *fdp {
	f := &fdp{Name: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(), Label: lOptional.Enum()}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func drepeated(f *fdp) *fdp {
	f.Label = lRepeated.Enum()
	return f
}

// testFile is t.proto, proto2 (for groups and extensions):
//
//	message Req {
//	  optional string name = 1;
//	  optional bytes blob = 2;
//	  optional User user = 3;
//	  repeated int64 ids = 4 [packed = true];
//	  repeated Item items = 5;
//	  map<string, string> labels = 6;
//	  optional google.protobuf.Any payload = 7;
//	  optional group Grp = 8 { optional string g = 1; }
//	  oneof choice { string a = 9; string b = 10; }
//	  optional fixed32 f32 = 11;
//	  optional double d = 12;
//	  optional bool flag = 13;
//	  repeated Req children = 14;
//	  repeated fixed32 fixed = 15;
//	  extensions 100 to 200;
//	}
//	message User { optional string name = 1; optional string email = 2; }
//	message Item { optional string sku = 1; optional int32 qty = 2; }
//	extend Req { optional string note = 100; }
//	service S { rpc Call(Req) returns (Item); }
func testFile() *descriptorpb.FileDescriptorProto {
	entry := &descriptorpb.DescriptorProto{
		Name:    proto.String("LabelsEntry"),
		Field:   []*fdp{dfield("key", 1, tString, ""), dfield("value", 2, tString, "")},
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
	}
	grp := &descriptorpb.DescriptorProto{Name: proto.String("Grp"), Field: []*fdp{dfield("g", 1, tString, "")}}
	ids := drepeated(dfield("ids", 4, tInt64, ""))
	ids.Options = &descriptorpb.FieldOptions{Packed: proto.Bool(true)}
	a, b := dfield("a", 9, tString, ""), dfield("b", 10, tString, "")
	a.OneofIndex, b.OneofIndex = proto.Int32(0), proto.Int32(0)
	req := &descriptorpb.DescriptorProto{
		Name: proto.String("Req"),
		Field: []*fdp{
			dfield("name", 1, tString, ""),
			dfield("blob", 2, tBytes, ""),
			dfield("user", 3, tMessage, ".t.User"),
			ids,
			drepeated(dfield("items", 5, tMessage, ".t.Item")),
			drepeated(dfield("labels", 6, tMessage, ".t.Req.LabelsEntry")),
			dfield("payload", 7, tMessage, ".google.protobuf.Any"),
			dfield("grp", 8, tGroup, ".t.Req.Grp"),
			a, b,
			dfield("f32", 11, tFixed32, ""),
			dfield("d", 12, tDouble, ""),
			dfield("flag", 13, tBool, ""),
			drepeated(dfield("children", 14, tMessage, ".t.Req")),
			drepeated(dfield("fixed", 15, tFixed32, "")),
		},
		NestedType:     []*descriptorpb.DescriptorProto{entry, grp},
		OneofDecl:      []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
		ExtensionRange: []*descriptorpb.DescriptorProto_ExtensionRange{{Start: proto.Int32(100), End: proto.Int32(201)}},
	}
	note := dfield("note", 100, tString, "")
	note.Extendee = proto.String(".t.Req")
	return &descriptorpb.FileDescriptorProto{
		Name:       proto.String("t.proto"),
		Package:    proto.String("t"),
		Syntax:     proto.String("proto2"),
		Dependency: []string{"google/protobuf/any.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			req,
			{Name: proto.String("User"), Field: []*fdp{dfield("name", 1, tString, ""), dfield("email", 2, tString, "")}},
			{Name: proto.String("Item"), Field: []*fdp{dfield("sku", 1, tString, ""), dfield("qty", 2, tInt32, "")}},
		},
		Extension: []*fdp{note},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name:   proto.String("S"),
			Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Call"), InputType: proto.String(".t.Req"), OutputType: proto.String(".t.Item")}},
		}},
	}
}

// schemaOf compiles files as the operator does and loads the schema as an
// engine does.
func schemaOf(t testing.TB, files ...*descriptorpb.FileDescriptorProto) *grpcschema.Schema {
	t.Helper()
	data, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: files})
	if err != nil {
		t.Fatal(err)
	}
	c, err := compile.Compile(data, "test")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s, err := load.Load(c)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return s
}

// testSchema is t.proto's schema, with google/protobuf/any.proto.
func testSchema(t testing.TB) *grpcschema.Schema {
	t.Helper()
	return schemaOf(t, protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto), testFile())
}

// withImports returns f's file and its imports, imports first.
func withImports(f protoreflect.FileDescriptor) []*descriptorpb.FileDescriptorProto {
	var out []*descriptorpb.FileDescriptorProto
	seen := map[string]bool{}
	var add func(f protoreflect.FileDescriptor)
	add = func(f protoreflect.FileDescriptor) {
		if seen[f.Path()] {
			return
		}
		seen[f.Path()] = true
		for i := range f.Imports().Len() {
			add(f.Imports().Get(i).FileDescriptor)
		}
		out = append(out, protodesc.ToFileDescriptorProto(f))
	}
	add(f)
	return out
}

// tagged appends field num with wire type typ and value v (bytes for
// BytesType and StartGroupType, a uint64 for numbers).
func tagged(b []byte, num protowire.Number, typ protowire.Type, v any) []byte {
	b = protowire.AppendTag(b, num, typ)
	switch typ {
	case protowire.BytesType:
		return protowire.AppendBytes(b, toBytes(v))
	case protowire.StartGroupType:
		b = append(b, toBytes(v)...)
		return protowire.AppendTag(b, num, protowire.EndGroupType)
	case protowire.VarintType:
		return protowire.AppendVarint(b, v.(uint64))
	case protowire.Fixed32Type:
		return protowire.AppendFixed32(b, uint32(v.(uint64)))
	case protowire.Fixed64Type:
		return protowire.AppendFixed64(b, v.(uint64))
	}
	return b
}

func toBytes(v any) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	return v.([]byte)
}
