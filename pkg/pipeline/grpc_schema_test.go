// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// compiled compiles files (with their imports first) as the operator
// does, and loads the schema as an engine does.
func compiled(t testing.TB, files ...*descriptorpb.FileDescriptorProto) *grpcschema.Schema {
	t.Helper()
	data, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: files})
	if err != nil {
		t.Fatal(err)
	}
	c, err := compile.Compile(data, "test/schema/set.binpb")
	if err != nil {
		t.Fatal(err)
	}
	s, err := load.Load(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fileOf(f protoreflect.FileDescriptor) *descriptorpb.FileDescriptorProto {
	return protodesc.ToFileDescriptorProto(f)
}

func schemaPipeline(t *testing.T, s *grpcschema.Schema, exclusions ...coraza.Exclusion) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if eval, err = eval.WithExclusions(exclusions); err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 2 * time.Minute, GRPCMessages: true, GRPCSchema: s})
}

// TestGRPCSchema (#316): with a schema, a described method's fields reach
// the rules named by their paths, an exclusion names them so, and an
// undescribed method is read as without a schema.
func TestGRPCSchema(t *testing.T) {
	const sqli = "1' OR '1'='1' -- "
	health := compiled(t, fileOf(grpc_health_v1.File_grpc_health_v1_health_proto))
	check := func(p *pipeline.Pipeline, method string, msg []byte) pipeline.Verdict {
		t.Helper()
		return p.Check(context.Background(), grpcCall(method, "application/grpc", grpcFrame(msg)))
	}
	attack := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), sqli)
	p := schemaPipeline(t, health)

	v := check(p, "/grpc.health.v1.Health/Check", attack)
	if v.Action != pipeline.ActionDeny || v.GRPCRead != (pipeline.GRPCRead{Described: 1}) {
		t.Fatalf("an attack in a described field: %+v", v)
	}
	var matched []int
	for _, m := range v.Matches {
		if m.Variable == "ARGS:service" {
			matched = append(matched, m.RuleID)
		} else if len(m.Variable) > 5 && m.Variable[:5] == "ARGS:" {
			t.Errorf("matched %s, want ARGS:service", m.Variable)
		}
	}
	if len(matched) == 0 {
		t.Fatalf("no match names ARGS:service: %+v", v.Matches)
	}
	// The query isn't the method.
	if v := check(p, "/grpc.health.v1.Health/Check?x=1", attack); v.GRPCRead.Described != 1 {
		t.Errorf("a path with a query isn't described: %+v", v.GRPCRead)
	}

	// An undescribed method: number names, as without a schema.
	v = check(p, "/grpc.health.v1.Health/Nope", attack)
	if v.Action != pipeline.ActionDeny || v.GRPCRead != (pipeline.GRPCRead{Undescribed: 1}) || !slices.ContainsFunc(v.Matches, func(m rules.Match) bool { return m.Variable == "ARGS:1" }) {
		t.Fatalf("an undescribed method: %+v", v)
	}
	// An unknown field: read, counted, named by number.
	unknown := protowire.AppendString(protowire.AppendTag(nil, 7, protowire.BytesType), sqli)
	v = check(p, "/grpc.health.v1.Health/Check", unknown)
	if v.Action != pipeline.ActionDeny || v.GRPCRead != (pipeline.GRPCRead{Described: 1, Unknown: 1}) || !slices.ContainsFunc(v.Matches, func(m rules.Match) bool { return m.Variable == "ARGS:7" }) {
		t.Fatalf("an unknown field: %+v", v)
	}

	// An exclusion by the field's name lets the attack through there only.
	excluded := schemaPipeline(t, health, coraza.Exclusion{RuleIDs: matched, Argument: "service"})
	if v := check(excluded, "/grpc.health.v1.Health/Check", attack); v.Action == pipeline.ActionDeny {
		t.Fatalf("excluded by name, still denied: %+v", v.Matches)
	}
	if v := check(excluded, "/grpc.health.v1.Health/Check", unknown); v.Action != pipeline.ActionDeny {
		t.Fatal("an exclusion by name let an unknown field through")
	}
	// Without a schema, the same exclusion names nothing.
	if v := check(schemaPipeline(t, nil, coraza.Exclusion{RuleIDs: matched, Argument: "service"}), "/grpc.health.v1.Health/Check", attack); v.Action != pipeline.ActionDeny {
		t.Fatal("without a schema, an exclusion by name matched a number name")
	}
}

// fpFile is a message of four short bytes fields and four numbers, as
// TestGRPCMessagesFalsePositives' random messages, with a method:
//
//	message R { bytes b1 = 1; ... bytes b4 = 4; uint64 n1 = 11; ... uint64 n4 = 14; }
//	service F { rpc Call(R) returns (R); }
func fpFile() *descriptorpb.FileDescriptorProto {
	m := &descriptorpb.DescriptorProto{Name: proto.String("R")}
	for i := int32(1); i <= 4; i++ {
		for _, f := range []struct {
			num int32
			typ descriptorpb.FieldDescriptorProto_Type
			pre string
		}{{i, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "b"}, {i + 10, descriptorpb.FieldDescriptorProto_TYPE_UINT64, "n"}} {
			m.Field = append(m.Field, &descriptorpb.FieldDescriptorProto{
				Name: proto.String(f.pre + string('0'+i)), Number: proto.Int32(f.num), Type: f.typ.Enum(),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			})
		}
	}
	return &descriptorpb.FileDescriptorProto{
		Name: proto.String("fp.proto"), Package: proto.String("fp"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{m},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("F"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Call"), InputType: proto.String(".fp.R"), OutputType: proto.String(".fp.R"),
		}}}},
	}
}

// readFile is a service reading descriptors:
//
//	service D { rpc Read(google.protobuf.FileDescriptorProto) returns (google.protobuf.FileDescriptorProto); }
func readFile() *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name: proto.String("read.proto"), Package: proto.String("read"), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/descriptor.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("D"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Read"), InputType: proto.String(".google.protobuf.FileDescriptorProto"), OutputType: proto.String(".google.protobuf.FileDescriptorProto"),
		}}}},
	}
}

// TestGRPCSchemaFalsePositives re-measures TestGRPCMessagesFalsePositives
// with the messages' schemas (design 0013 §2, §11): bytes fields give only
// their runs of 8 or more readable characters, so random bytes fields are
// never denied, in 100,000 messages of four (10,000 with -short or the
// race detector); and the
// real messages, the linked descriptors read with descriptor.proto's
// schema, are denied for no text the reader made up.
func TestGRPCSchemaFalsePositives(t *testing.T) {
	s := compiled(t, fileOf((&descriptorpb.FileDescriptorProto{}).ProtoReflect().Descriptor().ParentFile()), readFile(), fpFile())
	p := schemaPipeline(t, s)
	descriptorFalsePositives(t, checker(t, p, "/read.D/Read"))

	n := 100000
	if testing.Short() || raceDetector {
		// make test runs the race detector, ten times slower: 100,000
		// messages take minutes there. go test ./pkg/pipeline runs them all.
		n = 10000
	}
	check := checker(t, p, "/fp.F/Call")
	rng := rand.New(rand.NewPCG(275, 1))
	denied := 0
	for range n {
		var msg []byte
		for f := protowire.Number(1); f <= 4; f++ {
			b := make([]byte, 1+rng.IntN(24))
			for j := range b {
				b[j] = byte(rng.Uint32())
			}
			msg = protowire.AppendTag(msg, f, protowire.BytesType)
			msg = protowire.AppendBytes(msg, b)
			msg = protowire.AppendTag(msg, f+10, protowire.VarintType)
			msg = protowire.AppendVarint(msg, rng.Uint64())
		}
		v := check("random bytes", msg)
		if v.GRPCRead.Described != 1 {
			t.Fatalf("not read with the schema: %+v", v.GRPCRead)
		}
		if v.Action == pipeline.ActionDeny {
			denied++
			t.Errorf("random bytes fields denied: %+v", v.Matches)
		}
	}
	t.Logf("%d of %d messages of random bytes fields denied", denied, n)
}
