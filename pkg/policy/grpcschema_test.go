// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

func healthSchema(t *testing.T) *bundlev1.GRPCSchema {
	t.Helper()
	data, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto),
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := compile.Compile(data, "shop/schema/set.binpb")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// healthCheck is a call of grpc.health.v1.Health/Check whose service is
// value.
func healthCheck(value string) *request.Request {
	msg := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), value)
	r := req("shop.example.com", "/grpc.health.v1.Health/Check")
	r.Method, r.Proto = "POST", "HTTP/2.0"
	r.Headers.Set("Content-Type", "application/grpc")
	r.Headers.Set("Te", "trailers")
	r.Body = append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
	return r
}

// TestGRPCSchemaInBundle (#316): a policy reads with the schema its body
// names, shared by id and kept across bundles; a bundle whose schema
// doesn't load, or that doesn't carry the schema a policy names, is
// refused.
func TestGRPCSchemaInBundle(t *testing.T) {
	schema := healthSchema(t)
	b := testBundle()
	b.Policies[0].Body = &bundlev1.BodyConfig{Inspect: true, GrpcMessages: true, GrpcSchemaId: schema.GetId()}
	b.GrpcSchemas = []*bundlev1.GRPCSchema{schema}
	evals := NewEvaluators()
	set, err := Compile(b, Options{BodyLimit: 65536, Evaluators: evals})
	if err != nil {
		t.Fatal(err)
	}
	v := set.Check(context.Background(), healthCheck("1' OR '1'='1' -- "))
	if v.Action != pipeline.ActionDeny || v.GRPCRead != (pipeline.GRPCRead{Described: 1}) {
		t.Fatalf("an attack in a described field: %s, %+v", v.Action, v.GRPCRead)
	}
	named := false
	for _, m := range v.Matches {
		named = named || m.Variable == "ARGS:service"
	}
	if !named {
		t.Fatalf("no match names ARGS:service: %+v", v.Matches)
	}
	// Per message, the same reading.
	call := healthCheck("")
	call.Body = nil
	stream := set.GRPCStream(call)
	if stream != nil {
		t.Fatal("a buffered policy streams")
	}
	b.Policies[0].Body.GrpcPerMessage = true
	set, err = Compile(b, Options{BodyLimit: 65536, Evaluators: evals})
	if err != nil {
		t.Fatal(err)
	}
	if s, typ := set.GRPCStream(call).GRPCSchema(call); s == nil || typ == nil || typ.FullName != "grpc.health.v1.HealthCheckRequest" {
		t.Fatalf("per message: %v %v", s, typ)
	}
	first := set.policies[0].pipeline
	// The next bundle reuses the loaded schema.
	again, err := Compile(b, Options{BodyLimit: 65536, Evaluators: evals})
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := first.GRPCSchema(call)
	s2, _ := again.policies[0].pipeline.GRPCSchema(call)
	if s1 != s2 {
		t.Error("an unchanged schema loaded again")
	}
	// A bundle without it drops it from the cache.
	b.GrpcSchemas, b.Policies[0].Body = nil, nil
	if _, err := Compile(b, Options{BodyLimit: 65536, Evaluators: evals}); err != nil || len(evals.schemas) != 0 {
		t.Fatalf("%v, %d schemas cached", err, len(evals.schemas))
	}

	// Refused bundles.
	bad := proto.CloneOf(schema)
	bad.Methods[0].Input = 1 << 20
	for name, mutate := range map[string]func(*bundlev1.Bundle){
		"a schema that doesn't load": func(b *bundlev1.Bundle) { b.GrpcSchemas = []*bundlev1.GRPCSchema{bad} },
		"a schema not carried":       func(b *bundlev1.Bundle) { b.GrpcSchemas = nil },
	} {
		b := testBundle()
		b.Policies[0].Body = &bundlev1.BodyConfig{Inspect: true, GrpcMessages: true, GrpcSchemaId: schema.GetId()}
		b.GrpcSchemas = []*bundlev1.GRPCSchema{schema}
		mutate(b)
		if _, err := Compile(b, Options{}); err == nil || !strings.Contains(err.Error(), "gRPC schema") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
