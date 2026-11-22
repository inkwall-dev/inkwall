// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package load reads a bundle's compiled gRPC schema (bundlev1.GRPCSchema)
// into a grpcschema.Schema.
package load

import (
	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// Load checks a bundle's compiled schema and indexes it (grpcschema.New).
// An error means the schema can't be read with: the operator compiles only
// schemas that pass, so the bundle carrying it is invalid.
func Load(b *bundlev1.GRPCSchema) (*grpcschema.Schema, error) {
	d := grpcschema.Def{ID: b.GetId(), Source: b.GetSource(), Size: proto.Size(b)}
	if d.Size > grpcschema.MaxCompiledBytes {
		// Not converted: New refuses it on its size.
		return grpcschema.New(d)
	}
	d.Methods = make([]grpcschema.MethodDef, len(b.GetMethods()))
	for i, m := range b.GetMethods() {
		d.Methods[i] = grpcschema.MethodDef{Path: m.GetPath(), Input: m.GetInput(), Output: m.GetOutput()}
	}
	d.Messages = make([]grpcschema.MessageDef, len(b.GetMessages()))
	for i, m := range b.GetMessages() {
		md := grpcschema.MessageDef{FullName: m.GetFullName(), Any: m.GetAny(), Fields: make([]grpcschema.FieldDef, len(m.GetFields()))}
		for j, f := range m.GetFields() {
			md.Fields[j] = grpcschema.FieldDef{Number: f.GetNumber(), Name: f.GetName(), Kind: kind(f.GetKind()),
				Message: f.GetMessage(), Repeated: f.GetRepeated()}
		}
		d.Messages[i] = md
	}
	return grpcschema.New(d)
}

// kind is k's grpcschema.Kind: the same numbers; 0 (which New refuses) for
// one it doesn't know.
func kind(k bundlev1.GRPCFieldKind) grpcschema.Kind {
	if k < bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_STRING || k > bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_FIXED64 {
		return 0
	}
	return grpcschema.Kind(k) // #nosec G115 -- 1 to 7
}
