// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcschematest builds gRPC schemas for tests, as the operator
// compiles them and an engine loads them.
package grpcschematest

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
)

// Schema returns the schema of files and their imports.
func Schema(t testing.TB, files ...protoreflect.FileDescriptor) *grpcschema.Schema {
	t.Helper()
	var set descriptorpb.FileDescriptorSet
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
		set.File = append(set.File, protodesc.ToFileDescriptorProto(f))
	}
	for _, f := range files {
		add(f)
	}
	data, err := proto.Marshal(&set)
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
