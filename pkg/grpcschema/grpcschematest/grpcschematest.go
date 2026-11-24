// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcschematest builds gRPC schemas for tests, as the operator
// compiles them and an engine loads them.
package grpcschematest

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
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

// AtBound returns a descriptor set that compiles, named by a short source
// ("x"), to a schema within margin bytes under grpcschema.MaxCompiledBytes
// (at least 100 under; margin at least 300): named by a source margin
// bytes longer, the schema the bundle carries is over it.
func AtBound(t testing.TB, margin int) []byte {
	t.Helper()
	const nameLen = grpcschema.MaxFieldName
	fieldsOf := func(n int) []byte {
		f := &descriptorpb.FileDescriptorProto{Name: proto.String("big.proto"), Package: proto.String("big"), Syntax: proto.String("proto3")}
		svc := &descriptorpb.ServiceDescriptorProto{Name: proto.String("S")}
		for m := 0; n > 0; m++ {
			msg := &descriptorpb.DescriptorProto{Name: proto.String(fmt.Sprintf("M%d", m))}
			for i := 1; i <= min(n, grpcschema.MaxMessageFields); i++ {
				name := fmt.Sprintf("f%d_", i)
				msg.Field = append(msg.Field, &descriptorpb.FieldDescriptorProto{
					Name: proto.String(name + strings.Repeat("x", nameLen-len(name))), Number: proto.Int32(int32(i)), // #nosec G115 -- small
					Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				})
			}
			n -= len(msg.Field)
			f.MessageType = append(f.MessageType, msg)
			full := fmt.Sprintf(".big.M%d", m)
			svc.Method = append(svc.Method, &descriptorpb.MethodDescriptorProto{Name: proto.String(fmt.Sprintf("Call%d", m)), InputType: proto.String(full), OutputType: proto.String(full)})
		}
		f.Service = []*descriptorpb.ServiceDescriptorProto{svc}
		data, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{f}})
		if err != nil {
			t.Fatal(err)
		}
		// Gzipped: the set is over a ConfigMap's 1 MiB raw.
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// From an estimate, by the size a field adds.
	size := func(n int) int {
		c, err := compile.Compile(fieldsOf(n), "x")
		if err != nil {
			if strings.Contains(err.Error(), "compiled to") {
				return grpcschema.MaxCompiledBytes + 1
			}
			t.Fatal(err)
		}
		return proto.Size(c)
	}
	n := grpcschema.MaxCompiledBytes / (nameLen + 16)
	per := (size(n+100) - size(n)) / 100
	for range 20 {
		gap := grpcschema.MaxCompiledBytes - size(n)
		switch {
		case gap < 100:
			n -= max(1, (100-gap)/per+1)
		case gap > margin:
			n += max(1, (gap-(margin+100)/2)/per)
		default:
			return fieldsOf(n)
		}
	}
	t.Fatal("no set at the bound")
	return nil
}
