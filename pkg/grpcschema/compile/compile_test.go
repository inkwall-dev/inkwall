// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
)

// setOf returns the descriptor set of files and their imports, serialized.
func setOf(t testing.TB, files ...protoreflect.FileDescriptor) []byte {
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
	return marshal(t, &set)
}

func marshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// file is a hand-written .proto file: syntax, package, its messages and one
// service whose methods take and return the given types.
type file struct {
	name, pkg, syntax string
	deps              []string
	messages          []*descriptorpb.DescriptorProto
	extensions        []*descriptorpb.FieldDescriptorProto
	methods           [][2]string // input, output (full names, with a leading dot)
}

func (f file) proto() *descriptorpb.FileDescriptorProto {
	fd := &descriptorpb.FileDescriptorProto{
		Name:        proto.String(f.name),
		Package:     proto.String(f.pkg),
		Dependency:  f.deps,
		MessageType: f.messages,
		Extension:   f.extensions,
	}
	if f.syntax != "" {
		fd.Syntax = proto.String(f.syntax)
	}
	if len(f.methods) > 0 {
		svc := &descriptorpb.ServiceDescriptorProto{Name: proto.String("Svc")}
		for i, m := range f.methods {
			svc.Method = append(svc.Method, &descriptorpb.MethodDescriptorProto{
				Name: proto.String(fmt.Sprintf("M%d", i)), InputType: proto.String(m[0]), OutputType: proto.String(m[1]),
			})
		}
		fd.Service = []*descriptorpb.ServiceDescriptorProto{svc}
	}
	return fd
}

func set(t testing.TB, files ...file) []byte {
	t.Helper()
	var s descriptorpb.FileDescriptorSet
	for _, f := range files {
		s.File = append(s.File, f.proto())
	}
	return marshal(t, &s)
}

func msg(name string, fields ...*descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
	return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
}

func field(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func repeated(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
	f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	return f
}

const (
	tString  = descriptorpb.FieldDescriptorProto_TYPE_STRING
	tBytes   = descriptorpb.FieldDescriptorProto_TYPE_BYTES
	tMessage = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	tGroup   = descriptorpb.FieldDescriptorProto_TYPE_GROUP
	tInt64   = descriptorpb.FieldDescriptorProto_TYPE_INT64
	tEnum    = descriptorpb.FieldDescriptorProto_TYPE_ENUM
	tFixed32 = descriptorpb.FieldDescriptorProto_TYPE_FIXED32
	tDouble  = descriptorpb.FieldDescriptorProto_TYPE_DOUBLE
)

// loadSet compiles data and loads it as an engine does.
func loadSet(t *testing.T, data []byte) (*bundlev1.GRPCSchema, *grpcschema.Schema) {
	t.Helper()
	c, err := Compile(data, "ns/cm/key")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	s, err := load.Load(c)
	if err != nil {
		t.Fatalf("Load of a compiled schema: %v", err)
	}
	return c, s
}

func TestCompileHealth(t *testing.T) {
	data := setOf(t, grpc_health_v1.File_grpc_health_v1_health_proto)
	c, s := loadSet(t, data)
	if s.Source() != "ns/cm/key" || len(c.GetId()) != 64 {
		t.Fatalf("source %q, id %q", s.Source(), c.GetId())
	}
	in := s.Method("/grpc.health.v1.Health/Check")
	if in == nil || in.FullName != "grpc.health.v1.HealthCheckRequest" {
		t.Fatalf("Check's input %+v", in)
	}
	if f := in.Field(1); f == nil || f.Name != "service" || f.Kind != grpcschema.KindString {
		t.Fatalf("field 1 %+v", f)
	}
	if s.Method("/grpc.health.v1.Health/Nope") != nil || s.Method("/grpc.health.v1.health/Check") != nil {
		t.Fatal("an undescribed method, or another case, is described")
	}
	// Gzipped: the same schema.
	gc, _ := loadSet(t, gz(t, data))
	if gc.GetId() != c.GetId() {
		t.Fatal("gzipped set compiles to another schema")
	}
	// Only what reading needs: far smaller than the set.
	if n := proto.Size(c); n >= len(data) {
		t.Fatalf("compiled %d bytes, set %d", n, len(data))
	}
}

func TestCompileKinds(t *testing.T) {
	inner := msg("Inner", field("text", 1, tString, ""))
	entry := msg("LabelsEntry", field("key", 1, tString, ""), field("value", 2, tString, ""))
	entry.Options = &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)}
	grp := msg("Grp", field("g", 1, tString, ""))
	outer := msg("Outer",
		field("name", 1, tString, ""),
		field("blob", 2, tBytes, ""),
		field("inner", 3, tMessage, ".p.Inner"),
		repeated(field("ids", 4, tInt64, "")),
		field("color", 5, tEnum, ".p.Color"),
		field("f32", 6, tFixed32, ""),
		field("d", 7, tDouble, ""),
		repeated(field("labels", 8, tMessage, ".p.Outer.LabelsEntry")),
		field("grp", 9, tGroup, ".p.Outer.Grp"),
	)
	outer.NestedType = []*descriptorpb.DescriptorProto{entry, grp}
	outer.ExtensionRange = []*descriptorpb.DescriptorProto_ExtensionRange{{Start: proto.Int32(100), End: proto.Int32(200)}}
	f := file{name: "p.proto", pkg: "p", syntax: "proto2",
		messages: []*descriptorpb.DescriptorProto{outer, inner, msg("Unused", field("x", 1, tString, ""))},
		extensions: []*descriptorpb.FieldDescriptorProto{func() *descriptorpb.FieldDescriptorProto {
			x := field("note", 100, tString, "")
			x.Extendee = proto.String(".p.Outer")
			return x
		}()},
		methods: [][2]string{{".p.Outer", ".p.Inner"}},
	}
	fp := f.proto()
	fp.EnumType = []*descriptorpb.EnumDescriptorProto{{Name: proto.String("Color"), Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("RED"), Number: proto.Int32(0)}}}}
	data := marshal(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{fp}})
	c, s := loadSet(t, data)
	o := s.Method("/p.Svc/M0")
	want := map[protowire.Number][3]any{
		1: {"name", grpcschema.KindString, false}, 2: {"blob", grpcschema.KindBytes, false},
		3: {"inner", grpcschema.KindMessage, false}, 4: {"ids", grpcschema.KindVarint, true},
		5: {"color", grpcschema.KindVarint, false}, 6: {"f32", grpcschema.KindFixed32, false},
		7: {"d", grpcschema.KindFixed64, false}, 8: {"labels", grpcschema.KindMessage, true},
		9: {"grp", grpcschema.KindGroup, false}, 100: {"[p.note]", grpcschema.KindString, false},
	}
	if o.Fields() != len(want) {
		t.Fatalf("%d fields, want %d", o.Fields(), len(want))
	}
	for num, w := range want {
		fd := o.Field(num)
		if fd == nil || fd.Name != w[0] || fd.Kind != w[1] || fd.Repeated != w[2] {
			t.Errorf("field %d = %+v, want %v", num, fd, w)
		}
	}
	if e := o.Field(8).Message; e.FullName != "p.Outer.LabelsEntry" || e.Field(1).Name != "key" || e.Field(2).Name != "value" {
		t.Errorf("map entry %+v", e)
	}
	if g := o.Field(9).Message; g.FullName != "p.Outer.Grp" || g.Field(1).Kind != grpcschema.KindString {
		t.Errorf("group %+v", g)
	}
	// Unreachable from any method, and no Any: dropped.
	if s.Message("p.Unused") != nil {
		t.Error("an unreachable message is kept")
	}
	for _, m := range c.GetMessages() {
		if m.GetFullName() == "p.Color" {
			t.Error("an enum is kept")
		}
	}
}

func TestCompileAnyKeepsEverything(t *testing.T) {
	data := func(unusedName string) []byte {
		f := file{name: "p.proto", pkg: "p", syntax: "proto3", deps: []string{"google/protobuf/any.proto"},
			messages: []*descriptorpb.DescriptorProto{
				msg("Req", field("payload", 1, tMessage, ".google.protobuf.Any")),
				msg(unusedName, field("sku", 1, tString, "")),
			},
			methods: [][2]string{{".p.Req", ".p.Req"}},
		}
		var s descriptorpb.FileDescriptorSet
		s.File = append(s.File, protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto), f.proto())
		return marshal(t, &s)
	}
	_, s := loadSet(t, data("Item"))
	a := s.Method("/p.Svc/M0").Field(1).Message
	if !a.Any || a.FullName != "google.protobuf.Any" {
		t.Fatalf("payload's type %+v", a)
	}
	if s.AnyType("type.googleapis.com/p.Item") == nil || s.AnyType("p.Item") == nil {
		t.Fatal("an Any's message isn't kept")
	}
	if s.AnyType("type.googleapis.com/p.Nope") != nil {
		t.Fatal("an unknown type_url names a type")
	}
}

func TestCompileRecursive(t *testing.T) {
	_, s := loadSet(t, set(t, file{name: "p.proto", pkg: "p", syntax: "proto3",
		messages: []*descriptorpb.DescriptorProto{msg("Node", field("name", 1, tString, ""), repeated(field("children", 2, tMessage, ".p.Node")))},
		methods:  [][2]string{{".p.Node", ".p.Node"}},
	}))
	n := s.Method("/p.Svc/M0")
	if n.Field(2).Message != n {
		t.Fatal("a recursive type isn't itself")
	}
}

func TestCompileDeterministic(t *testing.T) {
	a := file{name: "a.proto", pkg: "a", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("A", field("x", 1, tString, ""))}}
	b := file{name: "b.proto", pkg: "b", syntax: "proto3", deps: []string{"a.proto"},
		messages: []*descriptorpb.DescriptorProto{msg("B", field("a", 1, tMessage, ".a.A"))}, methods: [][2]string{{".b.B", ".a.A"}}}
	c1, _ := loadSet(t, set(t, a, b))
	c2, _ := loadSet(t, set(t, b, a)) // imports after the file: any order
	if c1.GetId() != c2.GetId() || !proto.Equal(c1, c2) {
		t.Fatal("the same set in another order compiles to another schema")
	}
}

func TestCompileRefuses(t *testing.T) {
	deep := msg("D0")
	cur := deep
	for i := 1; i < 200; i++ {
		n := msg(fmt.Sprintf("D%d", i))
		cur.NestedType = []*descriptorpb.DescriptorProto{n}
		cur = n
	}
	manyFields := msg("Wide")
	for i := 1; i <= grpcschema.MaxMessageFields+1; i++ {
		manyFields.Field = append(manyFields.Field, field(fmt.Sprintf("f%d", i), int32(i), tString, ""))
	}
	manyMethods := file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M")}}
	for range grpcschema.MaxMethods + 1 {
		manyMethods.methods = append(manyMethods.methods, [2]string{".p.M", ".p.M"})
	}
	var bomb bytes.Buffer
	w := gzip.NewWriter(&bomb)
	_, _ = w.Write(make([]byte, MaxGunzipBytes+1))
	_ = w.Close()
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "no file"},
		{"not a set", []byte("not protobuf at all"), "not a FileDescriptorSet"},
		{"over 1 MiB", make([]byte, MaxSourceBytes+1), "over"},
		{"gzip bomb", bomb.Bytes(), "gunzipped over"},
		{"bad gzip", []byte{0x1f, 0x8b, 0, 0}, "gzip"},
		{"unresolved import", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", deps: []string{"missing.proto"},
			messages: []*descriptorpb.DescriptorProto{msg("M")}, methods: [][2]string{{".p.M", ".p.M"}}}), "missing.proto"},
		{"unknown type", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3",
			messages: []*descriptorpb.DescriptorProto{msg("M", field("x", 1, tMessage, ".p.Nope"))}, methods: [][2]string{{".p.M", ".p.M"}}}), "p.Nope"},
		{"no service", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M")}}), "no service"},
		{"duplicate number", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3",
			messages: []*descriptorpb.DescriptorProto{msg("M", field("a", 1, tString, ""), field("b", 1, tString, ""))}, methods: [][2]string{{".p.M", ".p.M"}}}), "conflicting fields"},
		{"nested too deep", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{deep, msg("M")},
			methods: [][2]string{{".p.M", ".p.M"}}}), "nested too deep"},
		{"too many fields", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{manyFields},
			methods: [][2]string{{".p.Wide", ".p.Wide"}}}), "fields, over"},
		{"too many methods", set(t, manyMethods), "methods, over"},
		{"long field name", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3",
			messages: []*descriptorpb.DescriptorProto{msg("M", field(strings.Repeat("n", grpcschema.MaxFieldName+1), 1, tString, ""))},
			methods:  [][2]string{{".p.M", ".p.M"}}}), "name over"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Compile(c.data, "ns/cm/key")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Compile = %v, %v; want an error with %q", s != nil, err, c.want)
			}
		})
	}
}

// publicChain is n files, each publicly importing every earlier one: the
// paths protodesc walks double with each file.
func publicChain(t testing.TB, n int) []byte {
	var set descriptorpb.FileDescriptorSet
	for i := range n {
		f := &descriptorpb.FileDescriptorProto{Name: proto.String(fmt.Sprintf("f%d.proto", i)), Package: proto.String(fmt.Sprintf("p%d", i)),
			Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{msg("M")}}
		for j := range i {
			f.Dependency = append(f.Dependency, fmt.Sprintf("f%d.proto", j))
			f.PublicDependency = append(f.PublicDependency, int32(j)) // #nosec G115 -- small
		}
		if i == n-1 {
			f.Service = []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("S"), Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("M"), InputType: proto.String(fmt.Sprintf(".p%d.M", i)), OutputType: proto.String(".p0.M")}}}}
		}
		set.File = append(set.File, f)
	}
	return marshal(t, &set)
}

// TestCompilePublicImportChain: a chain of public imports that would take
// protodesc minutes (30 files: 28 s, 40: over 2 min) is refused at once,
// and a short one still compiles.
func TestCompilePublicImportChain(t *testing.T) {
	for _, n := range []int{30, 40} {
		start := time.Now()
		_, err := Compile(publicChain(t, n), "ns/cm/key")
		if err == nil || !strings.Contains(err.Error(), "import paths") && !strings.Contains(err.Error(), "chained over") {
			t.Errorf("%d files: %v", n, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%d files: refused in %v", n, d)
		}
	}
	start := time.Now()
	if _, err := Compile(publicChain(t, 16), "ns/cm/key"); err != nil {
		t.Fatalf("16 files, at the bound: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("16 files compiled in %v", d)
	}
}

// TestCompileImportBounds: a cycle, a public import out of range, too many
// files.
func TestCompileImportBounds(t *testing.T) {
	cycle := marshal(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		{Name: proto.String("a.proto"), Dependency: []string{"b.proto"}, PublicDependency: []int32{0}},
		{Name: proto.String("b.proto"), Dependency: []string{"a.proto"}, PublicDependency: []int32{0}},
	}})
	if _, err := Compile(cycle, "x"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("a cycle: %v", err)
	}
	outOfRange := marshal(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		{Name: proto.String("a.proto"), PublicDependency: []int32{3}},
	}})
	if _, err := Compile(outOfRange, "x"); err == nil || !strings.Contains(err.Error(), "public import") {
		t.Errorf("a public import out of range: %v", err)
	}
	many := &descriptorpb.FileDescriptorSet{}
	for i := range MaxFiles + 1 {
		many.File = append(many.File, &descriptorpb.FileDescriptorProto{Name: proto.String(fmt.Sprintf("%d", i))})
	}
	if _, err := Compile(marshal(t, many), "x"); err == nil || !strings.Contains(err.Error(), "files, over") {
		t.Errorf("too many files: %v", err)
	}
	// The backstop past these bounds: TestCompileAbandoned.
}

// TestCompileHugeEnum: enum values aren't kept, so an enum of tens of
// thousands of values costs nothing in the schema.
func TestCompileHugeEnum(t *testing.T) {
	e := &descriptorpb.EnumDescriptorProto{Name: proto.String("Big")}
	for i := range 50000 {
		e.Value = append(e.Value, &descriptorpb.EnumValueDescriptorProto{Name: proto.String(fmt.Sprintf("V%d", i)), Number: proto.Int32(int32(i))})
	}
	f := file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M", field("e", 1, tEnum, ".p.Big"))},
		methods: [][2]string{{".p.M", ".p.M"}}}
	fp := f.proto()
	fp.EnumType = []*descriptorpb.EnumDescriptorProto{e}
	data := marshal(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{fp}})
	if len(data) > MaxSourceBytes {
		t.Fatalf("test set of %d bytes", len(data))
	}
	c, _ := loadSet(t, data)
	if n := proto.Size(c); n > 200 {
		t.Fatalf("compiled %d bytes", n)
	}
}

func TestCache(t *testing.T) {
	cache := NewCache()
	data := setOf(t, grpc_health_v1.File_grpc_health_v1_health_proto)
	a, ka, err := cache.Compile(data, "a/cm/k")
	if err != nil {
		t.Fatal(err)
	}
	b, kb, err := cache.Compile(data, "b/cm/k")
	// Compiled once; an entry per source, so that one never names another
	// namespace's ConfigMap.
	if err != nil || ka != kb || a.GetId() == b.GetId() || a.GetSource() != "a/cm/k" || b.GetSource() != "b/cm/k" || cache.Len() != 1 {
		t.Fatalf("cached compile: %v, keys equal %v, ids %s %s, sources %s %s, len %d", err, ka == kb, a.GetId(), b.GetId(), a.GetSource(), b.GetSource(), cache.Len())
	}
	if again, _, _ := cache.Compile(data, "a/cm/k"); again.GetId() != a.GetId() {
		t.Fatal("the same set and source compile to another id")
	}
	if direct, _ := Compile(data, "a/cm/k"); direct.GetId() != a.GetId() {
		t.Fatal("cached and uncached ids differ")
	}
	if _, _, err := cache.Compile([]byte("bad"), "c/cm/k"); err == nil {
		t.Fatal("a bad set compiles")
	}
	if cache.Len() != 2 {
		t.Fatalf("%d entries, want the error cached too", cache.Len())
	}
	cache.Retain(map[[sha256.Size]byte]bool{ka: true})
	if cache.Len() != 1 {
		t.Fatalf("%d entries after Retain", cache.Len())
	}
	var none *Cache
	if s, _, err := none.Compile(data, "x/y/z"); err != nil || s.GetSource() != "x/y/z" {
		t.Fatalf("nil cache: %v", err)
	}
}

// FuzzCompile: any bytes compile to an error or a schema Load accepts,
// never a panic.
func FuzzCompile(f *testing.F) {
	f.Add(setOf(f, grpc_health_v1.File_grpc_health_v1_health_proto))
	f.Add(setOf(f, anypb.File_google_protobuf_any_proto))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Compile(data, "ns/cm/key")
		if err != nil {
			return
		}
		if _, err := load.Load(c); err != nil {
			t.Fatalf("Load of a compiled schema: %v", err)
		}
	})
}
