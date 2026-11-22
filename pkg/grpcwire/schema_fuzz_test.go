// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	// Linked for their descriptors, as the engine links them.
	_ "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	_ "google.golang.org/grpc/health/grpc_health_v1"
	_ "google.golang.org/grpc/reflection/grpc_reflection_v1"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// randomFile returns a random .proto file: proto2 or proto3, messages
// with fields of every kind, repeated (packed or not), maps, oneofs,
// groups (proto2), references between messages and to themselves, and a
// service whose methods take each message.
func randomFile(r *rand.Rand) *descriptorpb.FileDescriptorProto {
	proto2 := r.IntN(2) == 0
	nMsgs := 1 + r.IntN(5)
	scalars := []descriptorpb.FieldDescriptorProto_Type{
		tString, tString, tString, tBytes, tBytes, tInt64, tInt32, tBool, tFixed32, tDouble, tEnum,
		descriptorpb.FieldDescriptorProto_TYPE_UINT64, descriptorpb.FieldDescriptorProto_TYPE_SINT32,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, descriptorpb.FieldDescriptorProto_TYPE_FLOAT,
	}
	numbers := []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 100, 2047, 2048, 536870911}
	file := &descriptorpb.FileDescriptorProto{
		Name: proto.String("r.proto"), Package: proto.String("r"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{Name: proto.String("E"), Value: []*descriptorpb.EnumValueDescriptorProto{
			{Name: proto.String("E0"), Number: proto.Int32(0)}, {Name: proto.String("E1"), Number: proto.Int32(1)}}}},
	}
	if proto2 {
		file.Syntax = proto.String("proto2")
	} else {
		file.Syntax = proto.String("proto3")
	}
	svc := &descriptorpb.ServiceDescriptorProto{Name: proto.String("S")}
	for i := range nMsgs {
		m := &descriptorpb.DescriptorProto{Name: proto.String(fmt.Sprintf("M%d", i))}
		nums := slicesShuffled(r, numbers)[:r.IntN(9)]
		var oneof []int
		for k, num := range nums {
			name := fmt.Sprintf("f%d", k)
			var fd *fdp
			switch c := r.IntN(10); {
			case c < 2:
				fd = dfield(name, num, tMessage, fmt.Sprintf(".r.M%d", r.IntN(nMsgs)))
			case c == 2 && proto2:
				g := fmt.Sprintf("G%d", k)
				fd = dfield(strings.ToLower(g), num, tGroup, fmt.Sprintf(".r.M%d.%s", i, g))
				m.NestedType = append(m.NestedType, &descriptorpb.DescriptorProto{Name: proto.String(g),
					Field: []*fdp{dfield("s", 1, tString, ""), dfield("n", 2, tInt64, "")}})
			case c == 3:
				entry := fmt.Sprintf("Mp%dEntry", k)
				fd = drepeated(dfield(fmt.Sprintf("mp%d", k), num, tMessage, fmt.Sprintf(".r.M%d.%s", i, entry)))
				value := dfield("value", 2, tString, "")
				if r.IntN(2) == 0 {
					value = dfield("value", 2, tMessage, fmt.Sprintf(".r.M%d", r.IntN(nMsgs)))
				}
				m.NestedType = append(m.NestedType, &descriptorpb.DescriptorProto{Name: proto.String(entry),
					Field: []*fdp{dfield("key", 1, tString, ""), value}, Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)}})
			default:
				typ := scalars[r.IntN(len(scalars))]
				fd = dfield(name, num, typ, "")
				if typ == tEnum {
					fd.TypeName = proto.String(".r.E")
				}
			}
			if fd.GetLabel() != lRepeated && r.IntN(4) == 0 && fd.GetType() != tGroup {
				fd = drepeated(fd)
				if proto2 && fd.GetType() != tString && fd.GetType() != tBytes && fd.GetType() != tMessage && r.IntN(2) == 0 {
					fd.Options = &descriptorpb.FieldOptions{Packed: proto.Bool(true)}
				}
			} else if fd.GetLabel() != lRepeated && fd.GetType() != tGroup && r.IntN(4) == 0 {
				oneof = append(oneof, len(m.Field))
			}
			m.Field = append(m.Field, fd)
		}
		if len(oneof) > 0 {
			// A oneof's members are declared one after another: last.
			m.OneofDecl = []*descriptorpb.OneofDescriptorProto{{Name: proto.String("o")}}
			var rest, members []*fdp
			for k, fd := range m.Field {
				if slices.Contains(oneof, k) {
					fd.OneofIndex = proto.Int32(0)
					members = append(members, fd)
				} else {
					rest = append(rest, fd)
				}
			}
			m.Field = slices.Concat(rest, members)
		}
		file.MessageType = append(file.MessageType, m)
		svc.Method = append(svc.Method, &descriptorpb.MethodDescriptorProto{Name: proto.String(fmt.Sprintf("C%d", i)),
			InputType: proto.String(fmt.Sprintf(".r.M%d", i)), OutputType: proto.String(".r.M0")})
	}
	file.Service = []*descriptorpb.ServiceDescriptorProto{svc}
	return file
}

func slicesShuffled[T any](r *rand.Rand, s []T) []T {
	out := append([]T(nil), s...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

var texts = []string{"", "alice", "' OR 1=1--", "<script>alert(1)</script>", "a\x00b", "héllo", "\xff\xfe", "x\ty\n", "; cat /etc/passwd", "日本語"}

// randomMessage returns a random message of type md: its fields with
// their wire types, mostly, and sometimes unknown numbers, another wire
// type, a field twice.
func randomMessage(r *rand.Rand, md protoreflect.MessageDescriptor, depth int) []byte {
	var b []byte
	fields := md.Fields()
	for range r.IntN(7) {
		if fields.Len() == 0 || r.IntN(8) == 0 {
			b = randomField(r, protowire.Number(1+r.IntN(30)), depth)
			continue
		}
		fd := fields.Get(r.IntN(fields.Len()))
		if r.IntN(10) == 0 {
			b = append(b, randomField(r, fd.Number(), depth)...)
			continue
		}
		b = append(b, encode(r, fd, depth)...)
	}
	return b
}

// randomField is field num with a random wire type and value.
func randomField(r *rand.Rand, num protowire.Number, depth int) []byte {
	switch r.IntN(5) {
	case 0:
		return tagged(nil, num, wVar, r.Uint64())
	case 1:
		return tagged(nil, num, wF32, r.Uint64()&0xffffffff)
	case 2:
		return tagged(nil, num, wF64, r.Uint64())
	case 3:
		return tagged(nil, num, wBytes, texts[r.IntN(len(texts))])
	default:
		var v []byte
		if depth < 4 {
			v = tagged(nil, 1, wBytes, texts[r.IntN(len(texts))])
		}
		return tagged(nil, num, wGroup, v)
	}
}

// encode is a value of fd, with its wire type.
func encode(r *rand.Rand, fd protoreflect.FieldDescriptor, depth int) []byte {
	num := fd.Number()
	switch fd.Kind() {
	case protoreflect.StringKind:
		return tagged(nil, num, wBytes, texts[r.IntN(len(texts))])
	case protoreflect.BytesKind:
		v := make([]byte, r.IntN(24))
		for i := range v {
			v[i] = byte(r.Uint32())
		}
		if r.IntN(3) == 0 {
			v = append(v, "readable text run"...)
		}
		return tagged(nil, num, wBytes, v)
	case protoreflect.MessageKind:
		var v []byte
		if depth < 4 {
			v = randomMessage(r, fd.Message(), depth+1)
		}
		return tagged(nil, num, wBytes, v)
	case protoreflect.GroupKind:
		var v []byte
		if depth < 4 {
			v = randomMessage(r, fd.Message(), depth+1)
		}
		return tagged(nil, num, wGroup, v)
	}
	if fd.IsPacked() || fd.IsList() && r.IntN(2) == 0 {
		var v []byte
		for range r.IntN(4) {
			switch wireOf(fd.Kind()) {
			case wF32:
				v = protowire.AppendFixed32(v, r.Uint32())
			case wF64:
				v = protowire.AppendFixed64(v, r.Uint64())
			default:
				v = protowire.AppendVarint(v, r.Uint64()>>r.IntN(64))
			}
		}
		return tagged(nil, num, wBytes, v)
	}
	switch typ := wireOf(fd.Kind()); typ {
	case wF32:
		return tagged(nil, num, typ, r.Uint64()&0xffffffff)
	default:
		return tagged(nil, num, typ, r.Uint64()>>r.IntN(64))
	}
}

func wireOf(k protoreflect.Kind) protowire.Type {
	switch k {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return wF32
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return wF64
	}
	return wVar
}

// stringsOf returns every string value of m as protobuf-go parsed it, and
// the unknown fields of m and every message in it.
func stringsOf(m protoreflect.Message, values *[]string, unknown *[][]byte) {
	if u := m.GetUnknown(); len(u) > 0 {
		*unknown = append(*unknown, u)
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		one := func(fd protoreflect.FieldDescriptor, v protoreflect.Value) {
			switch fd.Kind() {
			case protoreflect.StringKind:
				*values = append(*values, v.String())
			case protoreflect.MessageKind, protoreflect.GroupKind:
				stringsOf(v.Message(), values, unknown)
			}
		}
		switch {
		case fd.IsMap():
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				*values = append(*values, k.String())
				one(fd.MapValue(), mv)
				return true
			})
		case fd.IsList():
			for i := range v.List().Len() {
				one(fd, v.List().Get(i))
			}
		default:
			one(fd, v)
		}
		return true
	})
}

// checkDifferential checks Fields on msg, of type md (t in s), against
// protobuf-go's own parse: when protobuf-go parses it, Fields reads it
// whole, and every string value it gives the application, and the text of
// its unknown fields as Strings reads them, is among Fields' values. It
// returns how many values it compared, -1 when protobuf-go doesn't parse
// msg.
func checkDifferential(t *testing.T, msg []byte, s *grpcschema.Schema, md protoreflect.MessageDescriptor) int {
	t.Helper()
	lim := Limits{Depth: 100, Fields: 1 << 20}
	fields, _, ok := Fields(msg, s, s.Message(string(md.FullName())), lim, nil)
	for _, fd := range fields {
		// Text is UTF-8, as Strings gives (a string's invalid bytes are
		// spaces), and names fit an exclusion.
		if fd.Value == "" || !utf8.ValidString(fd.Value) || len(fd.Name) > MaxName {
			t.Fatalf("field %q = %q", fd.Name, fd.Value)
		}
	}
	m, parsed := unmarshal(msg, md)
	if !parsed {
		return -1
	}
	if !ok {
		t.Fatalf("protobuf-go parses %x, Fields doesn't read it whole", msg)
	}
	got := map[string]bool{}
	for _, fd := range fields {
		got[fd.Value] = true
	}
	var values []string
	var unknown [][]byte
	stringsOf(m, &values, &unknown)
	compared := len(values)
	for _, v := range values {
		if want := stringText([]byte(v)); want != "" && !got[want] {
			t.Fatalf("protobuf-go gives %q, Fields doesn't (%q) in %x", v, fields, msg)
		}
	}
	for _, u := range unknown {
		texts, _ := Strings(u, lim, nil)
		compared += len(texts)
		for _, fd := range texts {
			if !got[fd.Value] {
				t.Fatalf("an unknown field's text %q isn't read (%q) in %x", fd.Value, fields, msg)
			}
		}
	}
	return compared
}

// unmarshal parses msg as protobuf-go does. dynamicpb panics on some map
// entries whose key has another wire type: not parsed either.
func unmarshal(msg []byte, md protoreflect.MessageDescriptor) (m *dynamicpb.Message, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	m = dynamicpb.NewMessage(md)
	return m, (proto.UnmarshalOptions{RecursionLimit: 90}).Unmarshal(msg, m) == nil
}

// differential builds a random schema and message from seed, mutated by
// flips, and checks them. It returns how many messages protobuf-go parsed,
// and the values compared.
func differential(t *testing.T, seed uint64, flips []byte) (parsed, compared int) {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	file := randomFile(r)
	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatalf("seed %d: a random file protodesc refuses: %v", seed, err)
	}
	s := schemaOf(t, file)
	for i := range len(file.GetMessageType()) {
		d, err := files.FindDescriptorByName(protoreflect.FullName(fmt.Sprintf("r.M%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		md := d.(protoreflect.MessageDescriptor)
		msg := randomMessage(r, md, 0)
		for j, x := range flips {
			if len(msg) > 0 {
				msg[(j*7+int(x))%len(msg)] ^= x
			}
		}
		if n := checkDifferential(t, msg, s, md); n >= 0 {
			parsed++
			compared += n
		}
	}
	return parsed, compared
}

// TestFieldsDifferential runs the differential check on random schemas
// and messages, well-formed and mutated.
func TestFieldsDifferential(t *testing.T) {
	n := 3000
	if testing.Short() {
		n = 300
	}
	parsed, compared := 0, 0
	for seed := range uint64(n) {
		p, c := differential(t, seed, nil)
		parsed, compared = parsed+p, compared+c
		if seed%3 == 0 {
			differential(t, seed, []byte{byte(seed), byte(seed >> 3)})
		}
	}
	// Not vacuous: most well-formed messages parse, with values to compare.
	if parsed < n || compared < n {
		t.Fatalf("%d seeds: %d messages parsed, %d values compared", n, parsed, compared)
	}
	t.Logf("%d seeds: %d messages parsed, %d values compared", n, parsed, compared)
}

// TestFieldsDifferentialDescriptors: the descriptors linked into the test,
// read with descriptor.proto's schema (the 33 KB message of design 0013
// §6.6 among them), as protobuf-go reads them.
func TestFieldsDifferentialDescriptors(t *testing.T) {
	s, md := descriptorSchema(t)
	n := 0
	protoregistry.GlobalFiles.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		msg, err := proto.Marshal(protodesc.ToFileDescriptorProto(f))
		if err != nil {
			t.Fatal(err)
		}
		if checkDifferential(t, msg, s, md) <= 0 {
			t.Fatalf("%s: protobuf-go doesn't parse its own descriptor, or it has no text", f.Path())
		}
		n++
		return true
	})
	if n < 50 {
		t.Fatalf("%d files", n)
	}
}

// descriptorSchema is a schema whose method reads a FileDescriptorProto.
func descriptorSchema(t testing.TB) (*grpcschema.Schema, protoreflect.MessageDescriptor) {
	md := (&descriptorpb.FileDescriptorProto{}).ProtoReflect().Descriptor()
	files := withImports(md.ParentFile())
	files = append(files, &descriptorpb.FileDescriptorProto{
		Name: proto.String("bench.proto"), Package: proto.String("bench"), Syntax: proto.String("proto3"),
		Dependency: []string{md.ParentFile().Path()},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("B"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("Read"), InputType: proto.String("." + string(md.FullName())), OutputType: proto.String("." + string(md.FullName())),
		}}}},
	})
	return schemaOf(t, files...), md
}

// FuzzFields: random schemas and messages (from the seed), mutated (by
// flips), against protobuf-go; Fields never panics.
func FuzzFields(fz *testing.F) {
	fz.Add(uint64(1), []byte(nil))
	fz.Add(uint64(7), []byte{0x80, 0x01})
	fz.Add(uint64(42), []byte{0x0a})
	fz.Fuzz(func(t *testing.T, seed uint64, flips []byte) {
		differential(t, seed, flips)
	})
}

// FuzzFieldsBytes: any bytes, read with t.proto's schema, never panic, and
// give UTF-8 within the limits.
func FuzzFieldsBytes(fz *testing.F) {
	s := testSchema(fz)
	req := s.Method("/t.S/Call")
	fz.Add(f(7, wBytes, f(1, wBytes, "t.Item", 2, wBytes, f(1, wBytes, "x"))))
	fz.Add(f(8, wGroup, f(1, wBytes, "g"), 3, wBytes, f(1, wBytes, "alice")))
	fz.Fuzz(func(t *testing.T, msg []byte) {
		lim := Limits{Depth: 8, Fields: 64}
		fields, _, _ := Fields(msg, s, req, lim, nil)
		if len(fields) > lim.Fields {
			t.Fatalf("%d fields", len(fields))
		}
		for _, fd := range fields {
			if fd.Value == "" || !utf8.ValidString(fd.Value) || len(fd.Name) > MaxName {
				t.Fatalf("field %q = %q", fd.Name, fd.Value)
			}
		}
	})
}
