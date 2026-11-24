// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// deepPackage is one file whose package has n parts ("a.a.a..."), with a
// message whose fields name a type relatively ("Nope"+salt), that
// resolves nowhere: protodesc would look for it in every scope of the
// package, quadratic in its length.
func deepPackage(t testing.TB, n int, salt string) []byte {
	pkg := strings.TrimSuffix(strings.Repeat("a.", n), ".")
	var fields []*descriptorpb.FieldDescriptorProto
	for i := range 4 {
		fields = append(fields, field(fmt.Sprintf("f%d", i), int32(i+1), tMessage, "Nope"+salt)) // #nosec G115 -- small
	}
	return set(t, file{name: "x" + salt + ".proto", pkg: pkg, syntax: "proto3",
		messages: []*descriptorpb.DescriptorProto{msg("M", fields...)}, methods: [][2]string{{".x.M", ".x.M"}}})
}

// TestCompileDeepPackage: a package of 200,000 parts and a type named
// relatively, which kept protodesc past the timeout (and left its
// goroutine running), edited again and again, is refused at once, and
// leaves nothing running.
func TestCompileDeepPackage(t *testing.T) {
	before := runtime.NumGoroutine()
	c := NewCache()
	start := time.Now()
	for i := range 4 {
		// A new value each time, as a ConfigMap edited in a loop.
		data := gz(t, deepPackage(t, 200000, fmt.Sprint(i)))
		if len(data) > MaxSourceBytes {
			t.Fatalf("source of %d bytes", len(data))
		}
		if _, _, err := c.Compile(data, "ns/cm/key"); err == nil || !strings.Contains(err.Error(), "name over") {
			t.Fatalf("a package of 200,000 parts: %v", err)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("refused in %v", d)
	}
	if n := runtime.NumGoroutine() - before; n > 0 {
		t.Errorf("%d goroutines left running", n)
	}
}

// TestCompileNames: names are bounded before protodesc resolves them.
func TestCompileNames(t *testing.T) {
	long := strings.Repeat("n", MaxName+1)
	parts := "." + strings.TrimSuffix(strings.Repeat("p.", MaxNameParts), ".") + ".M"
	inPkg := func(pkg string, fields ...*descriptorpb.FieldDescriptorProto) []byte {
		return set(t, file{name: "p.proto", pkg: pkg, syntax: "proto3",
			messages: []*descriptorpb.DescriptorProto{msg("M", fields...)}, methods: [][2]string{{"." + pkg + ".M", "." + pkg + ".M"}}})
	}
	ext := field("e", 100, tString, "")
	ext.Extendee = proto.String("." + long)
	longMethod := set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M")},
		methods: [][2]string{{".p." + long, ".p.M"}}})
	relMethod := set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M")},
		methods: [][2]string{{"M", ".p.M"}}})
	wide := file{name: "p.proto", pkg: "p", syntax: "proto2", messages: []*descriptorpb.DescriptorProto{msg("M")}, methods: [][2]string{{".p.M", ".p.M"}}}
	for i := range MaxSetFields/grpcschema.MaxMessageFields + 1 {
		m := msg(fmt.Sprintf("W%d", i))
		for j := range grpcschema.MaxMessageFields {
			m.Field = append(m.Field, field("f", int32(j+1), tInt64, "")) // #nosec G115 -- small
		}
		wide.messages = append(wide.messages, m)
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"long package", inPkg(strings.Repeat("a", MaxName+1)), "name over"},
		{"package of many parts", inPkg(strings.TrimSuffix(strings.Repeat("a.", MaxNameParts+1), ".")), "dot-separated parts"},
		{"long message", set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg(long)},
			methods: [][2]string{{".p.M", ".p.M"}}}), "name over"},
		{"long field", inPkg("p", field(long, 1, tString, "")), "name over"},
		{"long type", inPkg("p", field("x", 1, tMessage, "."+long)), "name over"},
		{"type of many parts", inPkg("p", field("x", 1, tMessage, parts)), "dot-separated parts"},
		{"relative type", inPkg("p", field("x", 1, tMessage, "M")), "fully qualified"},
		{"relative extendee", set(t, file{name: "p.proto", pkg: "p", syntax: "proto2", messages: []*descriptorpb.DescriptorProto{msg("M")},
			extensions: []*descriptorpb.FieldDescriptorProto{func() *descriptorpb.FieldDescriptorProto {
				e := field("e", 100, tString, "")
				e.Extendee = proto.String("M")
				return e
			}()},
			methods: [][2]string{{".p.M", ".p.M"}}}), "fully qualified"},
		{"long extendee", set(t, file{name: "p.proto", pkg: "p", syntax: "proto2", messages: []*descriptorpb.DescriptorProto{msg("M")},
			extensions: []*descriptorpb.FieldDescriptorProto{ext}, methods: [][2]string{{".p.M", ".p.M"}}}), "name over"},
		{"long method input", longMethod, "name over"},
		{"relative method input", relMethod, "fully qualified"},
		{"too many fields in the set", gz(t, set(t, wide)), "fields and extensions in the set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Compile(c.data, "ns/cm/key"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Compile: %v; want an error with %q", err, c.want)
			}
		})
	}
	// At the bounds: compiles.
	atBound := "." + strings.TrimSuffix(strings.Repeat("p.", MaxNameParts-1), ".") + ".M"
	pkg := strings.TrimSuffix(strings.Repeat("p.", MaxNameParts-1), ".")
	if _, err := Compile(inPkg(pkg, field("x", 1, tMessage, atBound)), "ns/cm/key"); err != nil {
		t.Fatalf("a type of %d parts: %v", MaxNameParts, err)
	}
}

// TestCompileAbandoned: a set protodesc doesn't check in time is refused
// and not cached; while its check still runs, no other set is checked
// (ErrBusy, not cached either); once it ends, both compile.
func TestCompileAbandoned(t *testing.T) {
	defer func(d time.Duration) { Timeout = d }(Timeout)
	Timeout = 20 * time.Millisecond
	release := make(chan struct{})
	ran := make(chan struct{}, 1)
	fast := protodescNewFiles
	defer func() { protodescNewFiles = fast }()
	protodescNewFiles = func(s *descriptorpb.FileDescriptorSet) (*protoregistry.Files, error) {
		defer func() { ran <- struct{}{} }()
		<-release
		return fast(s)
	}
	cache := NewCache()
	slow := setOf(t, grpc_health_v1.File_grpc_health_v1_health_proto)
	if _, _, err := cache.Compile(slow, "x"); err == nil || !strings.Contains(err.Error(), "to check") {
		t.Fatalf("past the timeout: %v", err)
	}
	protodescNewFiles = fast
	other := set(t, file{name: "p.proto", pkg: "p", syntax: "proto3", messages: []*descriptorpb.DescriptorProto{msg("M")}, methods: [][2]string{{".p.M", ".p.M"}}})
	start := time.Now()
	if _, _, err := cache.Compile(other, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("while a check runs past its timeout: %v, want ErrBusy", err)
	}
	if d := time.Since(start); d > Timeout {
		t.Errorf("refused in %v", d)
	}
	if cache.Len() != 0 {
		t.Fatalf("%d entries: a timeout or ErrBusy cached", cache.Len())
	}
	close(release)
	<-ran
	Timeout = time.Minute
	deadline := time.Now().Add(10 * time.Second)
	for abandoned.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	for _, data := range [][]byte{slow, other} {
		if _, _, err := cache.Compile(data, "x"); err != nil {
			t.Fatalf("once the check ended: %v", err)
		}
	}
}
