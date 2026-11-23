// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
)

// TestFieldsAnyNestingLinear: Anys nested to the depth limit, each naming
// itself and another type, are read in time and text linear in the
// message: an Any's value is read as its last type_url's type or without
// the schema, not once per type its type_urls name, and all reading is
// charged against a budget of bytes read. (Read once per type, 100 KB took
// over a second and gave 83 MB of text.)
func TestFieldsAnyNestingLinear(t *testing.T) {
	s := testSchema(t)
	req := s.Method("/t.S/Call")
	for _, size := range []int{1 << 10, 100 << 10} {
		v := f(1, wBytes, strings.Repeat("a", size))
		for range 15 {
			v = f(1, wBytes, "t.Item", 1, wBytes, "type.googleapis.com/google.protobuf.Any", 2, wBytes, v)
		}
		msg := f(7, wBytes, v)
		start := time.Now()
		fields, _, _ := grpcwire.Fields(msg, s, req, grpcwire.Limits{Depth: 16, Fields: 4096}, nil)
		elapsed := time.Since(start)
		text := 0
		for _, fd := range fields {
			text += len(fd.Value)
		}
		if text > 64*len(msg)+64<<10 || elapsed > 2*time.Second {
			t.Errorf("%d bytes: %d bytes of text in %v", len(msg), text, elapsed)
		}
		t.Logf("%d bytes: %d fields, %d bytes of text in %v", len(msg), len(fields), text, elapsed)
	}
}

// TestFieldsBudget: a message whose reading would go past the budget of
// bytes read is over the limits, not read whole.
func TestFieldsBudget(t *testing.T) {
	s := testSchema(t)
	req := s.Method("/t.S/Call")
	// A string nested 15 deep in messages printable at no level: each
	// level reads it again, within the budget.
	v := f(1, wBytes, strings.Repeat("x", 1<<16))
	for range 15 {
		v = f(14, wBytes, v)
	}
	if _, _, ok := grpcwire.Fields(v, s, req, grpcwire.Limits{Depth: 16, Fields: 4096}, nil); !ok {
		t.Error("a message 15 deep isn't read whole within the budget")
	}
}

// TestFieldsAnyChain: an Any whose value is a message of the type its
// type_url names is read by that type only, not also without the schema:
// Anys nested in Anys give their text once, not once per way of reading
// each level (8 levels of a 200 KB value gave about 8 times its text).
func TestFieldsAnyChain(t *testing.T) {
	s := testSchema(t)
	req := s.Method("/t.S/Call")
	const attack = "' OR 1=1--"
	for _, levels := range []int{1, 4, 7} {
		inner := f(1, wBytes, strings.Repeat("A", 200000)+attack)
		for range levels {
			inner = f(7, wBytes, f(1, wBytes, "type.googleapis.com/t.Req", 2, wBytes, inner))
		}
		fields, _, ok := grpcwire.Fields(inner, s, req, grpcwire.Limits{Depth: 16, Fields: 4096}, nil)
		text, found := 0, false
		for _, fd := range fields {
			text += len(fd.Value)
			found = found || strings.HasSuffix(fd.Value, attack)
		}
		if !ok || !found || text > len(inner)+1<<10 {
			t.Errorf("%d levels, %d bytes: read whole %v, the attack found %v, %d bytes of text", levels, len(inner), ok, found, text)
		}
	}
}

// TestFieldsTextBudget: a message whose text would be over a few times its
// size (here, printable messages nested deep, each read whole as text at
// each level) is over the limits, whatever the field limit; one of them
// is read whole.
func TestFieldsTextBudget(t *testing.T) {
	s := testSchema(t)
	req := s.Method("/t.S/Call")
	// Children ('r', field 14) whose lengths are printable too.
	chain := f(1, wBytes, strings.Repeat("x", 90))
	for range 14 {
		chain = f(14, wBytes, chain)
	}
	lim := grpcwire.Limits{Depth: 16, Fields: 1 << 24}
	one, _, ok := grpcwire.Fields(chain, s, req, lim, nil)
	if !ok {
		t.Fatal("one chain isn't read whole")
	}
	perChain := 0
	for _, fd := range one {
		perChain += len(fd.Value)
	}
	if perChain <= 4*len(chain) {
		t.Fatalf("a chain of %d bytes gives %d bytes of text: not over the budget", len(chain), perChain)
	}
	msg := bytes.Repeat(chain, 100000)
	fields, _, ok := grpcwire.Fields(msg, s, req, lim, nil)
	text := 0
	for _, fd := range fields {
		text += len(fd.Value)
	}
	if ok || text > 4*len(msg)+64<<10 {
		t.Errorf("%d bytes: read whole %v, %d bytes of text", len(msg), ok, text)
	}
}
