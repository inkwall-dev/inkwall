// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package schematest

import (
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
)

// TestFieldsAnyNestingLinear: Anys nested to the depth limit, each naming
// itself and another type, are read in time and text linear in the
// message: an Any's value is read as its last type_url's type and without
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
