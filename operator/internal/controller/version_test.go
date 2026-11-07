// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"math"
	"testing"
)

// A bundle version beyond int64 (status.bundleVersion's type) is held at
// its maximum, never wrapped to a negative version.
func TestStatusVersion(t *testing.T) {
	for in, want := range map[uint64]int64{0: 0, 42: 42, math.MaxInt64: math.MaxInt64, math.MaxInt64 + 1: math.MaxInt64, math.MaxUint64: math.MaxInt64} {
		if got := statusVersion(in); got != want {
			t.Errorf("statusVersion(%d) = %d, want %d", in, got, want)
		}
	}
}
