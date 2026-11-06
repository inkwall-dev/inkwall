// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package memlimit

import "testing"

// GOMEMLIMIT follows the container's memory limit (#213).
func TestLimit(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want int64
	}{
		{map[string]string{Env: "536870912"}, 483183819},
		// Set by hand: the runtime applied it.
		{map[string]string{Env: "536870912", "GOMEMLIMIT": "300MiB"}, 0},
		{map[string]string{}, 0},
		{map[string]string{Env: "512Mi"}, 0},
		{map[string]string{Env: "0"}, 0},
	} {
		if got := Limit(func(k string) string { return tc.env[k] }); got != tc.want {
			t.Errorf("%v: %d, want %d", tc.env, got, tc.want)
		}
	}
}
