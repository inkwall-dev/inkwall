// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestLatest(t *testing.T) {
	// As git tag -l prints them, in no useful order, with pre-releases,
	// another module's tags and a tag that isn't a version.
	tags := []string{
		"v0.1.0", "v0.1.5", "v0.10.0-rc.1", "v0.2.2", "v0.2.10", "v0.3.0", "v0.3.3",
		"v0.4.0", "v0.4.0-rc.1", "v0.4.0-rc.2", "v0.4.1", "v0.5.0-rc.1",
		"adapters/caddy/v0.9.0", "nightly", "v1", "0.6.0",
	}
	for _, tc := range []struct {
		branch string
		minors int
		want   []string
	}{
		{"main", 1, []string{"0.4.1"}},
		{"", 1, []string{"0.4.1"}},
		{"test/390-upgrade", 2, []string{"0.4.1", "0.3.3"}},
		{"main", 4, []string{"0.4.1", "0.3.3", "0.2.10", "0.1.5"}},
		{"main", 9, []string{"0.4.1", "0.3.3", "0.2.10", "0.1.5"}},
		// A release branch upgrades from its own minor's latest patch, or
		// from an older one before its first release: never down.
		{"release-0.3", 1, []string{"0.3.3"}},
		{"release-0.3", 2, []string{"0.3.3", "0.2.10"}},
		{"release-0.2", 1, []string{"0.2.10"}},
		{"release-0.5", 1, []string{"0.4.1"}},
		{"release-0.0", 1, nil},
	} {
		if got := latest(tags, tc.branch, tc.minors); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("latest(%q, %d) = %q, want %q", tc.branch, tc.minors, got, tc.want)
		}
	}
}
