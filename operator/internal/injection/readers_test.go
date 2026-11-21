// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"
	"testing"
)

// TestBundleReaderSecrets: engines may read, at cold start, the bundle
// Secret and the country table's, and all their chunks.
func TestBundleReaderSecrets(t *testing.T) {
	names := BundleReaderSecrets()
	for _, want := range []string{"inkwall-bundle", "inkwall-bundle-a-0", "inkwall-bundle-b-7", "inkwall-geo", "inkwall-geo-a-0", "inkwall-geo-b-15"} {
		if !slices.Contains(names, want) {
			t.Errorf("%s missing", want)
		}
	}
	if len(names) != 1+16+1+32 || slices.Contains(names, "inkwall-bundle-signing-key") {
		t.Errorf("%d names: %v", len(names), names)
	}
}
