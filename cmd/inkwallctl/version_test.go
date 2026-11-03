// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// TestVersion: inkwallctl version and --version print the version, the
// commit and the Go version (#261).
func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr.String())
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 3 || !strings.HasPrefix(lines[0], "inkwallctl ") || !strings.HasPrefix(lines[1], "commit: ") ||
			lines[2] != "go: "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH {
			t.Errorf("%v: got %q", args, stdout.String())
		}
	}
	var stderr bytes.Buffer
	if code := run([]string{"version", "extra"}, &bytes.Buffer{}, &stderr); code != 2 {
		t.Errorf("version extra: exit %d, want 2", code)
	}
}
