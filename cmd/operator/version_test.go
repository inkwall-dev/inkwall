// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// TestVersion: inkwall-operator version and --version print the version, the
// commit and the Go version (#261).
func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr.String())
		}
		got := stdout.String()
		if !strings.HasPrefix(got, "inkwall-operator ") || !strings.Contains(got, "\ncommit: ") ||
			!strings.HasSuffix(got, "\ngo: "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH+"\n") {
			t.Errorf("%v: got %q", args, got)
		}
	}
}
