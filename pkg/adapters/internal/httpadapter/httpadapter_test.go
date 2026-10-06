// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"strings"
	"testing"
)

func TestRequestID(t *testing.T) {
	for id, want := range map[string]string{
		"":                       "",
		"abc-123_DEF.4:5":        "abc-123_DEF.4:5",
		"has space":              "",
		"inject\nnewline":        "",
		"<script>":               "",
		strings.Repeat("a", 128): strings.Repeat("a", 128),
		strings.Repeat("a", 129): "",
	} {
		if got := RequestID(id); got != want {
			t.Errorf("RequestID(%q) = %q, want %q", id, got, want)
		}
	}
}
