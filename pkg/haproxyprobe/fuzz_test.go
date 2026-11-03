// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package haproxyprobe

import (
	"strings"
	"testing"
)

// FuzzCheck: whatever a client sends, the engine answers only a probe made
// with the key, and its answer verifies.
func FuzzCheck(f *testing.F) {
	uri := PrefixPath("/", "0123456789abcdef0123")
	f.Add(uri, "a.example", Request(key, "0123456789abcdef0123", "a.example", uri))
	f.Add("/", "", "x.y")
	f.Fuzz(func(t *testing.T, uri, host, header string) {
		answer, ok := Check(key, uri, host, header)
		if !ok {
			return
		}
		nonce, _, _ := strings.Cut(header, ".")
		if header != Request(key, nonce, host, uri) {
			t.Fatalf("accepted header %q for %q", header, uri)
		}
		if !Verify(key, nonce, host, uri, answer) {
			t.Fatal("the answer doesn't verify")
		}
	})
}
