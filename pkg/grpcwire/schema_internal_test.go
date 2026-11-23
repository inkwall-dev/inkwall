// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// stringText on bytes that aren't UTF-8 ends, in time linear in its input:
// each byte that isn't UTF-8, and each control character, is one space,
// and the rest is as it is.
func TestStringTextInvalidUTF8(t *testing.T) {
	cases := map[string]string{
		"a\xffb":           "a b",
		"\xff\xfe\xfd":     "   ",
		"é\xc3":            "é ",
		"\xe2\x82":         "  ",
		"x\x00\xffy":       "x  y",
		"\xf0\x9f\x98\x80": "\U0001F600",
	}
	long := strings.Repeat("\xff\xc3(\x00日", 1<<16)
	done := make(chan bool, 1)
	go func() {
		for in, want := range cases {
			if got := stringText([]byte(in)); got != want {
				t.Errorf("stringText(%q) = %q, want %q", in, got, want)
			}
		}
		got := stringText([]byte(long))
		done <- utf8.ValidString(got) && len(got) == len(long)
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("stringText of invalid UTF-8: not UTF-8, or not one byte per byte")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stringText of invalid UTF-8 doesn't end")
	}
}
