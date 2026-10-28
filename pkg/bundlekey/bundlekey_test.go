// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundlekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestParseFormat(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	keys, err := Parse(Format(a, b))
	if err != nil || len(keys) != 2 || !a.Equal(keys[0]) || !b.Equal(keys[1]) {
		t.Fatalf("round trip: %v, %v", keys, err)
	}
	// A single key file is a plain ed25519.pub.
	if keys, err := Parse(a); err != nil || len(keys) != 1 || !bytes.Equal(keys[0], a) {
		t.Fatalf("one key: %v, %v", keys, err)
	}
	for name, data := range map[string][]byte{
		"empty":    nil,
		"short":    a[:31],
		"trailing": append(Format(a), 0),
		"too many": bytes.Repeat(a, MaxKeys+1),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestID(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	if id := ID(a); len(id) != 16 || id != ID(a) || id == ID(b) {
		t.Errorf("ID: %q, %q", ID(a), ID(b))
	}
}
