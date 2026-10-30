// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundlekey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// FuzzParse reads arbitrary key files: one is accepted only as one to
// MaxKeys whole keys, which Format writes back unchanged, each with a
// 16-hex-digit ID.
func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := Parse(data)
		valid := len(data) > 0 && len(data)%ed25519.PublicKeySize == 0 && len(data)/ed25519.PublicKeySize <= MaxKeys
		if (err == nil) != valid {
			t.Fatalf("Parse of %d bytes: %v", len(data), err)
		}
		if err != nil {
			return
		}
		if got := Format(keys...); !bytes.Equal(got, data) {
			t.Errorf("Format(Parse(%x)) = %x", data, got)
		}
		for _, k := range keys {
			if len(k) != ed25519.PublicKeySize {
				t.Errorf("key of %d bytes", len(k))
			}
			if id := ID(k); len(id) != 16 {
				t.Errorf("ID %q", id)
			} else if _, err := hex.DecodeString(id); err != nil {
				t.Errorf("ID %q: %v", id, err)
			}
		}
		// The keys are copies: changing the file doesn't change them.
		file := bytes.Clone(data)
		keys, _ = Parse(file)
		file[0] ^= 0xff
		if !bytes.Equal(Format(keys...), data) {
			t.Error("the keys alias the file")
		}
	})
}
