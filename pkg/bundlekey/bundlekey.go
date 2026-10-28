// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundlekey is how the operator and the engines name and exchange
// the public keys that bundles are signed with (0004 §4.6). A key file holds
// one or more raw 32-byte ed25519 public keys, concatenated: the trust
// ConfigMap's trusted-keys.pub carries every key an engine accepts while the
// signing key rotates, and a single key is the same format as ed25519.pub.
package bundlekey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MaxKeys bounds a key file: during a rotation two keys are trusted.
const MaxKeys = 8

// ID returns the key ID of pub, as in SignedBundle.key_id: the first 8 bytes
// of its SHA-256, in hex.
func ID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Parse reads a key file.
func Parse(data []byte) ([]ed25519.PublicKey, error) {
	n := len(data) / ed25519.PublicKeySize
	if len(data) == 0 || len(data)%ed25519.PublicKeySize != 0 {
		return nil, fmt.Errorf("%d bytes: want one or more raw %d-byte ed25519 keys", len(data), ed25519.PublicKeySize)
	}
	if n > MaxKeys {
		return nil, fmt.Errorf("%d keys, at most %d", n, MaxKeys)
	}
	keys := make([]ed25519.PublicKey, n)
	for i := range keys {
		keys[i] = ed25519.PublicKey(append([]byte(nil), data[i*ed25519.PublicKeySize:(i+1)*ed25519.PublicKeySize]...))
	}
	return keys, nil
}

// Format writes a key file.
func Format(keys ...ed25519.PublicKey) []byte {
	out := make([]byte, 0, len(keys)*ed25519.PublicKeySize)
	for _, k := range keys {
		out = append(out, k...)
	}
	return out
}
