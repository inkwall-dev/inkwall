// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundlesecret is the format of the operator's bundle Secret, which
// the operator writes and the engines and inkwallctl read (0004 §4.6).
//
// A bundle that fits in one Secret is stored there, gzip-compressed, under
// BundleKey. A larger one is split into chunk Secrets, and the bundle Secret
// holds a Manifest under ManifestKey instead. Chunks are written to one of
// two sets of names, the one the current manifest doesn't use, before the
// manifest: a reader never sees a manifest whose chunks are not all
// written, and the hash in the manifest rejects chunks overwritten since.
package bundlesecret

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// Keys of the bundle Secret and its chunks.
const (
	// BundleKey holds the gzip-compressed, serialized SignedBundle, when it
	// fits in one Secret.
	BundleKey = "bundle.pb.gz"
	// ManifestKey holds the Manifest of a bundle split into chunks.
	ManifestKey = "manifest.json"
	// ChunkKey holds a chunk Secret's part of the compressed bundle.
	ChunkKey = "chunk"
)

// Limits of the format.
const (
	// ChunkBytes is the most of the compressed bundle one Secret holds:
	// Secrets are limited to 1 MiB.
	ChunkBytes = 900 << 10
	// MaxChunks bounds the chunks of one bundle.
	MaxChunks = 8
	// MaxBytes is the largest compressed bundle.
	MaxBytes = MaxChunks * ChunkBytes
	// MaxBundleBytes is the largest bundle decompressed.
	MaxBundleBytes = 64 << 20
)

// Slots of chunk names: a bundle is written to the one the current
// manifest doesn't use.
var slots = []string{"a", "b"}

// ErrIncomplete is returned when the chunks don't match their manifest: one
// is missing, or was overwritten by a newer bundle being written.
var ErrIncomplete = errors.New("bundle chunks incomplete")

// Manifest lists the chunks of a bundle.
type Manifest struct {
	// SHA256 is the hash of the whole compressed bundle, in hex.
	SHA256 string `json:"sha256"`
	// Size is its length in bytes.
	Size int `json:"size"`
	// Chunks are the names of the chunk Secrets, in order, in the bundle
	// Secret's namespace.
	Chunks []string `json:"chunks"`
}

// ChunkName returns the name of chunk i in slot, for the bundle Secret
// secret.
func ChunkName(secret, slot string, i int) string {
	return secret + "-" + slot + "-" + strconv.Itoa(i)
}

// ChunkNames returns every name a chunk of secret can have: what engines
// need get on, besides the bundle Secret.
func ChunkNames(secret string) []string {
	names := make([]string, 0, len(slots)*MaxChunks)
	for _, slot := range slots {
		for i := range MaxChunks {
			names = append(names, ChunkName(secret, slot, i))
		}
	}
	return names
}

// Slot returns the slot of m's chunks, "" if it has none.
func (m *Manifest) Slot(secret string) string {
	for _, slot := range slots {
		if len(m.Chunks) > 0 && m.Chunks[0] == ChunkName(secret, slot, 0) {
			return slot
		}
	}
	return ""
}

// NextSlot returns the slot to write the next bundle's chunks to, given the
// current manifest (nil if there is none).
func NextSlot(secret string, current *Manifest) string {
	if current != nil && current.Slot(secret) == slots[0] {
		return slots[1]
	}
	return slots[0]
}

// Split splits a compressed bundle into chunks named in slot, and returns
// their manifest.
func Split(secret, slot string, data []byte) (Manifest, [][]byte, error) {
	if len(data) > MaxBytes {
		return Manifest{}, nil, fmt.Errorf("%d bytes, at most %d", len(data), MaxBytes)
	}
	sum := sha256.Sum256(data)
	m := Manifest{SHA256: hex.EncodeToString(sum[:]), Size: len(data)}
	var chunks [][]byte
	for i := 0; len(data) > 0; i++ {
		n := min(len(data), ChunkBytes)
		chunks = append(chunks, data[:n])
		m.Chunks = append(m.Chunks, ChunkName(secret, slot, i))
		data = data[n:]
	}
	return m, chunks, nil
}

// ParseManifest reads the manifest of secret, and checks that its chunks
// are named as Split names them.
func ParseManifest(secret string, data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if len(m.Chunks) == 0 || len(m.Chunks) > MaxChunks {
		return nil, fmt.Errorf("manifest: %d chunks, want 1 to %d", len(m.Chunks), MaxChunks)
	}
	slot := m.Slot(secret)
	for i, name := range m.Chunks {
		if slot == "" || name != ChunkName(secret, slot, i) {
			return nil, fmt.Errorf("manifest: chunk %d is %q, not a chunk of %s", i, name, secret)
		}
	}
	if m.Size <= 0 || m.Size > MaxBytes {
		return nil, fmt.Errorf("manifest: size %d, want 1 to %d", m.Size, MaxBytes)
	}
	if b, err := hex.DecodeString(m.SHA256); err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("manifest: sha256 %q is not a SHA-256 in hex", m.SHA256)
	}
	return &m, nil
}

// Marshal encodes m for ManifestKey.
func (m *Manifest) Marshal() ([]byte, error) { return json.Marshal(m) }

// Join reads m's chunks with get, which returns a chunk Secret's ChunkKey,
// and returns the compressed bundle, checked against the manifest's hash.
func Join(m *Manifest, get func(name string) ([]byte, error)) ([]byte, error) {
	var buf bytes.Buffer
	for _, name := range m.Chunks {
		chunk, err := get(name)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 || buf.Len()+len(chunk) > m.Size {
			return nil, fmt.Errorf("%w: chunk %s has %d bytes, the manifest %d in all", ErrIncomplete, name, len(chunk), m.Size)
		}
		buf.Write(chunk)
	}
	sum := sha256.Sum256(buf.Bytes())
	if buf.Len() != m.Size || hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, fmt.Errorf("%w: the chunks don't match the manifest's hash", ErrIncomplete)
	}
	return buf.Bytes(), nil
}

// IsChunk reports whether name is a chunk of secret.
func IsChunk(secret, name string) bool { return slices.Contains(ChunkNames(secret), name) }
