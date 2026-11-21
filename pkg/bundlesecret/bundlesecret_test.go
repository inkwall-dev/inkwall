// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundlesecret

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
)

const secret = "inkwall-bundle"

func split(t *testing.T, slot string, data []byte) (*Manifest, map[string][]byte) {
	t.Helper()
	m, chunks, err := Split(secret, slot, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string][]byte{}
	for i, c := range chunks {
		stored[m.Chunks[i]] = c
	}
	return parsed, stored
}

func getter(stored map[string][]byte) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		c, ok := stored[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s not found", ErrIncomplete, name)
		}
		return c, nil
	}
}

func TestSplitJoin(t *testing.T) {
	for _, n := range []int{1, ChunkBytes, ChunkBytes + 1, 3*ChunkBytes - 7, MaxBytes} {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		m, stored := split(t, "b", data)
		if want := (n + ChunkBytes - 1) / ChunkBytes; len(m.Chunks) != want {
			t.Errorf("%d bytes: %d chunks, want %d", n, len(m.Chunks), want)
		}
		if m.Slot(secret) != "b" || m.Chunks[0] != "inkwall-bundle-b-0" {
			t.Errorf("%d bytes: chunks %v, want slot b", n, m.Chunks)
		}
		got, err := Join(m, getter(stored))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: join: %v", n, err)
		}
	}
	if _, _, err := Split(secret, "a", make([]byte, MaxBytes+1)); err == nil {
		t.Error("a bundle over MaxBytes is split")
	}
}

// A missing chunk, or one overwritten by the next bundle (a write that
// stopped before its manifest), is never joined into a bundle.
func TestJoinIncomplete(t *testing.T) {
	data := make([]byte, 2*ChunkBytes+10)
	_, _ = rand.Read(data)
	m, stored := split(t, "a", data)

	missing := map[string][]byte{m.Chunks[0]: stored[m.Chunks[0]], m.Chunks[2]: stored[m.Chunks[2]]}
	if _, err := Join(m, getter(missing)); !errors.Is(err, ErrIncomplete) {
		t.Errorf("missing chunk: %v, want ErrIncomplete", err)
	}

	next := bytes.Clone(data)
	next[ChunkBytes+1] ^= 1
	_, nextStored := split(t, "a", next)
	partial := map[string][]byte{m.Chunks[0]: stored[m.Chunks[0]], m.Chunks[1]: nextStored[m.Chunks[1]], m.Chunks[2]: stored[m.Chunks[2]]}
	if _, err := Join(m, getter(partial)); !errors.Is(err, ErrIncomplete) {
		t.Errorf("chunk of another bundle: %v, want ErrIncomplete", err)
	}

	longer := map[string][]byte{m.Chunks[0]: stored[m.Chunks[0]], m.Chunks[1]: stored[m.Chunks[1]], m.Chunks[2]: append(bytes.Clone(stored[m.Chunks[2]]), 0)}
	if _, err := Join(m, getter(longer)); !errors.Is(err, ErrIncomplete) {
		t.Errorf("longer chunk: %v, want ErrIncomplete", err)
	}
}

func TestNextSlot(t *testing.T) {
	if s := NextSlot(secret, nil); s != "a" {
		t.Errorf("no manifest: slot %q, want a", s)
	}
	a, _ := split(t, "a", []byte("x"))
	b, _ := split(t, "b", []byte("x"))
	if s := NextSlot(secret, a); s != "b" {
		t.Errorf("after a: slot %q, want b", s)
	}
	if s := NextSlot(secret, b); s != "a" {
		t.Errorf("after b: slot %q, want a", s)
	}
}

func TestParseManifestRejects(t *testing.T) {
	const sum = `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	for name, data := range map[string]string{
		"not JSON":        `{`,
		"no chunks":       `{"sha256":` + sum + `,"size":1,"chunks":[]}`,
		"another Secret":  `{"sha256":` + sum + `,"size":1,"chunks":["inkwall-bundle-signing-key"]}`,
		"out of order":    `{"sha256":` + sum + `,"size":1,"chunks":["inkwall-bundle-a-1","inkwall-bundle-a-0"]}`,
		"mixed slots":     `{"sha256":` + sum + `,"size":1,"chunks":["inkwall-bundle-a-0","inkwall-bundle-b-1"]}`,
		"no size":         `{"sha256":` + sum + `,"chunks":["inkwall-bundle-a-0"]}`,
		"bad hash":        `{"sha256":"xyz","size":1,"chunks":["inkwall-bundle-a-0"]}`,
		"too many chunks": `{"sha256":` + sum + `,"size":1,"chunks":["inkwall-bundle-a-0","inkwall-bundle-a-1","inkwall-bundle-a-2","inkwall-bundle-a-3","inkwall-bundle-a-4","inkwall-bundle-a-5","inkwall-bundle-a-6","inkwall-bundle-a-7","inkwall-bundle-a-8"]}`,
	} {
		if _, err := ParseManifest(secret, []byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChunkNames(t *testing.T) {
	names := ChunkNames(secret)
	if len(names) != 2*MaxChunks || !IsChunk(secret, "inkwall-bundle-b-7") || IsChunk(secret, "inkwall-bundle-signing-key") {
		t.Errorf("chunk names %v", names)
	}
}

// TestFormats: the bundle's 8 chunks and the country table's 16.
func TestFormats(t *testing.T) {
	data := make([]byte, 16*ChunkBytes)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if _, _, err := Bundle(secret).Split("a", data); err == nil {
		t.Error("the bundle format took 16 chunks")
	}
	m, chunks, err := Geo.Split("b", data)
	if err != nil || len(chunks) != 16 || m.Chunks[15] != "inkwall-geo-b-15" {
		t.Fatalf("geo: %v, %d chunks, %v", err, len(chunks), m.Chunks)
	}
	raw, _ := m.Marshal()
	got, err := Geo.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(GeoSecret, raw); err == nil {
		t.Error("the bundle format took a manifest of 16 chunks")
	}
	joined, err := Join(got, func(name string) ([]byte, error) {
		return chunks[slices.Index(m.Chunks, name)], nil
	})
	if err != nil || !bytes.Equal(joined, data) {
		t.Fatalf("join: %v", err)
	}
	if _, _, err := Geo.Split("a", append(data, 1)); err == nil {
		t.Error("geo took 16 chunks and a byte")
	}
	names := Geo.ChunkNames()
	if len(names) != 32 || !Geo.IsChunk("inkwall-geo-a-15") || Geo.IsChunk("inkwall-geo-a-16") || Geo.IsChunk("inkwall-bundle-a-0") {
		t.Errorf("geo chunk names: %v", names)
	}
	if Geo.MaxBytes() != 14400<<10 || Bundle(secret).MaxBytes() != MaxBytes {
		t.Errorf("MaxBytes: %d, %d", Geo.MaxBytes(), Bundle(secret).MaxBytes())
	}
}
