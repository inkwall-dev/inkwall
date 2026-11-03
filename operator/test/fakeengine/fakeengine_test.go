// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package fakeengine

import (
	"crypto/ed25519"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
)

func sign(t *testing.T, s *bundle.Signer, version uint64) *bundlev1.SignedBundle {
	t.Helper()
	signed, err := s.Sign(&bundlev1.Bundle{Version: version, ClusterId: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Engines sharing a Shared decode the same bundle once, and still verify
// anything else: another bundle, a bad signature, another key.
func TestSharedVerify(t *testing.T) {
	signer, err := bundle.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	other, err := bundle.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	shared := &Shared{}
	engine := func(keys ...ed25519.PublicKey) *Engine { return &Engine{PublicKeys: keys, Shared: shared} }
	a, b := engine(signer.Public()), engine(signer.Public())

	v1 := sign(t, signer, 1)
	got1, err := a.verify(v1)
	if err != nil || got1.GetVersion() != 1 {
		t.Fatalf("a: version %d, %v; want 1", got1.GetVersion(), err)
	}
	// The same bytes, received on b's own stream: a's bundle.
	got2, err := b.verify(proto.Clone(v1).(*bundlev1.SignedBundle))
	if err != nil || got2 != got1 {
		t.Fatalf("b: %p, %v; want a's bundle %p", got2, err, got1)
	}

	// The same bundle with another signature isn't taken on trust.
	forged := proto.Clone(v1).(*bundlev1.SignedBundle)
	forged.Signature[0] ^= 1
	if _, err := b.verify(forged); err == nil {
		t.Error("a forged signature of a verified bundle was accepted")
	}
	// Nor the same bytes and signature, said to be another key's: checked
	// with that key, the signature is bad.
	impostor := &Engine{PublicKeys: []ed25519.PublicKey{other.Public()}, Shared: shared}
	byOther := proto.Clone(v1).(*bundlev1.SignedBundle)
	byOther.KeyId = other.KeyID()
	if _, err := impostor.verify(byOther); err == nil {
		t.Error("a bundle signed by another key was accepted")
	}
	// A new bundle is decoded.
	if got, err := b.verify(sign(t, signer, 2)); err != nil || got.GetVersion() != 2 {
		t.Fatalf("b: version %d, %v; want 2", got.GetVersion(), err)
	}

	// Many engines at once, under -race.
	v3 := sign(t, signer, 3)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		seen = map[*bundlev1.Bundle]int{}
	)
	for range 50 {
		wg.Go(func() {
			got, err := engine(signer.Public()).verify(proto.Clone(v3).(*bundlev1.SignedBundle))
			if err != nil || got.GetVersion() != 3 {
				t.Errorf("version %d, %v; want 3", got.GetVersion(), err)
			}
			mu.Lock()
			seen[got]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(seen) != 1 {
		t.Errorf("50 engines decoded the same bundle %d times, want once", len(seen))
	}
}
