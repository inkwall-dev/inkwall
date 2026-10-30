// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// fuzzKey is the trusted key of the fuzz targets, fixed so that the seeds
// stay valid.
var fuzzKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

// signedSeed is a SignedBundle signed with key, serialized as in the cache
// file.
func signedSeed(f *testing.F, key ed25519.PrivateKey, keyID string, b *bundlev1.Bundle) []byte {
	f.Helper()
	raw, err := proto.Marshal(b)
	if err != nil {
		f.Fatal(err)
	}
	out, err := proto.Marshal(&bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(key, raw), KeyId: keyID})
	if err != nil {
		f.Fatal(err)
	}
	return out
}

// addSignedSeeds adds bundles signed with the trusted key, with and without
// its key ID, and with another key. They can't be checked in: they are
// signed.
func addSignedSeeds(f *testing.F, add func(raw []byte)) {
	pub := fuzzKey.Public().(ed25519.PublicKey)
	b := &bundlev1.Bundle{Version: 3, ClusterId: "c-1", ContentHash: []byte("hash"), Policies: []*bundlev1.Policy{{}}}
	add(signedSeed(f, fuzzKey, bundlekey.ID(pub), b))
	add(signedSeed(f, fuzzKey, "", b))
	add(signedSeed(f, fuzzKey, bundlekey.ID(pub), &bundlev1.Bundle{}))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	add(signedSeed(f, other, bundlekey.ID(other.Public().(ed25519.PublicKey)), b))
	add(signedSeed(f, other, bundlekey.ID(pub), b))
}

// errCompiled stops apply after Compile: the fuzz targets only check what
// reaches it.
var errCompiled = errors.New("compiled")

// fuzzAgent returns an Agent that trusts fuzzKey, and the bundles its
// Compile is called with.
func fuzzAgent(f *testing.F) (*Agent, *[]*bundlev1.Bundle) {
	dir := f.TempDir()
	keyFile := filepath.Join(dir, "trusted-keys.pub")
	if err := os.WriteFile(keyFile, bundlekey.Format(fuzzKey.Public().(ed25519.PublicKey)), 0o600); err != nil {
		f.Fatal(err)
	}
	compiled := &[]*bundlev1.Bundle{}
	a, err := New(Config{
		Addr: "operator:9443", CAFile: "ca.crt", TokenFile: "token", PublicKeyFile: keyFile,
		EngineID: "e-1", Holder: &policy.Holder{}, Logger: slog.New(slog.DiscardHandler),
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			*compiled = append(*compiled, b)
			return nil, errCompiled
		},
	})
	if err != nil {
		f.Fatal(err)
	}
	return a, compiled
}

// checkApply applies a SignedBundle and checks that nothing reaches Compile
// unless it carries the trusted key's own signature of its bytes (ed25519
// signatures are unique: a mutated or forged one never verifies), and that
// Compile gets those bytes decoded.
func checkApply(t *testing.T, a *Agent, compiled *[]*bundlev1.Bundle, signed *bundlev1.SignedBundle) {
	t.Helper()
	*compiled = nil
	_, err := a.apply(signed, false)
	if len(*compiled) == 0 {
		if err == nil {
			t.Fatal("bundle applied without compiling")
		}
		return
	}
	if !errors.Is(err, errCompiled) || len(*compiled) != 1 {
		t.Fatalf("compiled %d times, apply: %v", len(*compiled), err)
	}
	pub := fuzzKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(signed.GetSignature(), ed25519.Sign(fuzzKey, signed.GetBundle())) {
		t.Fatalf("compiled a bundle not signed by the trusted key: signature %x", signed.GetSignature())
	}
	if id := signed.GetKeyId(); id != "" && id != bundlekey.ID(pub) {
		t.Fatalf("compiled a bundle naming key %q", id)
	}
	var want bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &want); err != nil || !proto.Equal(&want, (*compiled)[0]) {
		t.Fatalf("compiled %v, signed %v (%v)", (*compiled)[0], &want, err)
	}
	if a.Version() != 0 {
		t.Fatalf("version %d after a bundle that didn't compile", a.Version())
	}
}

// FuzzApply decodes arbitrary bytes as a SignedBundle, as from the cache
// file or the operator's stream, and applies it.
func FuzzApply(f *testing.F) {
	addSignedSeeds(f, func(raw []byte) { f.Add(raw) })
	a, compiled := fuzzAgent(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		var signed bundlev1.SignedBundle
		if err := proto.Unmarshal(raw, &signed); err != nil {
			return
		}
		checkApply(t, a, compiled, &signed)
	})
}

// FuzzSecretBundle decodes arbitrary bytes as the bundle Secret's
// bundle.pb.gz, gzip-compressed first or not, and applies what it decodes:
// the result is what the bytes decompress and decode to, and is applied
// only if signed by the trusted key.
func FuzzSecretBundle(f *testing.F) {
	addSignedSeeds(f, func(raw []byte) { f.Add(raw, true) })
	a, compiled := fuzzAgent(f)
	f.Fuzz(func(t *testing.T, data []byte, compress bool) {
		in := data
		if compress {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(data)
			_ = zw.Close()
			in = buf.Bytes()
		}
		signed, err := decodeSecretBundle(in)
		if err != nil {
			return
		}
		if compress {
			var want bundlev1.SignedBundle
			if err := proto.Unmarshal(data, &want); err != nil || !proto.Equal(&want, signed) {
				t.Fatalf("decoded %v from %x (%v)", signed, data, err)
			}
		}
		checkApply(t, a, compiled, signed)
	})
}
