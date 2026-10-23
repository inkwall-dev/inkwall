// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundlev1_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// The signature covers the exact bytes of the bundle: the operator signs
// what it serialized, and the engine verifies before decoding.
func Example_signedBundle() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Operator side.
	b := &bundlev1.Bundle{
		Version: 42,
		Policies: []*bundlev1.Policy{{
			Id:   "shop/shop",
			Mode: bundlev1.Mode_MODE_BLOCK,
			Routes: []*bundlev1.RouteMatch{{
				Host: "shop.example.com",
				Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"},
			}},
		}},
	}
	raw, _ := proto.Marshal(b)
	signed := &bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(priv, raw), KeyId: "2026-10"}

	// Engine side.
	if !ed25519.Verify(pub, signed.GetBundle(), signed.GetSignature()) {
		fmt.Println("bad signature: keep the current bundle")
		return
	}
	var got bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &got); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(got.GetVersion(), got.GetPolicies()[0].GetId(), got.GetPolicies()[0].GetMode())

	// A tampered bundle fails verification.
	signed.Bundle[len(signed.Bundle)-1] ^= 1
	fmt.Println(ed25519.Verify(pub, signed.GetBundle(), signed.GetSignature()))
	// Output:
	// 42 shop/shop MODE_BLOCK
	// false
}
