// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

func content(ids ...string) *bundlev1.Bundle {
	b := &bundlev1.Bundle{ClusterId: "c1"}
	for _, id := range ids {
		b.Policies = append(b.Policies, &bundlev1.Policy{Id: id, Mode: bundlev1.Mode_MODE_BLOCK})
	}
	return b
}

func TestNext(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	b1, changed, err := Next(nil, content("shop/a"), 0, now)
	if err != nil || !changed || b1.GetVersion() != 1 || len(b1.GetContentHash()) != 32 || !b1.GetCreatedAt().AsTime().Equal(now) {
		t.Fatalf("first bundle: %v changed=%v err=%v", b1, changed, err)
	}

	// The same content keeps the current bundle, whatever its version and
	// creation time.
	same, changed, _ := Next(b1, content("shop/a"), 1, now.Add(time.Hour))
	if changed || same != b1 {
		t.Fatalf("unchanged content produced a new bundle: %v", same)
	}

	b2, changed, _ := Next(b1, content("shop/a", "shop/b"), 1, now)
	if !changed || b2.GetVersion() != 2 {
		t.Fatalf("changed content: version %d changed=%v", b2.GetVersion(), changed)
	}

	// The Secret was deleted (no current bundle) while the leader ran: the
	// sequence continues.
	b3, _, _ := Next(nil, content("shop/c"), 2, now)
	if b3.GetVersion() != 3 {
		t.Fatalf("after a deleted Secret: version %d, want 3", b3.GetVersion())
	}
	// A new leader with an older memory continues from the Secret.
	b4, _, _ := Next(b3, content("shop/d"), 0, now)
	if b4.GetVersion() != 4 {
		t.Fatalf("new leader: version %d, want 4", b4.GetVersion())
	}
}

func TestContentHashIgnoresMetadata(t *testing.T) {
	a := content("shop/a")
	b := proto.Clone(a).(*bundlev1.Bundle)
	b.Version = 9
	ha, _ := ContentHash(a)
	hb, _ := ContentHash(b)
	if string(ha) != string(hb) {
		t.Fatal("the version changed the content hash")
	}
	b.Suspended = true
	hb, _ = ContentHash(b)
	if string(ha) == string(hb) {
		t.Fatal("suspending didn't change the content hash")
	}
}

func newClient(t *testing.T) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).Build()
}

func TestSignerSecret(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)
	s1, err := LoadOrCreateSigner(ctx, c, "inkwall-system")
	if err != nil {
		t.Fatal(err)
	}
	// The second call, or another replica, reads the same key.
	s2, err := LoadOrCreateSigner(ctx, c, "inkwall-system")
	if err != nil || !s1.Public().Equal(s2.Public()) || s1.KeyID() != s2.KeyID() || len(s1.KeyID()) != 16 {
		t.Fatalf("second load: %v, same key=%v", err, s1.Public().Equal(s2.Public()))
	}

	var bad corev1.Secret
	_ = c.Get(ctx, client.ObjectKey{Namespace: "inkwall-system", Name: SigningKeySecret}, &bad)
	bad.Data[privateKeyKey] = []byte("short")
	_ = c.Update(ctx, &bad)
	if _, err := LoadOrCreateSigner(ctx, c, "inkwall-system"); err == nil {
		t.Fatal("a corrupt key was accepted")
	}
}

func TestStoreAndLoad(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(priv)

	if b, err := Load(ctx, c, "inkwall-system"); b != nil || err != nil {
		t.Fatalf("no Secret yet: %v, %v", b, err)
	}
	for v := range uint64(2) {
		b, _, _ := Next(nil, content("shop/a"), v, time.Now())
		signed, err := signer.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		if err := Store(ctx, c, "inkwall-system", b, signed, signer.Public()); err != nil {
			t.Fatal(err)
		}
		got, err := Load(ctx, c, "inkwall-system")
		if err != nil || !proto.Equal(got, b) {
			t.Fatalf("version %d: loaded %v, %v", v+1, got, err)
		}
	}

	var s corev1.Secret
	_ = c.Get(ctx, client.ObjectKey{Namespace: "inkwall-system", Name: BundleSecret}, &s)
	if s.Annotations[VersionAnnotation] != "2" || s.Labels["app.kubernetes.io/managed-by"] != "inkwall-operator" {
		t.Errorf("Secret metadata: %v %v", s.Annotations, s.Labels)
	}
	signed, err := Decode(s.Data[BundleKey])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(s.Data[PublicKeyKey]), signed.GetBundle(), signed.GetSignature()) {
		t.Fatalf("stored bundle doesn't verify with the stored public key: %v", err)
	}
}

func TestStoreTooLarge(t *testing.T) {
	c := newClient(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(priv)
	b := content()
	// Random text compresses to about half: twice the limit stays over it.
	noise := make([]byte, MaxCompressedBytes)
	_, _ = rand.Read(noise)
	b.RuleSets = []*bundlev1.RuleSet{{Id: "WAFRuleSet/shop/big", Source: &bundlev1.RuleSet_Seclang{Seclang: hex.EncodeToString(noise)}}}
	signed, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	err = Store(context.Background(), c, "inkwall-system", b, signed, signer.Public())
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	var s corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "inkwall-system", Name: BundleSecret}, &s); err == nil {
		t.Fatal("a too-large bundle was stored")
	}
}
