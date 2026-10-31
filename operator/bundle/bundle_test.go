// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

func content(ids ...string) *bundlev1.Bundle {
	b := &bundlev1.Bundle{ClusterId: "c1"}
	for _, id := range ids {
		b.Policies = append(b.Policies, &bundlev1.Policy{Id: id, Mode: bundlev1.Mode_MODE_BLOCK})
	}
	return b
}

// Engines read the bundle Secret directly when the operator is down.
func TestSecretKeyMatchesEngines(t *testing.T) {
	if BundleKey != agent.SecretBundleKey {
		t.Fatalf("the operator writes %q, engines read %q", BundleKey, agent.SecretBundleKey)
	}
}

func TestNext(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	b1, changed, err := Next(nil, content("shop/a"), 0, now, false)
	if err != nil || !changed || b1.GetVersion() != 1 || len(b1.GetContentHash()) != 32 || !b1.GetCreatedAt().AsTime().Equal(now) {
		t.Fatalf("first bundle: %v changed=%v err=%v", b1, changed, err)
	}

	// The same content keeps the current bundle, whatever its version and
	// creation time.
	same, changed, _ := Next(b1, content("shop/a"), 1, now.Add(time.Hour), false)
	if changed || same != b1 {
		t.Fatalf("unchanged content produced a new bundle: %v", same)
	}

	b2, changed, _ := Next(b1, content("shop/a", "shop/b"), 1, now, false)
	if !changed || b2.GetVersion() != 2 {
		t.Fatalf("changed content: version %d changed=%v", b2.GetVersion(), changed)
	}

	// Signed again with a new key: a new version of the same content.
	resigned, changed, _ := Next(b2, content("shop/a", "shop/b"), 2, now, true)
	if !changed || resigned.GetVersion() != 3 || string(resigned.GetContentHash()) != string(b2.GetContentHash()) {
		t.Fatalf("re-signed: version %d changed=%v", resigned.GetVersion(), changed)
	}

	// The Secret was deleted (no current bundle) while the leader ran: the
	// sequence continues.
	b3, _, _ := Next(nil, content("shop/c"), 2, now, false)
	if b3.GetVersion() != 3 {
		t.Fatalf("after a deleted Secret: version %d, want 3", b3.GetVersion())
	}
	// A new leader with an older memory continues from the Secret.
	b4, _, _ := Next(b3, content("shop/d"), 0, now, false)
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

// A policy's hash changes with the policy, the rule sets it binds and
// suspension, not with other policies or the bundle's version.
func TestPolicyHashes(t *testing.T) {
	a := content("shop/a", "shop/b")
	a.RuleSets = []*bundlev1.RuleSet{{Id: "WAFRuleSet/shop/r", Source: &bundlev1.RuleSet_Seclang{Seclang: "SecAction id:1"}}}
	a.Policies[0].RuleSets = []*bundlev1.RuleSetBinding{{RuleSetId: "WAFRuleSet/shop/r"}}
	ha, err := PolicyHashes(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		edit    func(b *bundlev1.Bundle)
		changed []string
	}{
		{"metadata", func(b *bundlev1.Bundle) { b.Version, b.ContentHash = 9, []byte("x") }, nil},
		{"another policy", func(b *bundlev1.Bundle) { b.Policies[1].Mode = bundlev1.Mode_MODE_DETECT }, []string{"shop/b"}},
		{"a policy added", func(b *bundlev1.Bundle) { b.Policies = append(b.Policies, &bundlev1.Policy{Id: "shop/c"}) }, []string{"shop/c"}},
		{"a bound rule set", func(b *bundlev1.Bundle) {
			b.RuleSets[0].Source = &bundlev1.RuleSet_Seclang{Seclang: "SecAction id:2"}
		}, []string{"shop/a"}},
		{"suspended", func(b *bundlev1.Bundle) { b.Suspended = true }, []string{"shop/a", "shop/b"}},
	} {
		b := proto.Clone(a).(*bundlev1.Bundle)
		tc.edit(b)
		hb, err := PolicyHashes(b)
		if err != nil {
			t.Fatal(err)
		}
		var changed []string
		for _, id := range slices.Sorted(maps.Keys(hb)) {
			if h, ok := ha[id]; !ok || h != hb[id] {
				changed = append(changed, id)
			}
		}
		if !slices.Equal(changed, tc.changed) {
			t.Errorf("%s: changed %v, want %v", tc.name, changed, tc.changed)
		}
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

func TestStoreAndLoad(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(priv)

	if b, _, err := Load(ctx, c, "inkwall-system"); b != nil || err != nil {
		t.Fatalf("no Secret yet: %v, %v", b, err)
	}
	for v := range uint64(2) {
		b, _, _ := Next(nil, content("shop/a"), v, time.Now(), false)
		signed, err := signer.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Store(ctx, c, c, "inkwall-system", b, signed, signer.Public()); err != nil {
			t.Fatal(err)
		}
		got, keyID, err := Load(ctx, c, "inkwall-system")
		if err != nil || !proto.Equal(got, b) || keyID != signer.KeyID() {
			t.Fatalf("version %d: loaded %v, %v", v+1, got, err)
		}
	}

	var s corev1.Secret
	_ = c.Get(ctx, client.ObjectKey{Namespace: "inkwall-system", Name: BundleSecret}, &s)
	if s.Annotations[VersionAnnotation] != "2" || s.Annotations[KeyIDAnnotation] != signer.KeyID() || s.Labels["app.kubernetes.io/managed-by"] != "inkwall-operator" {
		t.Errorf("Secret metadata: %v %v", s.Annotations, s.Labels)
	}
	signed, err := Decode(s.Data[BundleKey])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(s.Data[PublicKeyKey]), signed.GetBundle(), signed.GetSignature()) {
		t.Fatalf("stored bundle doesn't verify with the stored public key: %v", err)
	}
}

// large returns a bundle of about n bytes compressed: random hex compresses
// to about half.
func large(n int, ids ...string) *bundlev1.Bundle {
	b := content(ids...)
	noise := make([]byte, n)
	_, _ = rand.Read(noise)
	b.RuleSets = []*bundlev1.RuleSet{{Id: "WAFRuleSet/shop/big", Source: &bundlev1.RuleSet_Seclang{Seclang: hex.EncodeToString(noise)}}}
	return b
}

type chunkEnv struct {
	t      *testing.T
	c      client.Client
	signer *Signer
	last   uint64
}

func (e *chunkEnv) store(content *bundlev1.Bundle) *bundlev1.Bundle {
	e.t.Helper()
	ctx := context.Background()
	b, _, _ := Next(nil, content, e.last, time.Now(), false)
	e.last = b.GetVersion()
	signed, err := e.signer.Sign(b)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := Store(ctx, e.c, e.c, "inkwall-system", b, signed, e.signer.Public()); err != nil {
		e.t.Fatal(err)
	}
	if err := Prune(ctx, e.c, e.c, "inkwall-system"); err != nil {
		e.t.Fatal(err)
	}
	got, _, err := Load(ctx, e.c, "inkwall-system")
	if err != nil || !proto.Equal(got, b) {
		e.t.Fatalf("version %d: loaded %v", b.GetVersion(), err)
	}
	return b
}

// chunks returns the names of the chunk Secrets.
func (e *chunkEnv) chunks() []string {
	e.t.Helper()
	var l corev1.SecretList
	if err := e.c.List(context.Background(), &l, client.MatchingLabels{ChunkLabel: BundleSecret}); err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, s := range l.Items {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	return names
}

func (e *chunkEnv) bundleSecret() *corev1.Secret {
	e.t.Helper()
	var s corev1.Secret
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: "inkwall-system", Name: BundleSecret}, &s); err != nil {
		e.t.Fatal(err)
	}
	return &s
}

// A bundle over one Secret is split into chunks, written to the names the
// current manifest doesn't use; the others are deleted once the manifest
// points at the new ones. A bundle that fits again goes back to one Secret.
func TestStoreChunks(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &chunkEnv{t: t, c: newClient(t), signer: NewSigner(priv)}

	e.store(large(2*bundlesecret.ChunkBytes+(50<<10), "shop/a"))
	if got := e.chunks(); !slices.Equal(got, []string{"inkwall-bundle-a-0", "inkwall-bundle-a-1", "inkwall-bundle-a-2"}) {
		t.Fatalf("chunks %v", got)
	}
	s := e.bundleSecret()
	if _, ok := s.Data[BundleKey]; ok || s.Data[ManifestKey] == nil || s.Data[PublicKeyKey] == nil {
		t.Fatalf("chunked bundle Secret keys: %v", slices.Collect(maps.Keys(s.Data)))
	}
	if n := CompressedSize(s); n <= 2*bundlesecret.ChunkBytes {
		t.Errorf("compressed size %d, want over 2 chunks", n)
	}

	e.store(large(bundlesecret.ChunkBytes+(50<<10), "shop/b"))
	if got := e.chunks(); !slices.Equal(got, []string{"inkwall-bundle-b-0", "inkwall-bundle-b-1"}) {
		t.Fatalf("second bundle: chunks %v", got)
	}
	e.store(large(bundlesecret.ChunkBytes+(50<<10), "shop/c"))
	if got := e.chunks(); !slices.Equal(got, []string{"inkwall-bundle-a-0", "inkwall-bundle-a-1"}) {
		t.Fatalf("third bundle: chunks %v", got)
	}

	// Fits again: one Secret, as older engines read it.
	e.store(content("shop/d"))
	if got := e.chunks(); len(got) != 0 {
		t.Fatalf("one-Secret bundle: chunks %v left", got)
	}
	s = e.bundleSecret()
	if _, ok := s.Data[ManifestKey]; ok || s.Data[BundleKey] == nil {
		t.Fatalf("one-Secret bundle keys: %v", slices.Collect(maps.Keys(s.Data)))
	}
	if n := CompressedSize(s); n != len(s.Data[BundleKey]) {
		t.Errorf("compressed size %d, want %d", n, len(s.Data[BundleKey]))
	}
}

// A write that stopped after its chunks, before its manifest, leaves the
// current bundle readable.
func TestStoreChunksPartialWrite(t *testing.T) {
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &chunkEnv{t: t, c: newClient(t), signer: NewSigner(priv)}
	b1 := e.store(large(bundlesecret.ChunkBytes+(50<<10), "shop/a"))

	// The next bundle's chunks, without its manifest.
	b2, _, _ := Next(b1, large(bundlesecret.ChunkBytes+(50<<10), "shop/b"), 1, time.Now(), false)
	signed, _ := e.signer.Sign(b2)
	encoded, _ := Encode(signed)
	m, chunks, _ := bundlesecret.Split(BundleSecret, "b", encoded)
	for i, chunk := range chunks {
		if err := writeChunk(ctx, e.c, e.c, "inkwall-system", m.Chunks[i], chunk, nil); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := Load(ctx, e.c, "inkwall-system")
	if err != nil || !proto.Equal(got, b1) {
		t.Fatalf("after a partial write: %v, want version 1", err)
	}
	// Prune deletes them.
	if err := Prune(ctx, e.c, e.c, "inkwall-system"); err != nil {
		t.Fatal(err)
	}
	if got := e.chunks(); !slices.Equal(got, []string{"inkwall-bundle-a-0", "inkwall-bundle-a-1"}) {
		t.Fatalf("pruned: chunks %v", got)
	}
}

// A deleted chunk is reported, with the version to continue from.
func TestLoadMissingChunk(t *testing.T) {
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &chunkEnv{t: t, c: newClient(t), signer: NewSigner(priv)}
	e.store(content("shop/a"))
	e.store(large(bundlesecret.ChunkBytes+(50<<10), "shop/a"))
	if err := e.c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: "inkwall-bundle-a-1"}}); err != nil {
		t.Fatal(err)
	}
	got, _, err := Load(ctx, e.c, "inkwall-system")
	if !errors.Is(err, bundlesecret.ErrIncomplete) || got.GetVersion() != 2 {
		t.Fatalf("missing chunk: %v, %v; want ErrIncomplete and version 2", got, err)
	}
	// Overwritten instead (another bundle's): the hash catches it.
	e.store(large(bundlesecret.ChunkBytes+(50<<10), "shop/b"))
	var chunk corev1.Secret
	_ = e.c.Get(ctx, client.ObjectKey{Namespace: "inkwall-system", Name: "inkwall-bundle-b-1"}, &chunk)
	chunk.Data[bundlesecret.ChunkKey][0] ^= 1
	if err := e.c.Update(ctx, &chunk); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(ctx, e.c, "inkwall-system"); !errors.Is(err, bundlesecret.ErrIncomplete) {
		t.Fatalf("edited chunk: %v, want ErrIncomplete", err)
	}
}

func TestStoreTooLarge(t *testing.T) {
	c := newClient(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(priv)
	// Random bytes don't compress (and are quicker than large's text).
	b := content()
	b.ContentHash = make([]byte, MaxCompressedBytes+1)
	_, _ = rand.Read(b.ContentHash)
	signed, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	size, err := Store(context.Background(), c, c, "inkwall-system", b, signed, signer.Public())
	if !errors.Is(err, ErrTooLarge) || size <= MaxCompressedBytes {
		t.Fatalf("got %d bytes, %v, want ErrTooLarge", size, err)
	}
	var s corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "inkwall-system", Name: BundleSecret}, &s); err == nil {
		t.Fatal("a too-large bundle was stored")
	}
	var chunks corev1.SecretList
	if err := c.List(context.Background(), &chunks); err != nil || len(chunks.Items) != 0 {
		t.Fatalf("a too-large bundle's chunks were stored: %d, %v", len(chunks.Items), err)
	}
}
