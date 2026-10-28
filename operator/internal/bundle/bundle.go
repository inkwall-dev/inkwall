// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundle builds, signs and stores policy bundles (0004 §4.6). The
// bundle Secret is both what the distribution server sends and the engines'
// cold-start source, and it carries the version sequence, so a new leader
// continues it.
package bundle

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
)

// Names of the Secrets in the operator's namespace.
const (
	BundleSecret     = "inkwall-bundle"
	SigningKeySecret = "inkwall-bundle-signing-key" // #nosec G101 -- the Secret's name, not a credential
)

// Keys of the bundle Secret.
const (
	// BundleKey holds the gzip-compressed, serialized SignedBundle.
	BundleKey = "bundle.pb.gz"
	// PublicKeyKey holds the ed25519 public key the bundle is signed with,
	// so an engine reading the Secret can check which key it needs. In the
	// signing key Secret and the trust ConfigMap it is the active key.
	PublicKeyKey = "ed25519.pub"
)

// Annotations on the bundle Secret, for people and tools.
const (
	VersionAnnotation = "waf.inkwall.dev/bundle-version"
	HashAnnotation    = "waf.inkwall.dev/content-hash"
	// KeyIDAnnotation names the key the bundle is signed with.
	KeyIDAnnotation = "waf.inkwall.dev/key-id"
)

// MaxCompressedBytes is the largest bundle stored: Secrets are limited to
// 1 MiB. Bundles reference the Core Rule Set by name, so this takes many
// thousands of policies.
const MaxCompressedBytes = 900 << 10

// ErrTooLarge is returned for a bundle over MaxCompressedBytes.
var ErrTooLarge = errors.New("bundle too large for a Secret")

// ContentHash hashes what a bundle enforces: everything but its version,
// creation time and the hash itself. Encoding is deterministic, so equal
// content gives an equal hash within one operator version.
func ContentHash(b *bundlev1.Bundle) ([]byte, error) {
	c := proto.Clone(b).(*bundlev1.Bundle)
	c.Version, c.CreatedAt, c.ContentHash = 0, nil, nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// Next returns the bundle to publish for content, given the current one
// (nil if none), and whether it differs: unchanged content keeps the current
// version, unless resign asks for a new one (the signing key changed).
// lastVersion is the highest version this process published, so a deleted
// Secret doesn't restart the sequence while the leader runs.
func Next(current, content *bundlev1.Bundle, lastVersion uint64, now time.Time, resign bool) (*bundlev1.Bundle, bool, error) {
	hash, err := ContentHash(content)
	if err != nil {
		return nil, false, err
	}
	if current != nil && !resign && bytes.Equal(current.GetContentHash(), hash) {
		return current, false, nil
	}
	next := proto.Clone(content).(*bundlev1.Bundle)
	next.Version = max(current.GetVersion(), lastVersion) + 1
	next.CreatedAt = timestamppb.New(now)
	next.ContentHash = hash
	return next, true, nil
}

// Signer signs bundles.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
}

// NewSigner returns a Signer for key, with a key ID derived from its public
// key (bundlekey.ID).
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key, keyID: bundlekey.ID(key.Public().(ed25519.PublicKey))}
}

// GenerateSigner returns a Signer for a new key.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewSigner(priv), nil
}

// Public returns the public key.
func (s *Signer) Public() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// KeyID identifies the key.
func (s *Signer) KeyID() string { return s.keyID }

// Sign serializes and signs b.
func (s *Signer) Sign(b *bundlev1.Bundle) (*bundlev1.SignedBundle, error) {
	raw, err := proto.Marshal(b)
	if err != nil {
		return nil, err
	}
	return &bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(s.key, raw), KeyId: s.keyID}, nil
}

// Load reads the current bundle from its Secret, and the ID of the key it
// is signed with; nil if there is none.
func Load(ctx context.Context, c client.Reader, namespace string) (*bundlev1.Bundle, string, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: BundleSecret}, &s)
	if apierrors.IsNotFound(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	signed, err := Decode(s.Data[BundleKey])
	if err != nil {
		return nil, "", fmt.Errorf("bundle Secret: %w", err)
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, "", fmt.Errorf("bundle Secret: %w", err)
	}
	return &b, signed.GetKeyId(), nil
}

// Decode reads the content of the bundle Secret's BundleKey.
func Decode(data []byte) (*bundlev1.SignedBundle, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		return nil, err
	}
	var signed bundlev1.SignedBundle
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	return &signed, nil
}

// Store writes a signed bundle to the bundle Secret.
func Store(ctx context.Context, c client.Client, namespace string, b *bundlev1.Bundle, signed *bundlev1.SignedBundle, pub ed25519.PublicKey) error {
	raw, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if buf.Len() > MaxCompressedBytes {
		return fmt.Errorf("%w: %d bytes compressed, at most %d", ErrTooLarge, buf.Len(), MaxCompressedBytes)
	}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: BundleSecret}}
	data := map[string][]byte{BundleKey: buf.Bytes(), PublicKeyKey: pub}
	annotations := map[string]string{
		VersionAnnotation: strconv.FormatUint(b.GetVersion(), 10),
		HashAnnotation:    hex.EncodeToString(b.GetContentHash()),
		KeyIDAnnotation:   signed.GetKeyId(),
	}
	err = c.Get(ctx, client.ObjectKeyFromObject(s), s)
	switch {
	case apierrors.IsNotFound(err):
		s.Labels, s.Annotations, s.Data = managedLabels(), annotations, data
		return c.Create(ctx, s)
	case err != nil:
		return err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		s.Annotations[k] = v
	}
	s.Data = data
	return c.Update(ctx, s)
}

func managedLabels() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
}
