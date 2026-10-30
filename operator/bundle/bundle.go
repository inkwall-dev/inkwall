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
	"maps"
	"slices"
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
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// Names of the Secrets in the operator's namespace.
const (
	BundleSecret     = "inkwall-bundle"
	SigningKeySecret = "inkwall-bundle-signing-key" // #nosec G101 -- the Secret's name, not a credential
)

// Keys of the bundle Secret.
const (
	// BundleKey holds the gzip-compressed, serialized SignedBundle, when it
	// fits in one Secret; else ManifestKey lists its chunks.
	BundleKey   = bundlesecret.BundleKey
	ManifestKey = bundlesecret.ManifestKey
	// PublicKeyKey holds the ed25519 public key the bundle is signed with,
	// so an engine reading the Secret can check which key it needs. In the
	// signing key Secret and the trust ConfigMap it is the active key.
	PublicKeyKey = "ed25519.pub"
)

// ChunkLabel marks the chunk Secrets of a bundle too large for one Secret.
const ChunkLabel = "waf.inkwall.dev/bundle-chunk"

// Annotations on the bundle Secret, for people and tools.
const (
	VersionAnnotation = "waf.inkwall.dev/bundle-version"
	HashAnnotation    = "waf.inkwall.dev/content-hash"
	// KeyIDAnnotation names the key the bundle is signed with.
	KeyIDAnnotation = "waf.inkwall.dev/key-id"
)

// MaxCompressedBytes is the largest bundle stored, in chunks of
// bundlesecret.ChunkBytes: Secrets are limited to 1 MiB. Bundles reference
// the Core Rule Set by name, so one Secret takes many thousands of policies.
const MaxCompressedBytes = bundlesecret.MaxBytes

// ErrTooLarge is returned for a bundle over MaxCompressedBytes, or over
// bundlesecret.MaxBundleBytes decompressed.
var ErrTooLarge = errors.New("bundle too large for its Secrets")

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
// is signed with; nil if there is none. If its chunks don't match its
// manifest (bundlesecret.ErrIncomplete), the bundle has only the version of
// the Secret's annotation, to continue the sequence.
func Load(ctx context.Context, c client.Reader, namespace string) (*bundlev1.Bundle, string, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: BundleSecret}, &s)
	if apierrors.IsNotFound(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	signed, err := Read(ctx, c, &s)
	if errors.Is(err, bundlesecret.ErrIncomplete) {
		v, _ := strconv.ParseUint(s.Annotations[VersionAnnotation], 10, 64)
		return &bundlev1.Bundle{Version: v}, "", fmt.Errorf("bundle Secret: %w", err)
	}
	if err != nil {
		return nil, "", fmt.Errorf("bundle Secret: %w", err)
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, "", fmt.Errorf("bundle Secret: %w", err)
	}
	return &b, signed.GetKeyId(), nil
}

// Read returns the signed bundle of the bundle Secret s, reading its chunks
// with c if it has a manifest.
func Read(ctx context.Context, c client.Reader, s *corev1.Secret) (*bundlev1.SignedBundle, error) {
	data, ok := s.Data[BundleKey]
	if !ok && s.Data[ManifestKey] != nil {
		m, err := bundlesecret.ParseManifest(s.Name, s.Data[ManifestKey])
		if err != nil {
			return nil, err
		}
		data, err = bundlesecret.Join(m, func(name string) ([]byte, error) {
			var chunk corev1.Secret
			err := c.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: name}, &chunk)
			if apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("%w: Secret %s not found", bundlesecret.ErrIncomplete, name)
			}
			return chunk.Data[bundlesecret.ChunkKey], err
		})
		if err != nil {
			return nil, err
		}
	}
	return Decode(data)
}

// CompressedSize returns the size of the bundle Secret s's compressed
// bundle, in one Secret or in chunks.
func CompressedSize(s *corev1.Secret) int {
	if data, ok := s.Data[BundleKey]; ok {
		return len(data)
	}
	if m, err := bundlesecret.ParseManifest(s.Name, s.Data[ManifestKey]); err == nil {
		return m.Size
	}
	return 0
}

// Decode reads the compressed bundle of the bundle Secret's BundleKey, or
// of its chunks joined.
func Decode(data []byte) (*bundlev1.SignedBundle, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, bundlesecret.MaxBundleBytes))
	if err != nil {
		return nil, err
	}
	var signed bundlev1.SignedBundle
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	return &signed, nil
}

// Encode returns the compressed bundle for signed: the reverse of Decode.
func Encode(signed *bundlev1.SignedBundle) ([]byte, error) {
	raw, err := proto.Marshal(signed)
	if err != nil {
		return nil, err
	}
	if len(raw) > bundlesecret.MaxBundleBytes {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrTooLarge, len(raw), bundlesecret.MaxBundleBytes)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxCompressedBytes {
		return buf.Bytes(), fmt.Errorf("%w: %d bytes compressed, at most %d", ErrTooLarge, buf.Len(), MaxCompressedBytes)
	}
	return buf.Bytes(), nil
}

// Store writes a signed bundle to the bundle Secret, and returns its
// compressed size (also with ErrTooLarge, when known). A bundle over
// bundlesecret.ChunkBytes is split into chunk Secrets, written before the
// manifest that points at them, to the names the current manifest doesn't
// use; Prune deletes the others after. c writes, r reads uncached: the
// current manifest decides where the chunks go.
func Store(ctx context.Context, c client.Client, r client.Reader, namespace string, b *bundlev1.Bundle,
	signed *bundlev1.SignedBundle, pub ed25519.PublicKey) (int, error) {
	encoded, err := Encode(signed)
	if err != nil {
		return len(encoded), err
	}
	annotations := map[string]string{
		VersionAnnotation: strconv.FormatUint(b.GetVersion(), 10),
		HashAnnotation:    hex.EncodeToString(b.GetContentHash()),
		KeyIDAnnotation:   signed.GetKeyId(),
	}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: BundleSecret}}
	err = r.Get(ctx, client.ObjectKeyFromObject(s), s)
	exists := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return len(encoded), err
	}
	data := map[string][]byte{BundleKey: encoded, PublicKeyKey: pub}
	if len(encoded) > bundlesecret.ChunkBytes {
		// An unreadable manifest is overwritten: its chunks are useless.
		current, _ := bundlesecret.ParseManifest(BundleSecret, s.Data[ManifestKey])
		m, chunks, err := bundlesecret.Split(BundleSecret, bundlesecret.NextSlot(BundleSecret, current), encoded)
		if err != nil {
			return len(encoded), err
		}
		for i, chunk := range chunks {
			if err := writeChunk(ctx, c, r, namespace, m.Chunks[i], chunk, annotations); err != nil {
				return len(encoded), fmt.Errorf("chunk %s: %w", m.Chunks[i], err)
			}
		}
		manifest, err := m.Marshal()
		if err != nil {
			return len(encoded), err
		}
		data = map[string][]byte{ManifestKey: manifest, PublicKeyKey: pub}
	}
	return len(encoded), save(ctx, c, s, exists, managedLabels(), annotations, data)
}

func writeChunk(ctx context.Context, c client.Client, r client.Reader, namespace, name string, chunk []byte, annotations map[string]string) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	err := r.Get(ctx, client.ObjectKeyFromObject(s), s)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	labels := managedLabels()
	labels[ChunkLabel] = BundleSecret
	return save(ctx, c, s, err == nil, labels, annotations, map[string][]byte{bundlesecret.ChunkKey: chunk})
}

// save creates s, or updates it if it exists, with labels and annotations
// added and data replaced.
func save(ctx context.Context, c client.Client, s *corev1.Secret, exists bool, labels, annotations map[string]string, data map[string][]byte) error {
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	maps.Copy(s.Labels, labels)
	maps.Copy(s.Annotations, annotations)
	s.Data = data
	if !exists {
		return c.Create(ctx, s)
	}
	return c.Update(ctx, s)
}

// Prune deletes the chunk Secrets the bundle Secret's manifest doesn't list:
// those of a bundle replaced since. r reads the bundle Secret uncached, c
// lists the chunks.
func Prune(ctx context.Context, c client.Client, r client.Reader, namespace string) error {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: BundleSecret}, &s); err != nil {
		// No bundle yet, or none to read: keep everything.
		return client.IgnoreNotFound(err)
	}
	var keep []string
	if _, ok := s.Data[BundleKey]; !ok {
		m, err := bundlesecret.ParseManifest(BundleSecret, s.Data[ManifestKey])
		if err != nil {
			return nil
		}
		keep = m.Chunks
	}
	var chunks corev1.SecretList
	if err := c.List(ctx, &chunks, client.InNamespace(namespace), client.MatchingLabels{ChunkLabel: BundleSecret}); err != nil {
		return err
	}
	for i := range chunks.Items {
		ch := &chunks.Items[i]
		if !bundlesecret.IsChunk(BundleSecret, ch.Name) || slices.Contains(keep, ch.Name) {
			continue
		}
		if err := c.Delete(ctx, ch); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete chunk %s: %w", ch.Name, err)
		}
	}
	return nil
}

func managedLabels() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
}
