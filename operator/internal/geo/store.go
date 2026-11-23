// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	geotable "github.com/inkwall-dev/inkwall/pkg/geo"
)

// Annotations of the geo manifest Secret.
const (
	// SizeAnnotation is the serialized table's size, what a bundle's
	// GeoTableRef names.
	SizeAnnotation = "waf.inkwall.dev/geo-table-size"
	// DatabaseHashAnnotation is the source database's SHA-256, in hex, to
	// skip compiling it again.
	DatabaseHashAnnotation = "waf.inkwall.dev/geo-database-sha256"
	// For people and tools.
	DatabaseTypeAnnotation = "waf.inkwall.dev/geo-database-type"
	BuildEpochAnnotation   = "waf.inkwall.dev/geo-build-epoch"
	// AliasesAnnotation lists the aliases found, comma-separated, and
	// BadCodesAnnotation counts the networks with a bad code: the status
	// message after a leader change.
	AliasesAnnotation  = "waf.inkwall.dev/geo-aliases"
	BadCodesAnnotation = "waf.inkwall.dev/geo-bad-codes"
)

// Format is the format of the table's Secrets: a manifest Secret,
// inkwall-geo, and up to 16 chunks per slot.
var Format = bundlesecret.Geo

// Load reads the stored table from its Secrets, nil if there is none, and
// checks it as an engine would: against the manifest's hash, then
// decompressed and checked. r should read uncached.
func Load(ctx context.Context, r client.Reader, namespace string) (*Table, error) {
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: Format.Name}, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := Format.ParseManifest(s.Data[bundlesecret.ManifestKey])
	if err != nil {
		return nil, fmt.Errorf("the Secret %s: %w", Format.Name, err)
	}
	gz, err := bundlesecret.Join(m, func(name string) ([]byte, error) {
		var chunk corev1.Secret
		err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &chunk)
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: Secret %s not found", bundlesecret.ErrIncomplete, name)
		}
		return chunk.Data[bundlesecret.ChunkKey], err
	})
	if err != nil {
		return nil, fmt.Errorf("the Secret %s: %w", Format.Name, err)
	}
	size, err := strconv.Atoi(s.Annotations[SizeAnnotation])
	if err != nil || size <= 0 {
		return nil, fmt.Errorf("the Secret %s: annotation %s is %q", Format.Name, SizeAnnotation, s.Annotations[SizeAnnotation])
	}
	dbHash, err := hex.DecodeString(s.Annotations[DatabaseHashAnnotation])
	if err != nil || len(dbHash) != 32 {
		return nil, fmt.Errorf("the Secret %s: annotation %s is %q", Format.Name, DatabaseHashAnnotation, s.Annotations[DatabaseHashAnnotation])
	}
	hash := geotable.Hash(gz)
	t, err := geotable.Decode(gz, hash[:], uint64(size))
	if err != nil {
		return nil, fmt.Errorf("the Secret %s: %w", Format.Name, err)
	}
	var aliases []netip.Prefix
	for a := range strings.SplitSeq(s.Annotations[AliasesAnnotation], ",") {
		if p, err := netip.ParsePrefix(a); err == nil {
			aliases = append(aliases, p)
		}
	}
	bad, _ := strconv.Atoi(s.Annotations[BadCodesAnnotation])
	return &Table{
		Compressed:     gz,
		Hash:           hash,
		Size:           size,
		DatabaseType:   t.DatabaseType(),
		BuildEpoch:     uint64(max(t.Built().Unix(), 0)), // #nosec G115 -- not negative
		DatabaseSHA256: [32]byte(dbHash),
		Ranges:         t.Ranges(),
		Aliases:        aliases,
		BadCodes:       max(bad, 0),
	}, nil
}

// Store writes t to the table's Secrets: its chunks, to the slot the
// current manifest doesn't use, then the manifest that names them, so a
// reader never sees a manifest whose chunks aren't written. It writes
// nothing when the manifest already names t. c writes, r reads uncached.
// The leader stores the table before the bundle that names it, and prunes
// the other slot (Prune) only after that bundle is stored.
func Store(ctx context.Context, c client.Client, r client.Reader, namespace string, t *Table) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: Format.Name}}
	err := r.Get(ctx, client.ObjectKeyFromObject(s), s)
	exists := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// An unreadable manifest is overwritten: its chunks are useless.
	current, _ := Format.ParseManifest(s.Data[bundlesecret.ManifestKey])
	if current != nil && current.SHA256 == hex.EncodeToString(t.Hash[:]) && s.Annotations[SizeAnnotation] == strconv.Itoa(t.Size) {
		return nil
	}
	m, chunks, err := Format.Split(bundlesecret.NextSlot(Format.Name, current), t.Compressed)
	if err != nil {
		return fail(ReasonTooLarge, "the table: %v", err)
	}
	for i, chunk := range chunks {
		if err := writeChunk(ctx, c, r, namespace, m.Chunks[i], chunk); err != nil {
			return fmt.Errorf("chunk %s: %w", m.Chunks[i], err)
		}
	}
	manifest, err := m.Marshal()
	if err != nil {
		return err
	}
	annotations := map[string]string{
		SizeAnnotation:         strconv.Itoa(t.Size),
		DatabaseHashAnnotation: hex.EncodeToString(t.DatabaseSHA256[:]),
		DatabaseTypeAnnotation: t.DatabaseType,
		BuildEpochAnnotation:   strconv.FormatUint(t.BuildEpoch, 10),
		AliasesAnnotation:      joinPrefixes(t.Aliases),
		BadCodesAnnotation:     strconv.Itoa(t.BadCodes),
	}
	return save(ctx, c, s, exists, managedLabels(), annotations, map[string][]byte{bundlesecret.ManifestKey: manifest})
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}

func writeChunk(ctx context.Context, c client.Client, r client.Reader, namespace, name string, chunk []byte) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	err := r.Get(ctx, client.ObjectKeyFromObject(s), s)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	labels := managedLabels()
	labels[bundle.ChunkLabel] = Format.Name
	return save(ctx, c, s, err == nil, labels, nil, map[string][]byte{bundlesecret.ChunkKey: chunk})
}

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

// Prune deletes the table's chunk Secrets its manifest doesn't list: those
// of a table replaced since. The leader calls it once the bundle that names
// the current table is stored. r reads the manifest uncached, c lists the
// chunks.
func Prune(ctx context.Context, c client.Client, r client.Reader, namespace string) error {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: Format.Name}, &s); err != nil {
		return client.IgnoreNotFound(err)
	}
	m, err := Format.ParseManifest(s.Data[bundlesecret.ManifestKey])
	if err != nil {
		return nil // nothing to go by: keep everything
	}
	var chunks corev1.SecretList
	if err := c.List(ctx, &chunks, client.InNamespace(namespace), client.MatchingLabels{bundle.ChunkLabel: Format.Name}); err != nil {
		return err
	}
	for i := range chunks.Items {
		ch := &chunks.Items[i]
		if !Format.IsChunk(ch.Name) || slices.Contains(m.Chunks, ch.Name) {
			continue
		}
		if err := c.Delete(ctx, ch); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete chunk %s: %w", ch.Name, err)
		}
	}
	return nil
}

// Delete deletes the table's Secrets, the manifest first, so no reader
// sees a manifest without its chunks. r lists the chunks uncached.
func Delete(ctx context.Context, c client.Client, r client.Reader, namespace string) error {
	err := c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: Format.Name}})
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	var chunks corev1.SecretList
	if err := r.List(ctx, &chunks, client.InNamespace(namespace), client.MatchingLabels{bundle.ChunkLabel: Format.Name}); err != nil {
		return err
	}
	for i := range chunks.Items {
		if ch := &chunks.Items[i]; Format.IsChunk(ch.Name) {
			if err := c.Delete(ctx, ch); client.IgnoreNotFound(err) != nil {
				return fmt.Errorf("delete chunk %s: %w", ch.Name, err)
			}
		}
	}
	return nil
}

func managedLabels() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
}
