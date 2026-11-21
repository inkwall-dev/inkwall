// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FileRoot is the directory a database file must be in: where the Helm
// chart mounts geo.volume, or the geoipupdate sidecar writes (design 0011
// §3.2).
const FileRoot = "/var/lib/inkwall/geo"

// Source is a database: read it, then Close it.
type Source struct {
	// Data is the database. A file's is mapped read-only: its pages are
	// the page cache, not the heap.
	Data []byte
	// Size and ModTime are a file's, to see it change cheaply.
	Size    int64
	ModTime time.Time
	close   func() error
}

// Close releases the source's data.
func (s *Source) Close() error {
	if s == nil || s.close == nil {
		return nil
	}
	err := s.close()
	s.close, s.Data = nil, nil
	return err
}

// RelativePath returns name relative to root, refusing a path that isn't
// absolute, isn't clean or leaves root: an InkwallConfig mustn't ship the
// operator's own files to every engine.
func RelativePath(root, name string) (string, error) {
	if !path.IsAbs(name) || path.Clean(name) != name {
		return "", fmt.Errorf("%q is not an absolute, clean path", name)
	}
	rel, ok := strings.CutPrefix(name, root+"/")
	if !ok || rel == "" {
		return "", fmt.Errorf("%q is not under %s", name, root)
	}
	return rel, nil
}

// StatFile returns the size and the modification time of the database
// file name under root, to poll it without reading it.
func StatFile(root, name string) (int64, time.Time, error) {
	rel, err := RelativePath(root, name)
	if err != nil {
		return 0, time.Time{}, fail(ReasonInvalid, "database file: %v", err)
	}
	// Through the Root, without opening the file: a poll needs no read
	// access, and a symlink still can't lead out.
	r, err := os.OpenRoot(root)
	if err != nil {
		return 0, time.Time{}, fail(ReasonNotFound, "database directory %s: %v", root, err)
	}
	defer func() { _ = r.Close() }()
	fi, err := r.Stat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, time.Time{}, fail(ReasonNotFound, "database file %s not found", name)
	}
	if err != nil {
		return 0, time.Time{}, fail(ReasonInvalid, "%s: %v", name, err)
	}
	return fi.Size(), fi.ModTime(), nil
}

func openFile(root, name string) (*os.File, error) {
	rel, err := RelativePath(root, name)
	if err != nil {
		return nil, fail(ReasonInvalid, "database file: %v", err)
	}
	// A Root refuses a path, or a symlink, that leads out of it. Opened
	// without blocking: a FIFO in its place would block the open, before
	// the check that refuses anything but a regular file.
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fail(ReasonNotFound, "database directory %s: %v", root, err)
	}
	defer func() { _ = r.Close() }()
	f, err := r.OpenFile(rel, os.O_RDONLY|openNonblock, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fail(ReasonNotFound, "database file %s not found", name)
	}
	if err != nil {
		return nil, fail(ReasonInvalid, "database file: %v", err)
	}
	return f, nil
}

// ReadFile maps the database file name, under root, read-only.
func ReadFile(root, name string) (*Source, error) {
	f, err := openFile(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fail(ReasonInvalid, "%s: %v", name, err)
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, fail(ReasonInvalid, "%s is not a regular file", name)
	case fi.Size() == 0:
		return nil, fail(ReasonInvalid, "%s is empty", name)
	case fi.Size() > MaxFileBytes:
		return nil, fail(ReasonTooLarge, "%s has %d bytes, at most %d MiB", name, fi.Size(), MaxFileBytes>>20)
	}
	data, unmap, err := mapFile(f, int(fi.Size()))
	if err != nil {
		return nil, fail(ReasonInvalid, "mapping %s: %v", name, err)
	}
	return &Source{Data: data, Size: fi.Size(), ModTime: fi.ModTime(), close: unmap}, nil
}

// ReadSecret reads the database under key in the Secret name of
// namespace, gunzipped if it is gzipped (by its magic bytes), through a
// limit of MaxSecretBytes.
func ReadSecret(ctx context.Context, c client.Reader, namespace, name, key string) (*Source, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		return nil, fail(ReasonNotFound, "Secret %s/%s not found", namespace, name)
	}
	if err != nil {
		return nil, fmt.Errorf("the Secret %s/%s: %w", namespace, name, err)
	}
	data, ok := s.Data[key]
	if !ok {
		return nil, fail(ReasonNotFound, "Secret %s/%s has no key %q", namespace, name, key)
	}
	data, err = gunzipMaybe(data)
	if err != nil {
		return nil, err
	}
	return &Source{Data: data, Size: int64(len(data))}, nil
}

func gunzipMaybe(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		if len(data) > MaxSecretBytes {
			return nil, fail(ReasonTooLarge, "the database has %d bytes, at most %d MiB from a Secret", len(data), MaxSecretBytes>>20)
		}
		return data, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fail(ReasonInvalid, "the database's gzip: %v", err)
	}
	out, err := io.ReadAll(io.LimitReader(zr, MaxSecretBytes+1))
	if err != nil {
		return nil, fail(ReasonInvalid, "the database's gzip: %v", err)
	}
	if len(out) > MaxSecretBytes {
		return nil, fail(ReasonTooLarge, "the database has more than %d MiB decompressed, at most from a Secret", MaxSecretBytes>>20)
	}
	return out, nil
}
