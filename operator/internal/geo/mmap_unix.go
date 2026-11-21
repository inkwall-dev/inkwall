// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package geo

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFile maps the first size bytes of f read-only.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED) // #nosec G115 -- a file descriptor
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
