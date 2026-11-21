// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package geo

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNonblock opens a FIFO without waiting for a writer.
const openNonblock = unix.O_NONBLOCK

// mapFile maps the first size bytes of f read-only. The mapping is shared:
// the database must be replaced by a rename (geoipupdate writes a new file
// and renames it), not rewritten in place, which would change the bytes
// under the compiler and so desynchronize them from the hash it took. A
// file truncated in place faults, which Compile recovers.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED) // #nosec G115 -- a file descriptor
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
