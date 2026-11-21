// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package geo

import (
	"io"
	"os"
)

// mapFile reads f into memory where there is no mmap: the operator runs on
// Linux, this is for building elsewhere.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, nil, err
	}
	return data, func() error { return nil }, nil
}
