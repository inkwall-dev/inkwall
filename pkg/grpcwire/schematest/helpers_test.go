// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package schematest tests grpcwire.Fields, apart from grpcwire's own
// tests: the descriptors, protodesc and dynamicpb it needs would weigh on
// BenchmarkGRPCMessages' garbage collection in grpcwire's test binary.
package schematest

import (
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// pb builds a message: pairs of a field number and a string, a nested
// message ([]byte) or a number (uint64).
func pb(fields ...any) []byte {
	var b []byte
	for i := 0; i+1 < len(fields); i += 2 {
		num := protowire.Number(fields[i].(int))
		switch v := fields[i+1].(type) {
		case string:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendString(b, v)
		case []byte:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, v)
		case uint64:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, v)
		}
	}
	return b
}

// prefixed prefixes msg as a gRPC message.
func prefixed(compressed bool, msg []byte) []byte {
	var flag byte
	if compressed {
		flag = 1
	}
	n := len(msg)
	return append([]byte{flag, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, msg...)
}

// grpcwireStringText is a string field's text as Fields gives it: each C0
// control character but tab, CR and LF, DEL, and each byte that isn't
// UTF-8, a space.
func grpcwireStringText(v []byte) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, n := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError && n == 1 || r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f {
			b.WriteByte(' ')
		} else {
			b.Write(v[i : i+n])
		}
		i += n
	}
	return b.String()
}
