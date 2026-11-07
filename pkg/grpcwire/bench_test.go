// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"
)

// prefixed prefixes msg as a gRPC message.
func prefixed(compressed bool, msg []byte) []byte {
	var flag byte
	if compressed {
		flag = 1
	}
	return []byte(frame(flag, string(msg)))
}

// BenchmarkGRPCMessages (#369): reading the text of a call's messages, as
// the pipeline does with grpcMessages: Inspect: splitting the body, and
// walking each message for its text fields; gzip-compressed too.
func BenchmarkGRPCMessages(b *testing.B) {
	// A typical request: a few strings, a number and a nested message.
	small := pb(1, "alice@example.com", 2, uint64(42), 3, pb(1, "shipping", 2, "221B Baker Street"))
	// A larger one: 50 repeated items with text, nested 3 deep.
	var large []byte
	for i := range 50 {
		large = append(large, pb(4, pb(1, fmt.Sprintf("item-%d", i), 2, pb(1, "a description of the item", 2, pb(1, "deep")), 3, uint64(i)))...)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(large)
	_ = w.Close()
	cases := []struct {
		name string
		body []byte
	}{
		{"small", prefixed(false, small)},
		{"three_small", append(append(prefixed(false, small), prefixed(false, small)...), prefixed(false, small)...)},
		{"large", prefixed(false, large)},
		{"large_gzip", prefixed(true, gz.Bytes())},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.body)))
			var out []Field
			for b.Loop() {
				msgs, ok := Messages(c.body, false)
				if !ok {
					b.Fatal("not gRPC messages")
				}
				out = out[:0]
				for _, m := range msgs {
					data := m.Data
					if m.Compressed {
						if data, ok = Gunzip(data, 1<<20); !ok {
							b.Fatal("gunzip")
						}
					}
					if out, ok = Strings(data, DefaultLimits, out); !ok {
						b.Fatal("not protobuf")
					}
				}
				if len(out) == 0 {
					b.Fatal("no text")
				}
			}
		})
	}
}
