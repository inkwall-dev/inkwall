// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"encoding/binary"
	"testing"
	"time"
)

// BenchmarkTake is one request's limit check (design 0009 §5.2: ≤ 1 µs, 0
// allocations).
func BenchmarkTake(b *testing.B) {
	keys := func(n int) []Key {
		ks := make([]Key, n)
		for i := range ks {
			ks[i].tag = tagIPv6
			binary.BigEndian.PutUint64(ks[i].b[:], uint64(i)*0x9e3779b97f4a7c15)
		}
		return ks
	}
	// One hot key from every CPU: the worst contention, on one shard.
	b.Run("hot-key", func(b *testing.B) {
		s := New(DefaultKeys, 0)
		l := s.Limit(Identity{Name: "b"}, 1_000_000, time.Second, 1_000_000)
		k := keys(1)[0]
		t := time.Now()
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				s.Take(l, k, t, nil)
			}
		})
	})
	// A million distinct keys: cache misses.
	b.Run("1M-keys", func(b *testing.B) {
		s := New(1<<20, 0)
		l := s.Limit(Identity{Name: "b"}, 10, time.Second, 10)
		ks := keys(1 << 20)
		t := time.Now()
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			s.Take(l, ks[i&(1<<20-1)], t, nil)
		}
	})
	// A full table: every new key evicts.
	b.Run("full-table", func(b *testing.B) {
		s := New(4096, 0)
		l := s.Limit(Identity{Name: "b"}, 1, time.Hour, 10)
		ks := keys(1 << 16)
		t := time.Now()
		for _, k := range ks {
			s.Take(l, k, t, nil)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			s.Take(l, ks[i&(1<<16-1)], t, nil)
		}
	})
}
