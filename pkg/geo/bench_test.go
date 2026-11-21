// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"testing"

	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
)

// synthetic is a table of n4 IPv4 and n6 IPv6 ranges at random starts, the
// IPv6 ones under 2000::/3 as allocated ranges are, with MaxMind's aliases.
func synthetic(tb testing.TB, n4, n6 int) *Table {
	tb.Helper()
	r := rand.New(rand.NewPCG(4, 724))
	m := &geov1.CountryTable{}
	// Evenly spread, each start jittered within its step.
	m.V4Starts = make([]uint32, n4)
	step4 := uint64(1<<32) / uint64(n4)
	for i := 1; i < n4; i++ {
		m.V4Starts[i] = uint32(uint64(i)*step4 + r.Uint64N(step4))
	}
	m.V6Starts = make([]byte, 16, 16*n6)
	step6 := uint64(1<<61) / uint64(n6)
	for i := 1; i < n6; i++ {
		m.V6Starts = binary.BigEndian.AppendUint64(m.V6Starts, 0x2000_0000_0000_0000|(uint64(i)*step6+r.Uint64N(step6)))
		m.V6Starts = binary.BigEndian.AppendUint64(m.V6Starts, r.Uint64())
	}
	code := func(n int) []byte {
		c := make([]byte, 2*n)
		for i := range n {
			c[2*i], c[2*i+1] = byte('A'+r.IntN(26)), byte('A'+r.IntN(26))
		}
		return c
	}
	m.V4Codes = code(len(m.V4Starts))
	m.V6Codes = code(len(m.V6Starts) / 16)
	m.V6Aliases = table(tb, nil, nil, maxmindAliases...).V6Aliases
	t, err := FromProto(m)
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

// BenchmarkLookup is one client's lookup at today's size (200,000 IPv4 and
// 200,000 IPv6 ranges) and at the bound of 32 MiB, all IPv4 or all IPv6,
// random addresses (design 0011 §10: ≤ 150 ns, 0 allocations).
func BenchmarkLookup(b *testing.B) {
	r := rand.New(rand.NewPCG(5, 724))
	v4 := make([]netip.Addr, 1<<16)
	v6 := make([]netip.Addr, 1<<16)
	for i := range v4 {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], r.Uint32())
		v4[i] = netip.AddrFrom4(a)
		var c [16]byte
		binary.BigEndian.PutUint64(c[:], 0x2000_0000_0000_0000|r.Uint64()>>3)
		binary.BigEndian.PutUint64(c[8:], r.Uint64())
		v6[i] = netip.AddrFrom16(c)
	}
	for _, c := range []struct {
		name   string
		n4, n6 int
	}{
		{"today", 200_000, 200_000},
		{"bound-v4", MaxRangeBytes/6 - 3, 1},
		{"bound-v6", 1, (MaxRangeBytes - 6) / 18},
	} {
		t := synthetic(b, c.n4, c.n6)
		for _, fam := range []struct {
			name  string
			addrs []netip.Addr
		}{{"v4", v4}, {"v6", v6}} {
			b.Run(c.name+"/"+fam.name, func(b *testing.B) {
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					t.Lookup(fam.addrs[i&(1<<16-1)])
					i++
				}
			})
		}
	}
}

// BenchmarkDecode is loading a table of today's size.
func BenchmarkDecode(b *testing.B) {
	t := synthetic(b, 200_000, 200_000)
	m := &geov1.CountryTable{V4Starts: t.v4, V4Codes: t.v4c, V6Codes: t.v6c, V6Aliases: table(b, nil, nil, maxmindAliases...).V6Aliases}
	for i := range t.v6hi {
		m.V6Starts = binary.BigEndian.AppendUint64(m.V6Starts, t.v6hi[i])
		m.V6Starts = binary.BigEndian.AppendUint64(m.V6Starts, t.v6lo[i])
	}
	gz, size, err := Encode(m)
	if err != nil {
		b.Fatal(err)
	}
	h := Hash(gz)
	b.ReportMetric(float64(len(gz)), "compressed-bytes")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(gz, h[:], uint64(size)); err != nil {
			b.Fatal(err)
		}
	}
}

// TestWideIndex checks a table large enough for a wider IPv6 index against
// a plain binary search over its starts.
func TestWideIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("a large table")
	}
	tb := synthetic(t, 1000, 600_000)
	if tb.shift6 >= 64-indexBits {
		t.Fatalf("IPv6 index of %d bits, want more than %d", 64-tb.shift6, indexBits)
	}
	r := rand.New(rand.NewPCG(6, 724))
	for range 20_000 {
		var b [16]byte
		binary.BigEndian.PutUint64(b[:], 0x2000_0000_0000_0000|r.Uint64()>>3)
		if r.IntN(4) == 0 { // a start exactly
			i := 1 + r.IntN(len(tb.v6hi)-1)
			binary.BigEndian.PutUint64(b[:], tb.v6hi[i])
			binary.BigEndian.PutUint64(b[8:], tb.v6lo[i])
		}
		if a := netip.AddrFrom16(b); netip.MustParsePrefix("2001::/32").Contains(a) || netip.MustParsePrefix("2002::/16").Contains(a) {
			continue // aliases, through the IPv4 table
		}
		x := u128From(b[:])
		lo, hi := 0, len(tb.v6hi)-1
		for lo < hi {
			m := (lo + hi + 1) / 2
			if !x.less(u128{tb.v6hi[m], tb.v6lo[m]}) {
				lo = m
			} else {
				hi = m - 1
			}
		}
		want := Country(tb.v6c[2*lo])<<8 | Country(tb.v6c[2*lo+1])
		if got, _ := tb.Lookup(netip.AddrFrom16(b)); got != want {
			t.Fatalf("Lookup(%s) = %v, want %v", netip.AddrFrom16(b), got, want)
		}
	}
}
