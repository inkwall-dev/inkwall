// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
)

// randomTable is a table of random ranges, codes and aliases: none,
// MaxMind's three, or random prefixes of /1 to /96 outside ::/96.
func randomTable(r *rand.Rand, n4, n6 int) (*geov1.CountryTable, []netip.Prefix) {
	m := &geov1.CountryTable{}
	starts4 := map[uint32]bool{0: true}
	for len(starts4) < n4 {
		starts4[r.Uint32()>>(r.UintN(32))] = true
	}
	m.V4Starts = make([]uint32, 0, n4)
	for s := range starts4 {
		m.V4Starts = append(m.V4Starts, s)
	}
	slices.Sort(m.V4Starts)
	randCode := func() []byte {
		if r.IntN(4) == 0 {
			return []byte{0, 0}
		}
		return []byte{byte('A' + r.IntN(26)), byte('A' + r.IntN(26))}
	}
	for range n4 {
		m.V4Codes = append(m.V4Codes, randCode()...)
	}
	var starts6 [][16]byte
	seen := map[[16]byte]bool{{}: true}
	starts6 = append(starts6, [16]byte{})
	for len(starts6) < n6 {
		var a [16]byte
		binary.BigEndian.PutUint64(a[:], r.Uint64()>>r.UintN(64))
		binary.BigEndian.PutUint64(a[8:], r.Uint64())
		if r.IntN(2) == 0 {
			clear(a[2+r.IntN(14):]) // prefix-like starts
		}
		if !seen[a] {
			seen[a] = true
			starts6 = append(starts6, a)
		}
	}
	slices.SortFunc(starts6, func(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) })
	for _, s := range starts6 {
		m.V6Starts = append(m.V6Starts, s[:]...)
		m.V6Codes = append(m.V6Codes, randCode()...)
	}
	var aliases []netip.Prefix
	switch r.IntN(3) {
	case 1:
		for _, s := range maxmindAliases {
			aliases = append(aliases, netip.MustParsePrefix(s))
		}
	case 2:
		for range r.IntN(6) {
			var a [16]byte
			binary.BigEndian.PutUint64(a[:], r.Uint64())
			binary.BigEndian.PutUint64(a[8:], r.Uint64())
			p, _ := netip.AddrFrom16(a).Prefix(1 + r.IntN(96))
			if p.Overlaps(netip.MustParsePrefix("::/96")) || slices.ContainsFunc(aliases, p.Overlaps) {
				continue
			}
			aliases = append(aliases, p)
		}
		slices.SortFunc(aliases, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	}
	for _, p := range aliases {
		a := p.Addr().As16()
		m.V6Aliases = append(m.V6Aliases, a[:]...)
		m.V6Aliases = append(m.V6Aliases, byte(p.Bits()))
	}
	return m, aliases
}

// refLookup is a reference lookup: linear scans, and the aliases resolved
// bit by bit.
func refLookup(m *geov1.CountryTable, aliases []netip.Prefix, a netip.Addr) Country {
	at := func(codes []byte, i int) Country {
		c := Country(codes[2*i])<<8 | Country(codes[2*i+1])
		if c == unknownCode {
			return NoCountry
		}
		return c
	}
	v4 := func(x uint32) Country {
		i := 0
		for i+1 < len(m.V4Starts) && m.V4Starts[i+1] <= x {
			i++
		}
		return at(m.V4Codes, i)
	}
	a = a.Unmap()
	if a.Is4() {
		return v4(binary.BigEndian.Uint32(a.AsSlice()))
	}
	b := a.As16()
	for _, p := range append([]netip.Prefix{netip.MustParsePrefix("::/96")}, aliases...) {
		if p.Contains(a) {
			var x uint32
			for k := range 32 {
				bit := p.Bits() + k
				x = x<<1 | uint32(b[bit/8]>>(7-bit%8)&1)
			}
			return v4(x)
		}
	}
	i := 0
	for i+1 < len(m.V6Codes)/2 && bytes.Compare(m.V6Starts[16*(i+1):16*(i+2)], b[:]) <= 0 {
		i++
	}
	return at(m.V6Codes, i)
}

// probes returns addresses at and around every range start and alias
// edge, and random ones.
func probes(r *rand.Rand, m *geov1.CountryTable, aliases []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, s := range m.V4Starts {
		for _, d := range []uint32{0, 1, ^uint32(0)} {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], s+d)
			a := netip.AddrFrom4(b)
			out = append(out, a, netip.AddrFrom16(a.As16()))
		}
	}
	for i := 0; i < len(m.V6Starts); i += 16 {
		a := netip.AddrFrom16([16]byte(m.V6Starts[i : i+16]))
		out = append(out, a, a.Prev(), a.Next())
	}
	for _, p := range aliases {
		lo := p.Addr()
		out = append(out, lo, lo.Prev())
		// Addresses inside, embedding each IPv4 start.
		for range 8 {
			b := lo.As16()
			x := m.V4Starts[r.IntN(len(m.V4Starts))]
			for k := range 32 {
				bit := p.Bits() + k
				if x>>(31-k)&1 == 1 {
					b[bit/8] |= 1 << (7 - bit%8)
				}
			}
			in := netip.AddrFrom16(b)
			out = append(out, in, in.Prev(), in.Next())
		}
		hi := lo.As16()
		for bit := p.Bits(); bit < 128; bit++ {
			hi[bit/8] |= 1 << (7 - bit%8)
		}
		out = append(out, netip.AddrFrom16(hi), netip.AddrFrom16(hi).Next())
	}
	for range 256 {
		var b [16]byte
		binary.BigEndian.PutUint64(b[:], r.Uint64())
		binary.BigEndian.PutUint64(b[8:], r.Uint64())
		out = append(out, netip.AddrFrom16(b), netip.AddrFrom4([4]byte(b[:4])))
	}
	return slices.DeleteFunc(out, func(a netip.Addr) bool { return !a.IsValid() })
}

// TestModel checks lookups against the reference over random tables, with
// the aliases present or not, at random prefixes.
func TestModel(t *testing.T) {
	for seed := range uint64(200) {
		r := rand.New(rand.NewPCG(seed, 724))
		m, aliases := randomTable(r, 1+r.IntN(64), 1+r.IntN(64))
		ref := proto.Clone(m).(*geov1.CountryTable)
		tb, err := FromProto(m)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, a := range probes(r, ref, aliases) {
			want := refLookup(ref, aliases, a)
			got, res := tb.Lookup(a)
			if got != want {
				t.Fatalf("seed %d, aliases %v: Lookup(%s) = %q, want %q", seed, aliases, a, got, want)
			}
			if (res == ResultCountry) != (want != NoCountry) {
				t.Fatalf("seed %d: Lookup(%s) result %v for %q", seed, a, res, got)
			}
		}
	}
}

// FuzzTable feeds arbitrary bytes to the decoder and its checks: an error,
// or a table whose lookups never panic and whose bytes check again.
func FuzzTable(f *testing.F) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 4 {
		m, _ := randomTable(r, 8, 8)
		raw, _ := proto.Marshal(m)
		f.Add(raw)
	}
	raw, _ := proto.Marshal(table(f, []r4{{"0.0.0.0", ""}, {"1.0.0.0", "AU"}}, []r6{{"::", ""}, {"2001:db8::", "DE"}}, maxmindAliases...))
	f.Add(raw)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x04, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		tb, err := Unmarshal(raw)
		if err != nil {
			return
		}
		var m geov1.CountryTable
		if err := proto.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if err := Check(&m); err != nil {
			t.Fatalf("loaded, but Check: %v", err)
		}
		if tb.Ranges() == 0 || tb.Bytes() <= 0 {
			t.Fatalf("loaded an empty table: %d ranges", tb.Ranges())
		}
		r := rand.New(rand.NewPCG(uint64(len(raw)), 0))
		for _, a := range probes(r, &m, nil) {
			if c, res := tb.Lookup(a); (res == ResultCountry) != (c != NoCountry) || c != NoCountry && c.String() == "" {
				t.Fatalf("Lookup(%s) = %#x, %v", a, uint16(c), res)
			}
		}
	})
}
