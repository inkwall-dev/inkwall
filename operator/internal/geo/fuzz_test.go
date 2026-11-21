// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
	geotable "github.com/inkwall-dev/inkwall/pkg/geo"
)

// randomDB is a database of random networks and codes: an IPv4 one, or an
// IPv6 one with the IPv4 aliases present or not, at MaxMind's prefixes or
// at random ones, or whose tree ends above ::/96; and the addresses to
// probe: the networks' edges, random ones, and ones in the aliases.
func randomDB(r *rand.Rand) ([]byte, []netip.Addr) {
	codes := []string{"AU", "DE", "FR", "US", "ZZ", "de", "D1", ""}
	record := func() *mmdbtest.Record {
		switch r.IntN(6) {
		case 0:
			return nil
		case 1:
			return &mmdbtest.Record{Registered: codes[r.IntN(len(codes))]}
		case 2:
			return &mmdbtest.Record{Continent: "EU"}
		}
		return &mmdbtest.Record{Country: codes[r.IntN(len(codes))], Registered: codes[r.IntN(len(codes))]}
	}
	d := mmdbtest.DB{BuildEpoch: r.Uint64N(1 << 40)}
	kind := r.IntN(6) // 0: IPv4, 1: ends above ::/96, else IPv6 with aliases or not
	if kind == 0 {
		d.IPVersion = 4
	}
	var probes []netip.Addr
	random16 := func() [16]byte {
		var b [16]byte
		binary.BigEndian.PutUint64(b[:], r.Uint64())
		binary.BigEndian.PutUint64(b[8:], r.Uint64())
		return b
	}
	// Always one country, so the database is a country database.
	d.Networks = append(d.Networks, nw("1.0.0.0/8", cc("AU")))
	for range 1 + r.IntN(40) {
		var p netip.Prefix
		if kind == 0 || r.IntN(2) == 0 {
			b := random16()
			p, _ = netip.AddrFrom4([4]byte(b[:4])).Prefix(1 + r.IntN(32))
		} else {
			p, _ = netip.AddrFrom16(random16()).Prefix(1 + r.IntN(128))
		}
		d.Networks = append(d.Networks, mmdbtest.Network{Prefix: p, Record: record()})
		probes = append(probes, p.Addr())
	}
	if kind == 1 {
		// The tree ends above ::/96: all of IPv4 is one record.
		p, _ := netip.IPv6Unspecified().Prefix(1 + r.IntN(95))
		d.Networks = append(d.Networks, mmdbtest.Network{Prefix: p, Record: cc(codes[r.IntN(4)])})
	}
	switch aliases := r.IntN(3); {
	case kind < 2:
	case aliases == 1:
		d.Aliases = mmdbtest.MaxMindAliases
	case aliases == 2:
		for range 1 + r.IntN(4) {
			p, _ := netip.AddrFrom16(random16()).Prefix(1 + r.IntN(96))
			if p.Overlaps(netip.MustParsePrefix("::/96")) || slices.ContainsFunc(d.Aliases, p.Overlaps) {
				continue
			}
			d.Aliases = append(d.Aliases, p)
		}
	}
	for _, p := range d.Aliases {
		for range 4 {
			b := p.Addr().As16()
			x := random16()
			for bit := p.Bits(); bit < 128; bit++ {
				b[bit/8] |= x[bit/8] & (1 << (7 - bit%8))
			}
			probes = append(probes, netip.AddrFrom16(b))
		}
		probes = append(probes, p.Addr(), p.Addr().Prev())
	}
	for range 64 {
		b := random16()
		probes = append(probes, netip.AddrFrom16(b), netip.AddrFrom4([4]byte(b[:4])))
	}
	if kind == 0 {
		probes = slices.DeleteFunc(probes, func(a netip.Addr) bool { return !a.Unmap().Is4() })
	}
	for _, p := range slices.Clone(probes) {
		probes = append(probes, p.Next(), p.Prev())
	}
	db, err := d.Bytes()
	if err != nil {
		panic(err)
	}
	return db, slices.DeleteFunc(probes, func(a netip.Addr) bool { return !a.IsValid() })
}

// libraryCountry is the reference: the library's Lookup, its record's
// country as the compiler reads it. An IPv4-mapped address is its IPv4
// address, as everywhere in Inkwall.
func libraryCountry(r *maxminddb.Reader, a netip.Addr) (geotable.Country, error) {
	res := r.Lookup(a.Unmap())
	if err := res.Err(); err != nil {
		return 0, err
	}
	if !res.Found() {
		return geotable.NoCountry, nil
	}
	c := &compiler{codes: map[uintptr]code{}}
	return c.code(res)
}

// agree checks the table against the library's Lookup at probes.
func agree(t *testing.T, db []byte, tb *Table, probes []netip.Addr, mustLookUp bool) {
	t.Helper()
	g, err := geotable.Decode(tb.Compressed, tb.Hash[:], uint64(tb.Size))
	if err != nil {
		t.Fatalf("the engine refuses the compiled table: %v", err)
	}
	lib, err := maxminddb.OpenBytes(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range probes {
		want, err := libraryCountry(lib, a)
		if err != nil {
			if mustLookUp {
				t.Fatalf("library Lookup(%s): %v", a, err)
			}
			continue
		}
		if got, _ := g.Lookup(a); got != want {
			t.Fatalf("aliases %v: %s is %q, the library says %q", tb.Aliases, a, got, want)
		}
	}
}

// edges returns the first and last address of the database's first
// networks, aliases followed, and addresses inside the table's aliases.
func edges(db []byte, tb *Table) []netip.Addr {
	lib, err := maxminddb.OpenBytes(db)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	n := 0
	for res := range lib.Networks(maxminddb.IncludeAliasedNetworks(), maxminddb.IncludeNetworksWithoutData()) {
		if n++; n > 512 || res.Err() != nil {
			break
		}
		p := res.Prefix()
		out = append(out, p.Addr(), lastAddr(p))
	}
	for _, p := range tb.Aliases {
		out = append(out, p.Addr(), lastAddr(p), lastAddr(p).Next())
	}
	return slices.DeleteFunc(out, func(a netip.Addr) bool { return !a.IsValid() })
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 1 << (7 - bit%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// FuzzDifferential checks the compiled table against the library's own
// Lookup, for random databases with the aliases present or not.
func FuzzDifferential(f *testing.F) {
	for i := range uint64(16) {
		f.Add(i)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		r := rand.New(rand.NewPCG(seed, 724))
		db, probes := randomDB(r)
		tb, err := Compile(context.Background(), db, nil)
		if err != nil {
			if ReasonOf(err) == ReasonNoCountryData {
				return // the random codes left no country.iso_code
			}
			t.Fatalf("compile: %v", err)
		}
		agree(t, db, tb, append(probes, edges(db, tb)...), true)
	})
}

// FuzzCompile feeds the compiler arbitrary bytes, valid databases with
// bytes flipped, and trees whose nodes share children: an error, or a
// table the engine's checks pass; never a panic, a timeout or unbounded
// memory.
func FuzzCompile(f *testing.F) {
	defer func(n int) { maxNetworks = n }(maxNetworks)
	maxNetworks = 200_000
	r := rand.New(rand.NewPCG(7, 724))
	for range 4 {
		db, _ := randomDB(r)
		f.Add(db)
		f.Add(mmdbtest.Flip(db, r.IntN(len(db)), r.IntN(len(db))))
	}
	f.Add(mmdbtest.SharedChildren(40, false))
	f.Add(mmdbtest.SharedChildren(40, true))
	f.Add(mmdbtest.SharedChildren(126, false))
	f.Add(mmdbtest.SharedAliases(100))
	f.Add(mmdbtest.AlternatingAliases(26))
	f.Add(mmdbtest.Tree{Nodes: [][2]uint32{{1, 2}, {0, 0}, {3, 3}, {3, 3}}}.Bytes())
	f.Add([]byte("\xab\xcd\xefMaxMind.com"))
	f.Fuzz(func(t *testing.T, db []byte) {
		tb, err := Compile(context.Background(), db, nil)
		if err != nil {
			if ReasonOf(err) == "" {
				t.Fatalf("no reason: %v", err)
			}
			return
		}
		// The table the library's own answers, wherever it can give one.
		agree(t, db, tb, edges(db, tb), false)
	})
}
