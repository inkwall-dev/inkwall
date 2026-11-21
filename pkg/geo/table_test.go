// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
)

// r4 and r6 are a range's start and its country ("" for none).
type r4 struct {
	start string
	cc    string
}

type r6 = r4

func code(t testing.TB, cc string) []byte {
	t.Helper()
	if cc == "" {
		return []byte{0, 0}
	}
	if len(cc) != 2 {
		t.Fatalf("code %q", cc)
	}
	return []byte(cc)
}

// table builds the CountryTable of the ranges and aliases (prefixes).
func table(t testing.TB, v4 []r4, v6 []r6, aliases ...string) *geov1.CountryTable {
	t.Helper()
	m := &geov1.CountryTable{DatabaseType: "Test-Country", DatabaseBuildEpoch: 1_700_000_000}
	for _, r := range v4 {
		a := netip.MustParseAddr(r.start)
		m.V4Starts = append(m.V4Starts, binary.BigEndian.Uint32(a.AsSlice()))
		m.V4Codes = append(m.V4Codes, code(t, r.cc)...)
	}
	for _, r := range v6 {
		a := netip.MustParseAddr(r.start).As16()
		m.V6Starts = append(m.V6Starts, a[:]...)
		m.V6Codes = append(m.V6Codes, code(t, r.cc)...)
	}
	for _, s := range aliases {
		p := netip.MustParsePrefix(s)
		a := p.Addr().As16()
		m.V6Aliases = append(m.V6Aliases, a[:]...)
		m.V6Aliases = append(m.V6Aliases, byte(p.Bits()))
	}
	return m
}

func load(t testing.TB, m *geov1.CountryTable) *Table {
	t.Helper()
	tb, err := FromProto(m)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

var maxmindAliases = []string{"::ffff:0:0/96", "2001::/32", "2002::/16"}

func sample(t testing.TB, aliases ...string) *Table {
	return load(t, table(t,
		[]r4{{"0.0.0.0", ""}, {"1.0.0.0", "AU"}, {"1.0.1.0", "CN"}, {"5.0.0.0", ""}, {"192.0.2.0", "XA"}, {"192.0.3.0", ""}, {"255.255.255.255", "ZW"}},
		[]r6{{"::", ""}, {"2001::", "XT"}, {"2001:db8::", "DE"}, {"2001:db9::", ""}, {"2002::", "XS"}, {"2003::", "FR"}, {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ZW"}},
		aliases...))
}

func TestLookup(t *testing.T) {
	plain, aliased := sample(t), sample(t, maxmindAliases...)
	for _, c := range []struct {
		addr          string
		plain, alised string
		res           Result
	}{
		// Range edges.
		{"0.0.0.0", "", "", ResultPrivate},
		{"0.255.255.255", "", "", ResultUnknown},
		{"1.0.0.0", "AU", "AU", ResultCountry},
		{"1.0.0.255", "AU", "AU", ResultCountry},
		{"1.0.1.0", "CN", "CN", ResultCountry},
		{"4.255.255.255", "CN", "CN", ResultCountry},
		{"5.0.0.0", "", "", ResultUnknown},
		{"192.0.2.255", "XA", "XA", ResultCountry},
		{"192.0.3.0", "", "", ResultUnknown},
		{"255.255.255.254", "", "", ResultUnknown},
		{"255.255.255.255", "ZW", "ZW", ResultCountry},
		{"::", "", "", ResultPrivate},
		{"::1", "", "", ResultPrivate},
		// Outside Teredo, 2001:0::/32.
		{"2001:db8::", "DE", "DE", ResultCountry},
		{"2001:db8:ffff::", "DE", "DE", ResultCountry},
		{"2003::1", "FR", "FR", ResultCountry},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "FR", "FR", ResultCountry},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ZW", "ZW", ResultCountry},
		// IPv4-mapped: always its IPv4 address.
		{"::ffff:1.0.1.7", "CN", "CN", ResultCountry},
		// IPv4-compatible (::/96): the IPv4 tree.
		{"::1.0.0.9", "AU", "AU", ResultCountry},
		// 6to4 (2002:c000:0207::/48 is 192.0.2.7) and Teredo (2001:0:c000:0207::, server 192.0.2.7).
		{"2002:c000:207::1", "XS", "XA", ResultCountry},
		{"2002:0100:0001::", "XS", "AU", ResultCountry},
		{"2001:0:c000:207::1", "XT", "XA", ResultCountry},
	} {
		a := netip.MustParseAddr(c.addr)
		for _, tc := range []struct {
			name string
			tb   *Table
			want string
		}{{"plain", plain, c.plain}, {"aliased", aliased, c.alised}} {
			got, res := tc.tb.Lookup(a)
			if got.String() != tc.want {
				t.Errorf("%s: Lookup(%s) = %q, want %q", tc.name, c.addr, got, tc.want)
			}
			if tc.want != "" && res != ResultCountry || tc.want == "" && res != c.res {
				t.Errorf("%s: Lookup(%s) result %v, want %v", tc.name, c.addr, res, c.res)
			}
		}
	}
}

func TestLookupPrivate(t *testing.T) {
	tb := load(t, table(t, []r4{{"0.0.0.0", ""}, {"10.1.0.0", "XA"}, {"10.1.1.0", ""}}, []r6{{"::", ""}}))
	for _, c := range []struct {
		addr string
		want Result
	}{
		{"10.0.0.1", ResultPrivate},
		{"10.1.0.1", ResultCountry}, // a country the database maps always wins
		{"172.16.0.1", ResultPrivate},
		{"192.168.1.1", ResultPrivate},
		{"127.0.0.1", ResultPrivate},
		{"169.254.1.1", ResultPrivate},
		{"100.64.0.1", ResultPrivate},
		{"100.127.255.255", ResultPrivate},
		{"100.128.0.0", ResultUnknown},
		{"100.63.255.255", ResultUnknown},
		{"0.0.0.0", ResultPrivate},
		{"::ffff:192.168.0.1", ResultPrivate},
		{"fd00::1", ResultPrivate},
		{"fe80::1", ResultPrivate},
		{"::1", ResultPrivate},
		{"::", ResultPrivate},
		{"8.8.8.8", ResultUnknown},
		{"2a00::1", ResultUnknown},
	} {
		if _, res := tb.Lookup(netip.MustParseAddr(c.addr)); res != c.want {
			t.Errorf("Lookup(%s) = %v, want %v", c.addr, res, c.want)
		}
	}
	if c, res := tb.Lookup(netip.Addr{}); c != NoCountry || res != ResultPrivate {
		t.Errorf("Lookup(zero Addr) = %v, %v, want no country, private", c, res)
	}
	var none *Table
	if c, res := none.Lookup(netip.MustParseAddr("8.8.8.8")); c != NoCountry || res != ResultNoTable {
		t.Errorf("nil table: %v, %v", c, res)
	}
	if _, res := none.Lookup(netip.Addr{}); res != ResultNoTable {
		t.Errorf("nil table, zero Addr: %v, want no-table", res)
	}
}

func TestZZIsNoCountry(t *testing.T) {
	tb := load(t, table(t, []r4{{"0.0.0.0", ""}, {"8.0.0.0", "ZZ"}, {"9.0.0.0", "US"}}, []r6{{"::", "ZZ"}}))
	if c, res := tb.Lookup(netip.MustParseAddr("8.8.8.8")); c != NoCountry || res != ResultUnknown {
		t.Errorf("ZZ: %v, %v, want no country, unknown", c, res)
	}
	if c, _ := tb.Lookup(netip.MustParseAddr("9.9.9.9")); c.String() != "US" {
		t.Errorf("US: %v", c)
	}
	if _, res := tb.Lookup(netip.MustParseAddr("2a00::1")); res != ResultUnknown {
		t.Errorf("ZZ v6: %v", res)
	}
}

func TestLookupAllocs(t *testing.T) {
	tb := sample(t, maxmindAliases...)
	addrs := []netip.Addr{netip.MustParseAddr("1.0.1.1"), netip.MustParseAddr("2002:c000:207::1"), netip.MustParseAddr("2003::1"), netip.MustParseAddr("10.0.0.1")}
	if n := testing.AllocsPerRun(100, func() {
		for _, a := range addrs {
			tb.Lookup(a)
		}
	}); n != 0 {
		t.Errorf("Lookup allocates %v times", n)
	}
}

func TestCheck(t *testing.T) {
	good := func() *geov1.CountryTable {
		return table(t, []r4{{"0.0.0.0", ""}, {"1.0.0.0", "AU"}}, []r6{{"::", ""}, {"2001:db8::", "DE"}}, maxmindAliases...)
	}
	if err := Check(good()); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		edit func(*geov1.CountryTable)
		want string
	}{
		"no IPv4":           {func(m *geov1.CountryTable) { m.V4Starts, m.V4Codes = nil, nil }, "at least one of each"},
		"no IPv6":           {func(m *geov1.CountryTable) { m.V6Starts, m.V6Codes = nil, nil }, "at least one of each"},
		"v6 starts length":  {func(m *geov1.CountryTable) { m.V6Starts = m.V6Starts[:20] }, "multiple of 16"},
		"v4 codes length":   {func(m *geov1.CountryTable) { m.V4Codes = m.V4Codes[:3] }, "bytes of codes"},
		"v6 codes length":   {func(m *geov1.CountryTable) { m.V6Codes = append(m.V6Codes, 'A', 'B') }, "bytes of codes"},
		"v4 first":          {func(m *geov1.CountryTable) { m.V4Starts[0] = 1 }, "0.0.0.0"},
		"v6 first":          {func(m *geov1.CountryTable) { m.V6Starts[15] = 1 }, "address zero"},
		"v4 order":          {func(m *geov1.CountryTable) { m.V4Starts = append(m.V4Starts, 5); m.V4Codes = append(m.V4Codes, 0, 0) }, "doesn't start after"},
		"v4 duplicate":      {func(m *geov1.CountryTable) { m.V4Starts[1] = 0 }, "doesn't start after"},
		"v6 order":          {func(m *geov1.CountryTable) { copy(m.V6Starts[16:], make([]byte, 16)) }, "doesn't start after"},
		"code lower":        {func(m *geov1.CountryTable) { m.V4Codes[2] = 'a' }, "not two letters"},
		"code half":         {func(m *geov1.CountryTable) { m.V6Codes[2] = 0 }, "not two letters"},
		"aliases length":    {func(m *geov1.CountryTable) { m.V6Aliases = m.V6Aliases[:16] }, "multiple of 17"},
		"alias /0":          {func(m *geov1.CountryTable) { m.V6Aliases[16] = 0 }, "/1 to /96"},
		"alias /97":         {func(m *geov1.CountryTable) { m.V6Aliases[16] = 97 }, "/1 to /96"},
		"alias host bits":   {func(m *geov1.CountryTable) { m.V6Aliases[17+15] = 1 }, "bits after"},
		"alias order":       {func(m *geov1.CountryTable) { m.V6Aliases = append(m.V6Aliases[17:34], m.V6Aliases[:17]...) }, "isn't after"},
		"alias overlap":     {func(m *geov1.CountryTable) { m.V6Aliases = table(t, nil, nil, "2001::/16", "2001:db8::/32").V6Aliases }, "isn't after"},
		"alias over ::/96":  {func(m *geov1.CountryTable) { m.V6Aliases = table(t, nil, nil, "::/64").V6Aliases }, "isn't after"},
		"alias in ::/96":    {func(m *geov1.CountryTable) { m.V6Aliases = table(t, nil, nil, "::1.0.0.0/96").V6Aliases }, "bits after"},
		"database type":     {func(m *geov1.CountryTable) { m.DatabaseType = strings.Repeat("x", MaxDatabaseType+1) }, "database type"},
		"database hash":     {func(m *geov1.CountryTable) { m.DatabaseSha256 = []byte{1} }, "database hash"},
		"too many aliases":  {func(m *geov1.CountryTable) { m.V6Aliases = make([]byte, 17*(MaxAliases+1)) }, "at most"},
		"too many v4 range": {func(m *geov1.CountryTable) { grow(m, MaxRangeBytes/6+1, 1) }, "over"},
		"too many v6 range": {func(m *geov1.CountryTable) { grow(m, 1, MaxRangeBytes/18) }, "over"},
	} {
		m := good()
		c.edit(m)
		err := Check(m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
		if _, err2 := FromProto(m); err2 == nil {
			t.Errorf("%s: FromProto took it", name)
		}
	}
	// At the bound exactly.
	m := good()
	grow(m, MaxRangeBytes/6-2*3, 1)
	if err := Check(m); err != nil {
		t.Errorf("at the bound: %v", err)
	}
}

// grow gives m n4 IPv4 and n6 IPv6 ranges, distinct and increasing.
func grow(m *geov1.CountryTable, n4, n6 int) {
	m.V4Starts = make([]uint32, n4)
	for i := range m.V4Starts {
		m.V4Starts[i] = uint32(i)
	}
	m.V4Codes = make([]byte, 2*n4)
	m.V6Starts = make([]byte, 16*n6)
	for i := range n6 {
		binary.BigEndian.PutUint64(m.V6Starts[16*i:], uint64(i))
	}
	m.V6Codes = make([]byte, 2*n6)
}

func encode(t testing.TB, m *geov1.CountryTable) ([]byte, [32]byte, uint64) {
	t.Helper()
	gz, size, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return gz, Hash(gz), uint64(size)
}

func TestEncodeDecode(t *testing.T) {
	m := table(t, []r4{{"0.0.0.0", ""}, {"1.0.0.0", "AU"}}, []r6{{"::", ""}, {"2001:db8::", "DE"}}, maxmindAliases...)
	m.DatabaseSha256 = make([]byte, 32)
	gz, h, size := encode(t, m)
	gz2, _, _ := encode(t, proto.Clone(m).(*geov1.CountryTable))
	if !bytes.Equal(gz, gz2) {
		t.Error("the same table encodes to different bytes")
	}
	tb, err := Decode(gz, h[:], size)
	if err != nil {
		t.Fatal(err)
	}
	if tb.Hash() != h || tb.DatabaseType() != "Test-Country" || tb.Built().Unix() != 1_700_000_000 || tb.Ranges() != 4 || tb.Bytes() <= 0 {
		t.Errorf("metadata: %x %q %v %d %d", tb.Hash(), tb.DatabaseType(), tb.Built(), tb.Ranges(), tb.Bytes())
	}
	if c, _ := tb.Lookup(netip.MustParseAddr("2001:db8::1")); c.String() != "DE" {
		t.Errorf("Lookup: %v", c)
	}
	if _, _, err := Encode(&geov1.CountryTable{}); err == nil {
		t.Error("Encode took an empty table")
	}
}

func TestDecodeRefuses(t *testing.T) {
	m := table(t, []r4{{"0.0.0.0", "AU"}}, []r6{{"::", ""}})
	gz, h, size := encode(t, m)
	gzipOf := func(b []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(b)
		_ = zw.Close()
		return buf.Bytes()
	}
	notGzip := []byte("not gzip at all")
	hNot := Hash(notGzip)
	raw, _ := proto.Marshal(&geov1.CountryTable{V4Starts: []uint32{1}, V4Codes: []byte{0, 0}, V6Starts: make([]byte, 16), V6Codes: []byte{0, 0}})
	bad := gzipOf(raw)
	hBad := Hash(bad)
	twice := append(append([]byte{}, gz...), gz...)
	hTwice := Hash(twice)
	corrupt := append([]byte{}, gz...)
	corrupt[len(corrupt)-5] ^= 0xff // the CRC
	hCorrupt := Hash(corrupt)
	for name, c := range map[string]struct {
		gz, hash []byte
		size     uint64
		want     string
	}{
		"wrong hash":         {gz, make([]byte, 32), size, "don't match"},
		"short hash":         {gz, h[:16], size, "don't match"},
		"hash before gzip":   {notGzip, make([]byte, 32), size, "don't match"},
		"not gzip":           {notGzip, hNot[:], size, "gzip"},
		"size zero":          {gz, h[:], 0, "want 1 to"},
		"size over bound":    {gz, h[:], MaxTableBytes + 1, "want 1 to"},
		"size short":         {gz, h[:], size - 1, "longer than"},
		"size long":          {gz, h[:], size + 1, "shorter than"},
		"bad table":          {bad, hBad[:], uint64(len(raw)), "0.0.0.0"},
		"two streams":        {twice, hTwice[:], size, "after the gzip"},
		"corrupt trailer":    {corrupt, hCorrupt[:], size, "checksum"},
		"too large":          {make([]byte, MaxCompressedBytes+1), nil, size, "compressed"},
		"not a CountryTable": {gzipOf([]byte{0xff}), nil, 1, "don't match"},
	} {
		_, err := Decode(c.gz, c.hash, c.size)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
	if _, err := Decode(gz, make([]byte, 32), size); !errors.Is(err, ErrHash) {
		t.Errorf("wrong hash: %v, want ErrHash", err)
	}
	if _, err := Unmarshal(make([]byte, MaxTableBytes+1)); err == nil {
		t.Error("Unmarshal took a table over the bound")
	}
}

// TestDecompressionBound: a small gzip that expands far past its size is
// read only through the size the bundle names.
func TestDecompressionBound(t *testing.T) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(make([]byte, 64<<20))
	_ = zw.Close()
	bomb := buf.Bytes()
	h := Hash(bomb)
	if _, err := Decode(bomb, h[:], 1024); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("bomb: %v", err)
	}
}

func TestCountry(t *testing.T) {
	for _, s := range []string{"", "D", "de", "DEU", "D1", "@A", "[A"} {
		if _, ok := ParseCountry(s); ok {
			t.Errorf("ParseCountry(%q) took it", s)
		}
	}
	c, ok := ParseCountry("DE")
	if !ok || c != 'D'<<8|'E' || c.String() != "DE" {
		t.Errorf("DE: %v %v", c, ok)
	}
	if NoCountry.String() != "" {
		t.Error("no country has a name")
	}
	var s Set
	for _, cc := range []string{"AA", "DE", "ZZ", "ZW", "DE"} {
		c, _ := ParseCountry(cc)
		s.Add(c)
	}
	s.Add(NoCountry)
	s.Add(Country(0x4100))
	if s.Len() != 4 {
		t.Errorf("Len %d, want 4", s.Len())
	}
	for _, cc := range []string{"AA", "DE", "ZZ", "ZW"} {
		if c, _ := ParseCountry(cc); !s.Has(c) {
			t.Errorf("Has(%s) false", cc)
		}
	}
	for _, c := range []Country{NoCountry, 'D'<<8 | 'F', 'A'<<8 | 'B', 0x4100, 0xffff} {
		if s.Has(c) {
			t.Errorf("Has(%#x) true", uint16(c))
		}
	}
	// Every code has its own bit.
	var all Set
	for a := byte('A'); a <= 'Z'; a++ {
		for b := byte('A'); b <= 'Z'; b++ {
			all.Add(Country(a)<<8 | Country(b))
		}
	}
	if all.Len() != 676 {
		t.Errorf("all: %d", all.Len())
	}
	for _, r := range []Result{ResultCountry, ResultPrivate, ResultUnknown, ResultNoTable, Result(9)} {
		if r.String() == "" {
			t.Errorf("%d has no name", r)
		}
	}
}
