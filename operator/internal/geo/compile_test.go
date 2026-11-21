// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	geotable "github.com/inkwall-dev/inkwall/pkg/geo"
)

func nw(prefix string, r *mmdbtest.Record) mmdbtest.Network {
	return mmdbtest.Network{Prefix: netip.MustParsePrefix(prefix), Record: r}
}

func cc(code string) *mmdbtest.Record { return &mmdbtest.Record{Country: code} }

// sampleDB is an IPv6 database as the vendors write them: MaxMind's
// aliases, a registered country, ZZ, lower case, a bad code, a record with
// only a continent.
func sampleDB(t testing.TB, aliases ...netip.Prefix) []byte {
	t.Helper()
	db, err := mmdbtest.DB{
		Type:       "Test-Country",
		BuildEpoch: 1_700_000_000,
		Networks: []mmdbtest.Network{
			nw("1.0.0.0/24", cc("AU")),
			nw("1.0.1.0/24", cc("CN")),
			nw("1.0.2.0/23", cc("CN")),
			nw("8.8.8.0/24", &mmdbtest.Record{Registered: "US"}),
			nw("9.0.0.0/8", cc("ZZ")),
			nw("10.0.0.0/8", cc("de")),
			nw("11.0.0.0/8", cc("D1")),
			nw("12.0.0.0/8", &mmdbtest.Record{Continent: "EU"}),
			nw("13.0.0.0/8", &mmdbtest.Record{Country: "FR", Registered: "DE"}),
			nw("192.0.2.0/24", cc("XA")),
			nw("2001:db8::/32", cc("DE")),
			nw("2a00::/12", cc("FR")),
			nw("2a10::/12", cc("FR")),
		},
		Aliases: aliases,
	}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func compileOK(t testing.TB, db []byte) (*Table, *geotable.Table) {
	t.Helper()
	tb, err := Compile(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := geotable.Decode(tb.Compressed, tb.Hash[:], uint64(tb.Size))
	if err != nil {
		t.Fatalf("the engine refuses the table: %v", err)
	}
	return tb, g
}

func TestCompile(t *testing.T) {
	for _, aliases := range [][]netip.Prefix{nil, mmdbtest.MaxMindAliases} {
		tb, g := compileOK(t, sampleDB(t, aliases...))
		if !slices.Equal(tb.Aliases, aliases) {
			t.Errorf("aliases %v, want %v", tb.Aliases, aliases)
		}
		if tb.DatabaseType != "Test-Country" || tb.BuildEpoch != 1_700_000_000 || tb.BadCodes != 1 {
			t.Errorf("metadata: %q %d, %d bad codes", tb.DatabaseType, tb.BuildEpoch, tb.BadCodes)
		}
		for addr, want := range map[string]string{
			"0.0.0.1":         "",
			"1.0.0.7":         "AU",
			"1.0.1.7":         "CN",
			"1.0.3.255":       "CN",
			"1.0.4.0":         "",
			"8.8.8.8":         "US", // registered_country
			"9.9.9.9":         "",   // ZZ
			"10.1.1.1":        "DE", // lower case folded
			"11.1.1.1":        "",   // a bad code
			"12.1.1.1":        "",   // a continent only
			"13.1.1.1":        "FR", // country over registered
			"192.0.2.1":       "XA",
			"255.255.255.255": "",
			"2001:db8::1":     "DE",
			"2a00::1":         "FR",
			"2a1f:ffff::":     "FR",
			"2a20::":          "",
			"::ffff:1.0.0.1":  "AU",
			"::1.0.1.1":       "CN",
		} {
			if got, _ := g.Lookup(netip.MustParseAddr(addr)); got.String() != want {
				t.Errorf("aliases %v: %s is %q, want %q", aliases, addr, got, want)
			}
		}
		// 6to4 and Teredo of 192.0.2.1 through the IPv4 table, only with
		// the aliases.
		want := ""
		if aliases != nil {
			want = "XA"
		}
		for _, a := range []string{"2002:c000:201::1", "2001:0:c000:201::"} {
			if got, _ := g.Lookup(netip.MustParseAddr(a)); got.String() != want {
				t.Errorf("aliases %v: %s is %q, want %q", aliases, a, got, want)
			}
		}
		// Merged: AU, CN (two networks), then the gaps.
		if tb.Ranges > 30 {
			t.Errorf("%d ranges: neighbours not merged", tb.Ranges)
		}
	}
}

func TestCompileDeterministic(t *testing.T) {
	db := sampleDB(t, mmdbtest.MaxMindAliases...)
	a, _ := compileOK(t, db)
	b, _ := compileOK(t, bytes.Clone(db))
	if !bytes.Equal(a.Compressed, b.Compressed) || a.Hash != b.Hash || a.Size != b.Size {
		t.Error("the same database compiles to different tables")
	}
	// The one hash: the gzipped bytes', as the Secrets' manifest has it.
	m, _, err := bundlesecret.Geo.Split("a", a.Compressed)
	if err != nil {
		t.Fatal(err)
	}
	if h := geotable.Hash(a.Compressed); h != a.Hash || m.SHA256 != hexOf(h[:]) {
		t.Error("the table hash isn't the SHA-256 of the gzipped table")
	}
	if geotable.MaxCompressedBytes != bundlesecret.Geo.MaxBytes() {
		t.Errorf("the engine bounds the table at %d bytes, the Secrets at %d", geotable.MaxCompressedBytes, bundlesecret.Geo.MaxBytes())
	}
}

// TestCompileCityLike: many networks with the same country merge into a
// table no larger than the country edition's.
func TestCompileMerges(t *testing.T) {
	var city, country []mmdbtest.Network
	for i := range 64 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(i), 0, 0}), 16)
		city = append(city, mmdbtest.Network{Prefix: p, Record: &mmdbtest.Record{Country: "DE", Continent: string(rune('A' + i%26))}})
	}
	country = append(country, nw("20.0.0.0/10", cc("DE")))
	a, _ := Compile(context.Background(), must(mmdbtest.DB{Networks: city}.Bytes()), nil)
	b, _ := Compile(context.Background(), must(mmdbtest.DB{Networks: country}.Bytes()), nil)
	if a == nil || b == nil || a.Ranges != b.Ranges {
		t.Fatalf("city edition %v, country edition %v", a, b)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestCompileAliases(t *testing.T) {
	for name, aliases := range map[string][]string{
		"one":      {"2002::/16"},
		"others":   {"3000::/4", "fc00::/96"},
		"siblings": {"4000::/3", "6000::/3"},
		"deep":     {"5000:1:2:3:4:5::/96"},
		"shallow":  {"8000::/1"},
	} {
		var ps []netip.Prefix
		for _, a := range aliases {
			ps = append(ps, netip.MustParsePrefix(a))
		}
		tb, g := compileOK(t, sampleDB(t, ps...))
		if !slices.Equal(tb.Aliases, ps) {
			t.Errorf("%s: aliases %v, want %v", name, tb.Aliases, ps)
		}
		for _, p := range ps {
			// The address with 192.0.2.1 right after the prefix.
			b := p.Addr().As16()
			v4 := [4]byte{192, 0, 2, 1}
			for k := range 32 {
				bit := p.Bits() + k
				if v4[k/8]>>(7-k%8)&1 == 1 {
					b[bit/8] |= 1 << (7 - bit%8)
				}
			}
			if got, _ := g.Lookup(netip.AddrFrom16(b)); got.String() != "XA" {
				t.Errorf("%s: %s is %q, want XA", name, netip.AddrFrom16(b), got)
			}
		}
	}
}

func TestCompileIPv4(t *testing.T) {
	db := must(mmdbtest.DB{IPVersion: 4, Networks: []mmdbtest.Network{nw("1.0.0.0/24", cc("AU")), nw("128.0.0.0/1", cc("US"))}}.Bytes())
	_, g := compileOK(t, db)
	for addr, want := range map[string]string{"1.0.0.1": "AU", "200.1.1.1": "US", "2.0.0.0": "", "::200.1.1.1": "US", "2001:db8::": ""} {
		if got, _ := g.Lookup(netip.MustParseAddr(addr)); got.String() != want {
			t.Errorf("%s is %q, want %q", addr, got, want)
		}
	}
}

func TestCompileRefuses(t *testing.T) {
	ctx := context.Background()
	noCountry := must(mmdbtest.DB{Networks: []mmdbtest.Network{nw("1.0.0.0/8", &mmdbtest.Record{Registered: "US"}), nw("2.0.0.0/8", &mmdbtest.Record{Continent: "EU"})}}.Bytes())
	for name, c := range map[string]struct {
		db     []byte
		reason string
	}{
		"empty":          {nil, ReasonInvalid},
		"garbage":        {[]byte("not a database at all"), ReasonInvalid},
		"no country":     {noCountry, ReasonNoCountryData},
		"flipped tree":   {mmdbtest.Flip(sampleDB(t), 3, 4, 5), ReasonInvalid},
		"bad node count": {mmdbtest.Tree{Nodes: [][2]uint32{{1, 1}}, NodeCount: 1 << 20}.Bytes(), ReasonInvalid},
		"pointer out":    {mmdbtest.Tree{Nodes: [][2]uint32{{1 << 20, 1}}}.Bytes(), ReasonInvalid},
	} {
		_, err := Compile(ctx, c.db, nil)
		if err == nil || ReasonOf(err) != c.reason {
			t.Errorf("%s: %v (%s), want %s", name, err, ReasonOf(err), c.reason)
		}
	}
}

// TestCompileHostile: trees whose nodes share children, Verify accepts
// them, yield exponentially many networks; the cap stops the walk, empty
// leaves or not, and so does the deadline.
func TestCompileHostile(t *testing.T) {
	defer func(n int, d time.Duration) { maxNetworks, timeout = n, d }(maxNetworks, timeout)
	maxNetworks = 100_000
	for _, withData := range []bool{false, true} {
		_, err := Compile(context.Background(), mmdbtest.SharedChildren(64, withData), nil)
		if ReasonOf(err) != ReasonTooLarge || !strings.Contains(err.Error(), "networks") {
			t.Errorf("data %v: %v, want too many networks", withData, err)
		}
	}
	// Shared children that end in aliases: a walk that skips aliases
	// would skip 2^100 of them without yielding once. The guard counts
	// them: refused past MaxAliases, at once.
	start := time.Now()
	_, err := Compile(context.Background(), mmdbtest.SharedAliases(100), nil)
	if ReasonOf(err) != ReasonInvalid || !strings.Contains(err.Error(), "alias") {
		t.Errorf("shared aliases: %v, want too many aliases", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("shared aliases took %v", d)
	}
	maxNetworks, timeout = MaxNetworks, 50*time.Millisecond
	start = time.Now()
	_, err = Compile(context.Background(), mmdbtest.SharedChildren(120, false), nil)
	if ReasonOf(err) != ReasonInvalid || !strings.Contains(err.Error(), "took more than") {
		t.Errorf("deadline: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the deadline took %v to stop the walk", d)
	}
}

func TestCompileTableBound(t *testing.T) {
	defer func(n int) { maxRangeBytes = n }(maxRangeBytes)
	maxRangeBytes = 6 * 10
	var nets []mmdbtest.Network
	for i := range 20 {
		nets = append(nets, mmdbtest.Network{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i * 2), 0, 0, 0}), 8), Record: cc("AU")})
	}
	_, err := Compile(context.Background(), must(mmdbtest.DB{Networks: nets}.Bytes()), nil)
	if ReasonOf(err) != ReasonTooLarge {
		t.Errorf("%v, want TooLarge", err)
	}
}

func TestCompileOlder(t *testing.T) {
	stored, _ := compileOK(t, sampleDB(t))
	older := must(mmdbtest.DB{BuildEpoch: stored.BuildEpoch - 1, Networks: []mmdbtest.Network{nw("1.0.0.0/8", cc("AU"))}}.Bytes())
	if _, err := Compile(context.Background(), older, stored); !errors.Is(err, ErrOlder) {
		t.Errorf("older: %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
