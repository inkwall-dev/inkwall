// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package geo looks a client's country up in a country table (design 0011
// §5.1): the sorted IP ranges, each with a country code, that the operator
// compiles a country database (MMDB) into and sends to engines
// (inkwall.geo.v1.CountryTable).
//
// A Table holds the ranges in pointer-free slices, one per family, so the
// garbage collector never scans them, and an index on the top 16 bits of
// the address narrows the binary search to a few steps: a lookup takes
// well under 150 ns at the bound of 32 MiB, with no allocation. A Table is
// checked completely when it is loaded (Check), and trusted after: a bad
// table can only give a wrong country, never a crash.
package geo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
)

// Bounds of a table (design 0011 §4.2).
const (
	// MaxRangeBytes bounds the ranges: 6 bytes per IPv4 range (a start and
	// a code) and 18 per IPv6 range. 5.5 million IPv4 ranges, or 1.8
	// million IPv6 ranges, or any mix in between.
	MaxRangeBytes = 32 << 20
	// MaxAliases bounds the IPv6 prefixes that alias the IPv4 table.
	// MaxMind's databases have three.
	MaxAliases = 256
	// MaxDatabaseType bounds the database type, in bytes.
	MaxDatabaseType = 256
	// MaxTableBytes bounds a serialized CountryTable: the ranges and their
	// framing (field tags, lengths, the metadata, the aliases).
	MaxTableBytes = MaxRangeBytes + 64<<10
	// MaxCompressedBytes bounds the gzipped table, as it is sent and
	// stored: 16 Secrets of 900 KiB (pkg/bundlesecret).
	MaxCompressedBytes = 16 * 900 << 10
)

// Result is what a lookup found.
type Result uint8

// Results of a lookup (design 0011 §2.2).
const (
	// ResultCountry: the table maps the address to a country.
	ResultCountry Result = iota
	// ResultPrivate: no country, and the address is loopback, link-local,
	// private (RFC 1918, RFC 4193), shared (RFC 6598, CGNAT) or
	// unspecified, or there is no valid address at all. Geo never denies
	// it.
	ResultPrivate
	// ResultUnknown: no country for a public address.
	ResultUnknown
	// ResultNoTable: there is no table to look in.
	ResultNoTable
)

// String returns the result as the metrics label it (design 0011 §8).
func (r Result) String() string {
	switch r {
	case ResultCountry:
		return "country"
	case ResultPrivate:
		return "private"
	case ResultUnknown:
		return "unknown"
	case ResultNoTable:
		return "no-table"
	}
	return "invalid"
}

// ErrHash is returned when a table's bytes don't match the hash that names
// them.
var ErrHash = errors.New("country table: the bytes don't match the table hash")

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

// shl is a << n, for n < 128.
func (a u128) shl(n uint) u128 {
	switch {
	case n == 0:
		return a
	case n >= 64:
		return u128{a.lo << (n - 64), 0}
	}
	return u128{a.hi<<n | a.lo>>(64-n), a.lo << n}
}

func u128From(b []byte) u128 {
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:16])}
}

// indexBits is the width of the index on the top bits of an address. The
// IPv6 index grows to maxIndexBits6 for a large table: allocated IPv6
// ranges sit under 2000::/3, so its top 16 bits leave only 8,192 buckets,
// and at the bound of 1.8 million ranges a bucket's search would miss the
// cache at each step. The index stays under a quarter of the starts.
const (
	indexBits     = 16
	maxIndexBits6 = 20
)

// alias is an IPv6 prefix whose addresses are looked up in the IPv4 table
// by the 32 bits after the prefix.
type alias struct {
	lo, hi u128
	bits   uint8
}

// v4alias is ::/96, the IPv4 tree of an IPv6 database: always an alias.
var v4alias = alias{u128{}, u128{0, 1<<32 - 1}, 96}

// Table is a checked country table. It is immutable and safe for
// concurrent use. The nil Table holds no countries (ResultNoTable).
type Table struct {
	v4   []uint32 // range starts, strictly increasing, v4[0] == 0
	v4c  []byte   // two bytes per range: its Country, 0 for none
	v6hi []uint64 // the IPv6 starts' high and low halves, apart: the
	v6lo []uint64 // search reads only the high ones, but for a tie
	v6c  []byte
	idx4 []uint32 // idx4[h]: the range holding h << 16; idx4[1<<16]: the last
	idx6 []uint32 // idx6[h]: the range holding h << (128 - bits6)
	// shift6 is 64 - the IPv6 index's width.
	shift6 uint
	// aliases, sorted and disjoint, ::/96 first.
	aliases []alias

	hash         [sha256.Size]byte
	databaseType string
	buildEpoch   uint64
}

// Hash returns the table hash: the SHA-256 of the gzipped table, as
// Decode checked it. Zero for a Table made by FromProto.
func (t *Table) Hash() [sha256.Size]byte { return t.hash }

// DatabaseType is the type of the database the table was compiled from,
// e.g. GeoLite2-Country.
func (t *Table) DatabaseType() string { return t.databaseType }

// Built is when the database was built.
func (t *Table) Built() time.Time {
	return time.Unix(int64(min(t.buildEpoch, 1<<62)), 0).UTC() // #nosec G115 -- capped
}

// Ranges is the number of ranges, IPv4 and IPv6.
func (t *Table) Ranges() int { return len(t.v4) + len(t.v6hi) }

// Bytes is the table's size in memory: its ranges and their index.
func (t *Table) Bytes() int {
	return len(t.v4)*4 + len(t.v4c) + len(t.v6hi)*16 + len(t.v6c) + (len(t.idx4)+len(t.idx6))*4 + len(t.aliases)*40
}

// Hash returns the table hash of a gzipped table: its SHA-256.
func Hash(compressed []byte) [sha256.Size]byte { return sha256.Sum256(compressed) }

// Encode checks m and returns it serialized and gzipped, as it is sent and
// stored, and its serialized size (what a bundle's GeoTableRef names). The
// same m gives the same bytes, so the same database gives the same table
// hash.
func Encode(m *geov1.CountryTable) (compressed []byte, size int, err error) {
	if err := Check(m); err != nil {
		return nil, 0, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, 0, fmt.Errorf("country table: %w", err)
	}
	if len(raw) > MaxTableBytes {
		return nil, 0, fmt.Errorf("country table: %d bytes, at most %d", len(raw), MaxTableBytes)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(raw)
	if err := zw.Close(); err != nil {
		return nil, 0, fmt.Errorf("country table: %w", err)
	}
	if buf.Len() > MaxCompressedBytes {
		return nil, 0, fmt.Errorf("country table: %d bytes compressed, at most %d", buf.Len(), MaxCompressedBytes)
	}
	return buf.Bytes(), len(raw), nil
}

// Decode loads a gzipped table: it checks the bytes against hash, the
// table hash a signed bundle names, before it decompresses them, then
// decompresses through size, the serialized size the bundle names, and
// checks the table.
func Decode(compressed, hash []byte, size uint64) (*Table, error) {
	if len(compressed) > MaxCompressedBytes {
		return nil, fmt.Errorf("country table: %d bytes compressed, at most %d", len(compressed), MaxCompressedBytes)
	}
	sum := Hash(compressed)
	if len(hash) != sha256.Size || !bytes.Equal(sum[:], hash) {
		return nil, ErrHash
	}
	if size == 0 || size > MaxTableBytes {
		return nil, fmt.Errorf("country table: size %d, want 1 to %d", size, MaxTableBytes)
	}
	br := bytes.NewReader(compressed)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("country table: %w", err)
	}
	zr.Multistream(false)
	raw := make([]byte, size)
	if _, err := io.ReadFull(zr, raw); err != nil {
		return nil, fmt.Errorf("country table: shorter than its size %d: %w", size, err)
	}
	// Reading past the end checks the gzip trailer, and that there is no
	// more than size.
	var one [1]byte
	switch _, err := io.ReadAtLeast(zr, one[:], 1); {
	case err == nil:
		return nil, fmt.Errorf("country table: longer than its size %d", size)
	case !errors.Is(err, io.EOF):
		return nil, fmt.Errorf("country table: %w", err)
	case br.Len() != 0:
		return nil, errors.New("country table: data after the gzip stream")
	}
	t, err := Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	t.hash = sum
	return t, nil
}

// Unmarshal loads a serialized, uncompressed table and checks it.
func Unmarshal(raw []byte) (*Table, error) {
	if len(raw) > MaxTableBytes {
		return nil, fmt.Errorf("country table: %d bytes, at most %d", len(raw), MaxTableBytes)
	}
	var m geov1.CountryTable
	if err := proto.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("country table: %w", err)
	}
	return FromProto(&m)
}

// FromProto checks m and returns its Table. The Table keeps m's slices:
// m must not change after.
func FromProto(m *geov1.CountryTable) (*Table, error) {
	if err := Check(m); err != nil {
		return nil, err
	}
	t := &Table{
		v4:           m.GetV4Starts(),
		v4c:          m.GetV4Codes(),
		v6c:          m.GetV6Codes(),
		databaseType: m.GetDatabaseType(),
		buildEpoch:   m.GetDatabaseBuildEpoch(),
	}
	noUnknown(t.v4c)
	noUnknown(t.v6c)
	s6 := m.GetV6Starts()
	t.v6hi = make([]uint64, len(s6)/16)
	t.v6lo = make([]uint64, len(s6)/16)
	for i := range t.v6hi {
		t.v6hi[i] = binary.BigEndian.Uint64(s6[16*i:])
		t.v6lo[i] = binary.BigEndian.Uint64(s6[16*i+8:])
	}
	t.aliases = append(t.aliases, v4alias)
	a := m.GetV6Aliases()
	for i := 0; i < len(a); i += 17 {
		t.aliases = append(t.aliases, aliasOf(u128From(a[i:]), a[i+16]))
	}
	t.idx4 = make([]uint32, 1<<indexBits+1)
	i := 0
	for h := range 1 << indexBits {
		x := uint32(h) << (32 - indexBits)
		for i+1 < len(t.v4) && t.v4[i+1] <= x {
			i++
		}
		t.idx4[h] = uint32(i) // #nosec G115 -- bounded by MaxRangeBytes
	}
	t.idx4[1<<indexBits] = uint32(len(t.v4) - 1) // #nosec G115 -- bounded
	bits6 := uint(indexBits)
	for bits6 < maxIndexBits6 && 4<<(bits6+1) <= 16*len(t.v6hi)/4 {
		bits6++
	}
	t.shift6 = 64 - bits6
	t.idx6 = make([]uint32, 1<<bits6+1)
	i = 0
	for h := range 1 << bits6 {
		x := u128{uint64(h) << t.shift6, 0}
		for i+1 < len(t.v6hi) && !x.less(u128{t.v6hi[i+1], t.v6lo[i+1]}) {
			i++
		}
		t.idx6[h] = uint32(i) // #nosec G115 -- bounded
	}
	t.idx6[1<<bits6] = uint32(len(t.v6hi) - 1) // #nosec G115 -- bounded
	return t, nil
}

// noUnknown rewrites ZZ codes to no country.
func noUnknown(codes []byte) {
	for i := 0; i < len(codes); i += 2 {
		if codes[i] == 'Z' && codes[i+1] == 'Z' {
			codes[i], codes[i+1] = 0, 0
		}
	}
}

func aliasOf(lo u128, bits uint8) alias {
	host := 128 - uint(bits)
	hi := lo
	switch {
	case host >= 64:
		hi.lo = ^uint64(0)
		hi.hi |= 1<<(host-64) - 1
	default:
		hi.lo |= 1<<host - 1
	}
	return alias{lo, hi, bits}
}

// Check checks a table completely: the lengths match, the starts are
// strictly increasing from zero, the codes are two letters or none, the
// aliases are prefixes of /1 to /96 outside ::/96, sorted and disjoint,
// and the table is within the bounds.
func Check(m *geov1.CountryTable) error {
	s4, c4 := m.GetV4Starts(), m.GetV4Codes()
	s6, c6 := m.GetV6Starts(), m.GetV6Codes()
	if len(s6)%16 != 0 {
		return fmt.Errorf("country table: %d bytes of IPv6 starts, not a multiple of 16", len(s6))
	}
	n4, n6 := len(s4), len(s6)/16
	if n4 == 0 || n6 == 0 {
		return fmt.Errorf("country table: %d IPv4 and %d IPv6 ranges, want at least one of each", n4, n6)
	}
	if 6*n4+18*n6 > MaxRangeBytes {
		return fmt.Errorf("country table: %d IPv4 and %d IPv6 ranges, over %d bytes", n4, n6, MaxRangeBytes)
	}
	if len(c4) != 2*n4 || len(c6) != 2*n6 {
		return fmt.Errorf("country table: %d and %d bytes of codes for %d IPv4 and %d IPv6 ranges", len(c4), len(c6), n4, n6)
	}
	if s4[0] != 0 {
		return errors.New("country table: the first IPv4 range doesn't start at 0.0.0.0")
	}
	for i := 1; i < n4; i++ {
		if s4[i] <= s4[i-1] {
			return fmt.Errorf("country table: IPv4 range %d doesn't start after range %d", i, i-1)
		}
	}
	if (u128From(s6) != u128{}) {
		return errors.New("country table: the first IPv6 range doesn't start at address zero")
	}
	for i := 1; i < n6; i++ {
		if !u128From(s6[16*(i-1):]).less(u128From(s6[16*i:])) {
			return fmt.Errorf("country table: IPv6 range %d doesn't start after range %d", i, i-1)
		}
	}
	for _, c := range [][]byte{c4, c6} {
		for i := 0; i < len(c); i += 2 {
			if code := Country(c[i])<<8 | Country(c[i+1]); code != NoCountry && !code.valid() {
				return fmt.Errorf("country table: range %d has code %#04x, not two letters", i/2, uint16(code))
			}
		}
	}
	a := m.GetV6Aliases()
	if len(a)%17 != 0 || len(a)/17 > MaxAliases {
		return fmt.Errorf("country table: %d bytes of aliases, want a multiple of 17, at most %d aliases", len(a), MaxAliases)
	}
	prev := v4alias
	for i := 0; i < len(a); i += 17 {
		lo, bits := u128From(a[i:]), a[i+16]
		if bits < 1 || bits > 96 {
			return fmt.Errorf("country table: alias %d is a /%d, want /1 to /96", i/17, bits)
		}
		al := aliasOf(lo, bits)
		if al.lo != lo.mask(bits) {
			return fmt.Errorf("country table: alias %d has bits after its /%d", i/17, bits)
		}
		if !prev.hi.less(al.lo) {
			return fmt.Errorf("country table: alias %d isn't after alias %d and ::/96", i/17, i/17-1)
		}
		prev = al
	}
	if t := m.GetDatabaseType(); len(t) > MaxDatabaseType {
		return fmt.Errorf("country table: database type of %d bytes, at most %d", len(t), MaxDatabaseType)
	}
	if h := m.GetDatabaseSha256(); len(h) != 0 && len(h) != sha256.Size {
		return fmt.Errorf("country table: database hash of %d bytes, want %d", len(h), sha256.Size)
	}
	return nil
}

// mask is a with the bits after the first bits cleared.
func (a u128) mask(bits uint8) u128 {
	switch {
	case bits >= 128:
		return a
	case bits >= 64:
		return u128{a.hi, a.lo &^ (^uint64(0) >> (bits - 64))}
	}
	return u128{a.hi &^ (^uint64(0) >> bits), 0}
}

// Lookup returns a's country and what the lookup found. A country found
// always wins, even for a private address a custom database maps. An
// IPv4-mapped IPv6 address is its IPv4 address, and an address in ::/96 or
// in one of the table's aliases (MaxMind's ::ffff:0:0/96, 2001::/32 and
// 2002::/16) is looked up in the IPv4 table by the 32 bits after the
// prefix, as the database's own reader resolves it.
func (t *Table) Lookup(a netip.Addr) (Country, Result) {
	if !a.IsValid() {
		return NoCountry, ResultPrivate
	}
	if t == nil {
		return NoCountry, ResultNoTable
	}
	a = a.Unmap()
	var c Country
	if a.Is4() {
		c = t.lookup4(binary.BigEndian.Uint32(a.AsSlice()))
	} else {
		b := a.As16()
		c = t.lookup6(u128From(b[:]))
	}
	if c != NoCountry {
		return c, ResultCountry
	}
	if private(a) {
		return NoCountry, ResultPrivate
	}
	return NoCountry, ResultUnknown
}

func (t *Table) lookup4(x uint32) Country {
	h := x >> (32 - indexBits)
	lo, hi := int(t.idx4[h]), int(t.idx4[h+1])
	// The range holding x is in [lo, hi]: the last start ≤ x.
	for lo < hi {
		m := int(uint(lo+hi+1) >> 1)
		if t.v4[m] <= x {
			lo = m
		} else {
			hi = m - 1
		}
	}
	return Country(t.v4c[2*lo])<<8 | Country(t.v4c[2*lo+1])
}

func (t *Table) lookup6(x u128) Country {
	if x.hi == 0 && x.lo>>32 == 0 {
		return t.lookup4(uint32(x.lo)) // #nosec G115 -- x.lo < 1<<32
	}
	if len(t.aliases) > 1 {
		// The last alias starting at or before x may hold it.
		lo, hi := 0, len(t.aliases)-1
		for lo < hi {
			m := int(uint(lo+hi+1) >> 1)
			if !x.less(t.aliases[m].lo) {
				lo = m
			} else {
				hi = m - 1
			}
		}
		if al := t.aliases[lo]; !x.less(al.lo) && !al.hi.less(x) {
			return t.lookup4(uint32(x.shl(uint(al.bits)).hi >> 32))
		}
	}
	h := x.hi >> t.shift6
	lo, hi := int(t.idx6[h]), int(t.idx6[h+1])
	for lo < hi {
		m := int(uint(lo+hi+1) >> 1)
		if h := t.v6hi[m]; h < x.hi || h == x.hi && t.v6lo[m] <= x.lo {
			lo = m
		} else {
			hi = m - 1
		}
	}
	return Country(t.v6c[2*lo])<<8 | Country(t.v6c[2*lo+1])
}

// private reports whether a, unmapped, is an address geo never denies
// without a country: loopback, link-local, private (RFC 1918 and RFC 4193),
// shared (RFC 6598, 100.64.0.0/10) or unspecified.
func private(a netip.Addr) bool {
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate() || a.IsUnspecified() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		return b[0] == 100 && b[1]&0xc0 == 64
	}
	return false
}
