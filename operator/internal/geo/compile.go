// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package geo compiles a country database (MMDB) into the country table
// engines enforce geo blocking with (design 0011 §4.2, §6), and stores the
// table in its Secrets (§4.4). Only the leader compiles; engines never parse
// an MMDB.
//
// The database is the cluster admin's own file, but it is parsed as
// untrusted: in a goroutine that recovers from a panic and from a fault of
// a mapped file truncated under the reader, under a deadline the walk checks
// at every network, with a cap on the networks and on the table. A crafted
// or corrupt file makes an Invalid or TooLarge condition, never a crashed or
// out-of-memory leader.
package geo

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
	geotable "github.com/inkwall-dev/inkwall/pkg/geo"
)

// Reasons of the InkwallConfig's GeoDatabaseReady condition (design 0011
// §7) that a compile decides.
const (
	ReasonLoaded        = "Loaded"
	ReasonNotFound      = "NotFound"
	ReasonInvalid       = "Invalid"
	ReasonNoCountryData = "NoCountryData"
	ReasonTooLarge      = "TooLarge"
)

// Limits of a compile (design 0011 §6).
const (
	// MaxFileBytes bounds a database file, mapped.
	MaxFileBytes = 256 << 20
	// MaxSecretBytes bounds a database from a Secret, decompressed.
	MaxSecretBytes = 16 << 20
	// MaxNetworks bounds the networks a walk yields, past any real
	// database: a tree whose nodes share children yields exponentially
	// many.
	MaxNetworks = 16_000_000
	// Timeout bounds a compile.
	Timeout = time.Minute
	// maxCachedRecords bounds the records whose country is remembered by
	// offset.
	maxCachedRecords = 1 << 20
)

// The limits a compile applies; tests lower them.
var (
	maxNetworks   = MaxNetworks
	timeout       = Timeout
	maxRangeBytes = geotable.MaxRangeBytes
)

// Error is a compile's failure, with the condition's reason.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

func fail(reason, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// ReasonOf returns the reason of err: its Error's, else Invalid.
func ReasonOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ReasonInvalid
}

// Table is a compiled country table.
type Table struct {
	// Compressed is the gzipped CountryTable, as it is sent and stored.
	Compressed []byte
	// Hash is the table hash: the SHA-256 of Compressed.
	Hash [sha256.Size]byte
	// Size is the serialized CountryTable's size, what a bundle's
	// GeoTableRef names.
	Size int
	// DatabaseType and BuildEpoch are the database's metadata.
	DatabaseType string
	BuildEpoch   uint64
	// DatabaseSHA256 is the hash of the source database.
	DatabaseSHA256 [sha256.Size]byte
	// Ranges counts the merged ranges, IPv4 and IPv6.
	Ranges int
	// Aliases are the IPv6 prefixes found to alias the IPv4 table.
	Aliases []netip.Prefix
	// BadCodes counts the records whose code wasn't two letters, made no
	// country.
	BadCodes int
}

// Built is when the database was built.
func (t *Table) Built() time.Time {
	return time.Unix(int64(min(t.BuildEpoch, 1<<62)), 0).UTC() // #nosec G115 -- capped
}

// ErrOlder is returned for a database built before the stored table's: it
// isn't compiled (design 0011 §4.2).
var ErrOlder = errors.New("the database is older than the stored table")

// Compile compiles the database db into a country table. db must not
// change while it runs; a mapped file truncated under it is a recovered
// fault, reported as Invalid. A database whose build epoch is before
// floor's isn't compiled: ErrOlder.
func Compile(ctx context.Context, db []byte, floor *Table) (*Table, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		t   *Table
		err error
	}
	done := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			if p := recover(); p != nil {
				res = result{err: fail(ReasonInvalid, "reading the database failed: %v", p)}
			}
			done <- res
		}()
		debug.SetPanicOnFault(true)
		res.t, res.err = compile(ctx, db, floor)
	}()
	res := <-done
	return res.t, res.err
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Registered struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type compiler struct {
	ctx      context.Context
	r        *maxminddb.Reader
	networks int
	v4       ranges4
	v6       ranges6
	// gaps in the IPv6 walk: the alias prefixes it skips.
	gaps    []span6
	codes   map[uintptr]geotable.Country
	country int // records with country.iso_code
	bad     int
	firstV4 int // the bits of the first IPv4 network, -1 before it
	sawIPv4 bool
}

func compile(ctx context.Context, db []byte, floor *Table) (*Table, error) {
	sum := sha256.Sum256(db)
	r, err := maxminddb.OpenBytes(db, maxminddb.DisableStringCache())
	if err != nil {
		return nil, fail(ReasonInvalid, "not a valid MaxMind DB: %v", err)
	}
	if floor != nil && uint64(r.Metadata.BuildEpoch) < floor.BuildEpoch {
		return nil, fmt.Errorf("%w: built %s, the stored table %s", ErrOlder,
			time.Unix(int64(min(r.Metadata.BuildEpoch, 1<<62)), 0).UTC().Format(time.RFC3339), floor.Built().Format(time.RFC3339)) // #nosec G115 -- capped
	}
	if err := r.Verify(); err != nil {
		return nil, fail(ReasonInvalid, "not a valid MaxMind DB: %v", err)
	}
	c := &compiler{ctx: ctx, r: r, codes: map[uintptr]geotable.Country{}, firstV4: -1}
	if err := c.walk(); err != nil {
		return nil, err
	}
	if c.country == 0 {
		return nil, fail(ReasonNoCountryData, "no record has country.iso_code: not a country database")
	}
	aliases, err := c.aliases()
	if err != nil {
		return nil, err
	}
	m := &geov1.CountryTable{
		V4Starts:           c.v4.starts,
		V4Codes:            c.v4.codes,
		V6Starts:           c.v6.starts,
		V6Codes:            c.v6.codes,
		DatabaseType:       r.Metadata.DatabaseType,
		DatabaseBuildEpoch: uint64(r.Metadata.BuildEpoch),
		DatabaseSha256:     sum[:],
	}
	for _, p := range aliases {
		a := p.Addr().As16()
		m.V6Aliases = append(m.V6Aliases, a[:]...)
		m.V6Aliases = append(m.V6Aliases, byte(p.Bits())) // #nosec G115 -- at most 96
	}
	if len(m.DatabaseType) > geotable.MaxDatabaseType {
		return nil, fail(ReasonInvalid, "database type of %d bytes, at most %d", len(m.DatabaseType), geotable.MaxDatabaseType)
	}
	gz, size, err := geotable.Encode(m)
	if err != nil {
		// The ranges are within their bound and checked as built: what is
		// left is the compressed size.
		return nil, fail(ReasonTooLarge, "%v", err)
	}
	return &Table{
		Compressed:     gz,
		Hash:           geotable.Hash(gz),
		Size:           size,
		DatabaseType:   m.DatabaseType,
		BuildEpoch:     m.DatabaseBuildEpoch,
		DatabaseSHA256: sum,
		Ranges:         len(c.v4.starts) + len(c.v6.starts)/16,
		Aliases:        aliases,
		BadCodes:       c.bad,
	}, nil
}

// step counts a network and checks the deadline and the cap.
func (c *compiler) step() error { return c.stepUpTo(maxNetworks) }

func (c *compiler) stepUpTo(limit int) error {
	c.networks++
	if c.networks > limit {
		return fail(ReasonTooLarge, "more than %d networks", limit)
	}
	if err := c.ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fail(ReasonInvalid, "reading the database took more than %v", timeout)
		}
		return err
	}
	return nil
}

// guardWalks bounds the walk that follows the aliases: the IPv4 networks
// once in their subtree and once under each of MaxMind's three aliases.
const guardWalks = 4

// walk walks every network, those without data included: without them an
// empty leaf yields nothing, and a tree whose shared children all end in
// empty leaves would keep the walk from ever coming back to check the
// deadline. The IPv4 aliases are skipped, and leave gaps.
//
// A skipped alias doesn't yield either, so a tree whose shared children end
// in aliases would make that walk as long, unchecked. So a first walk
// follows the aliases, where every path end yields: it is checked and
// capped, and the walk that skips them ends at no more path ends than it
// yielded.
func (c *compiler) walk() error {
	for res := range c.r.Networks(maxminddb.IncludeAliasedNetworks(), maxminddb.IncludeNetworksWithoutData()) {
		if err := c.stepUpTo(guardWalks * maxNetworks); err != nil {
			return err
		}
		if err := res.Err(); err != nil {
			return fail(ReasonInvalid, "reading the database: %v", err)
		}
	}
	c.networks = 0
	c.v6.init()
	for res := range c.r.Networks(maxminddb.IncludeNetworksWithoutData()) {
		if err := c.step(); err != nil {
			return err
		}
		if err := res.Err(); err != nil {
			return fail(ReasonInvalid, "reading the database: %v", err)
		}
		code, err := c.code(res)
		if err != nil {
			return err
		}
		p := res.Prefix()
		if p.Addr().Is4() {
			if c.firstV4 < 0 {
				c.firstV4 = p.Bits()
			}
			c.sawIPv4 = true
			if err := c.v4.add(p, code); err != nil {
				return err
			}
		} else {
			// A tree that ends above ::/96 maps all IPv4 to one record.
			if p.Contains(netip.IPv6Unspecified()) && p.Bits() < 96 {
				if err := c.v4.add(netip.PrefixFrom(netip.IPv4Unspecified(), 0), code); err != nil {
					return err
				}
				c.sawIPv4 = true
			}
			if err := c.add6(p, code); err != nil {
				return err
			}
		}
		if c.v4.bytes()+c.v6.bytes() > maxRangeBytes {
			return fail(ReasonTooLarge, "a table over %d KiB", maxRangeBytes>>10)
		}
	}
	if !c.v4.full() {
		if c.r.Metadata.IPVersion == 4 || c.sawIPv4 {
			return fail(ReasonInvalid, "the IPv4 networks stop at %s", uint32Addr(c.v4.next))
		}
		// No IPv4 subtree: an IPv6 database without one.
		if err := c.v4.add(netip.PrefixFrom(netip.IPv4Unspecified(), 0), geotable.NoCountry); err != nil {
			return err
		}
	}
	if c.r.Metadata.IPVersion == 6 && !c.v6.full() {
		c.gaps = append(c.gaps, span6{c.v6.next, u128{^uint64(0), ^uint64(0)}})
	}
	return nil
}

func (c *compiler) add6(p netip.Prefix, code geotable.Country) error {
	lo, hi := prefixSpan(p)
	if hi.less(c.v6.next) {
		// Inside ::/96, which the IPv4 table holds: a tree that ends above
		// ::/96 yields it here.
		return nil
	}
	if c.v6.next.less(lo) {
		prev, _ := lo.prev()
		c.gaps = append(c.gaps, span6{c.v6.next, prev})
		c.v6.next = lo
	}
	if lo.less(c.v6.next) {
		lo = c.v6.next
	}
	return c.v6.add(lo, hi, code)
}

// code returns the country of a network's record: country.iso_code, else
// registered_country.iso_code; upper-cased; no country for ZZ or for a code
// that isn't two ASCII letters (counted).
func (c *compiler) code(res maxminddb.Result) (geotable.Country, error) {
	if !res.Found() {
		return geotable.NoCountry, nil
	}
	if code, ok := c.codes[res.Offset()]; ok {
		return code, nil
	}
	var rec record
	if err := res.Decode(&rec); err != nil {
		return 0, fail(ReasonInvalid, "decoding the record of %s: %v", res.Prefix(), err)
	}
	s := rec.Country.ISOCode
	if s != "" {
		c.country++
	} else {
		s = rec.Registered.ISOCode
	}
	code := geotable.NoCountry
	if s != "" {
		b := []byte(s)
		for i, ch := range b {
			if 'a' <= ch && ch <= 'z' {
				b[i] = ch - 'a' + 'A'
			}
		}
		var ok bool
		if code, ok = geotable.ParseCountry(string(b)); !ok {
			c.bad++
		} else if code.String() == "ZZ" {
			code = geotable.NoCountry
		}
	}
	if len(c.codes) < maxCachedRecords {
		c.codes[res.Offset()] = code
	}
	return code, nil
}

// aliases finds the prefixes in the walk's gaps: each points to the IPv4
// subtree, so a walk that follows aliases, from the gap's start, first
// yields the IPv4 subtree's first network under it, firstV4 bits below the
// alias.
func (c *compiler) aliases() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, g := range c.gaps {
		if c.firstV4 < 1 {
			return nil, fail(ReasonInvalid, "networks missing at %s, and no IPv4 subtree for an alias", g.lo.addr())
		}
		cursor := g.lo
		for {
			block := largestBlock(cursor, g.hi)
			first, err := c.first(block)
			if err != nil {
				return nil, err
			}
			l := first.Bits() - c.firstV4
			if l < block.Bits() || l > 96 || !first.Addr().Is6() {
				return nil, fail(ReasonInvalid, "networks missing at %s, not an alias of the IPv4 subtree", block)
			}
			p := netip.PrefixFrom(cursor.addr(), l)
			if p.Masked() != p {
				return nil, fail(ReasonInvalid, "networks missing at %s, not an alias of the IPv4 subtree", block)
			}
			if out = append(out, p); len(out) > geotable.MaxAliases {
				return nil, fail(ReasonInvalid, "more than %d prefixes alias the IPv4 subtree", geotable.MaxAliases)
			}
			_, end := prefixSpan(p)
			next, ok := end.next()
			if !ok || g.hi.less(next) {
				break
			}
			cursor = next
		}
	}
	return out, nil
}

// first returns the prefix of the first network within block, aliases
// followed.
func (c *compiler) first(block netip.Prefix) (netip.Prefix, error) {
	for res := range c.r.NetworksWithin(block, maxminddb.IncludeAliasedNetworks(), maxminddb.IncludeNetworksWithoutData()) {
		if err := c.step(); err != nil {
			return netip.Prefix{}, err
		}
		if err := res.Err(); err != nil {
			return netip.Prefix{}, fail(ReasonInvalid, "reading the database at %s: %v", block, err)
		}
		return res.Prefix(), nil
	}
	return netip.Prefix{}, fail(ReasonInvalid, "no network within %s", block)
}

// largestBlock is the largest prefix starting at lo that ends at or before
// hi.
func largestBlock(lo, hi u128) netip.Prefix {
	for b := range 129 {
		p := netip.PrefixFrom(lo.addr(), b)
		if p.Masked().Addr() != lo.addr() {
			continue
		}
		if _, end := prefixSpan(p); !hi.less(end) {
			return p
		}
	}
	return netip.PrefixFrom(lo.addr(), 128)
}

func uint32Addr(x uint64) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}) // #nosec G115 -- the bytes of an IPv4 address
}
