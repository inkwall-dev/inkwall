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
	"unicode/utf8"

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
	// MaxNetworks bounds the networks a walk yields: a tree whose nodes
	// share children yields exponentially many. A tree without shared
	// children yields one network per node, plus one (empty networks
	// included), and a file of MaxFileBytes holds at most 32 Mi nodes of
	// the smallest node a large database uses (8 bytes, 32-bit records): so
	// no database within the file bound is refused for its networks.
	// GeoLite2-City, the largest free one, has about 4 million nodes.
	MaxNetworks = MaxFileBytes / 8
	// Timeout bounds a compile.
	Timeout = time.Minute
	// maxCachedRecords bounds the records whose country is remembered by
	// offset.
	maxCachedRecords = 1 << 18
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

// ReasonOf returns the reason of err: its Error's. Other errors, such as
// the API server's or a cancelled context (leadership lost), have none:
// they are transient, and leave the condition as it is.
func ReasonOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ""
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

// ErrUnchanged is returned for the database the stored table was compiled
// from: it isn't compiled again.
var ErrUnchanged = errors.New("the database is the stored table's")

// Compile compiles the database db into a country table. db must not
// change while it runs; a mapped file truncated under it is a recovered
// fault, reported as Invalid: so db is read, hashed included, only in
// here. The database floor was compiled from isn't compiled again
// (ErrUnchanged), nor one whose build epoch is before floor's (ErrOlder).
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

// code is a record's country, and whether its code was bad.
type code struct {
	c   geotable.Country
	bad bool
}

type compiler struct {
	ctx      context.Context
	r        *maxminddb.Reader
	networks int
	v4       ranges4
	v6       ranges6
	// gaps in the IPv6 walk: the alias prefixes it skips.
	gaps    []span6
	codes   map[uintptr]code
	country int // records with country.iso_code
	bad     int // networks whose record's code isn't two letters
	firstV4 int // the bits of the first IPv4 network, -1 before it
	sawIPv4 bool
}

func compile(ctx context.Context, db []byte, floor *Table) (*Table, error) {
	if len(db) == 0 {
		return nil, fail(ReasonInvalid, "the database is empty")
	}
	sum := sha256.Sum256(db)
	if floor != nil && sum == floor.DatabaseSHA256 {
		return nil, ErrUnchanged
	}
	r, err := maxminddb.OpenBytes(db, maxminddb.DisableStringCache())
	if err != nil {
		return nil, fail(ReasonInvalid, "not a valid MaxMind DB: %v", err)
	}
	if floor != nil && uint64(r.Metadata.BuildEpoch) < floor.BuildEpoch {
		return nil, fmt.Errorf("%w: built %s, the stored table %s", ErrOlder,
			time.Unix(int64(min(r.Metadata.BuildEpoch, 1<<62)), 0).UTC().Format(time.RFC3339), floor.Built().Format(time.RFC3339)) // #nosec G115 -- capped
	}
	if err := checkMetadata(r.Metadata); err != nil {
		return nil, err
	}
	// No Verify: its memory grows with the database's distinct records
	// (about 85 bytes each at its peak, measured on v2.9.1), which nothing
	// here bounds, so a crafted file of a few million records would take
	// the leader's memory. The walks below check what matters as they go:
	// every tree record they follow is bounds-checked, every data record
	// decoded, under the deadline and the caps.
	c := &compiler{ctx: ctx, r: r, codes: map[uintptr]code{}, firstV4: -1}
	if err := c.walk(db); err != nil {
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

// checkMetadata checks what Verify would of the metadata, and that the tree
// can be walked within the cap: a tree without shared children has a
// network per node, plus one.
func checkMetadata(m maxminddb.Metadata) error {
	switch {
	case m.BinaryFormatMajorVersion != 2:
		return fail(ReasonInvalid, "not a valid MaxMind DB: binary format %d, want 2", m.BinaryFormatMajorVersion)
	case m.IPVersion != 4 && m.IPVersion != 6:
		return fail(ReasonInvalid, "not a valid MaxMind DB: IP version %d", m.IPVersion)
	case m.RecordSize != 24 && m.RecordSize != 28 && m.RecordSize != 32:
		return fail(ReasonInvalid, "not a valid MaxMind DB: record size %d", m.RecordSize)
	case m.NodeCount == 0:
		return fail(ReasonInvalid, "not a valid MaxMind DB: no nodes")
	case m.NodeCount >= uint(maxNetworks):
		return fail(ReasonTooLarge, "%d nodes in the search tree, more than %d networks", m.NodeCount, maxNetworks)
	case !utf8.ValidString(m.DatabaseType):
		return fail(ReasonInvalid, "not a valid MaxMind DB: the database type isn't UTF-8")
	}
	return nil
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

// walk walks every network, those without data included: without them an
// empty leaf yields nothing, and a tree whose shared children all end in
// empty leaves would keep the walk from ever coming back to check the
// deadline. The IPv4 aliases are skipped, and leave gaps.
//
// A skipped alias doesn't yield either, so a tree whose shared children end
// in aliases would make that walk as long, unchecked. So guard walks the
// search tree first, as the library's walk does, counting its path ends
// and its aliases, and refuses the tree past either cap: the walk then
// yields at most maxNetworks networks and skips at most MaxAliases.
func (c *compiler) walk(db []byte) error {
	if err := c.guard(db); err != nil {
		return err
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
		if err := c.addGap(span6{c.v6.next, u128{^uint64(0), ^uint64(0)}}); err != nil {
			return err
		}
	}
	return nil
}

// guard walks the search tree in db as the library's network walk does
// (maxminddb-golang v2.9.1, traverse.go), without decoding anything: each
// empty or data record ends a path, and so does an alias, a record that
// points to the IPv4 subtree from outside ::/96, where the walk that skips
// aliases stops. It refuses more than maxNetworks path ends (TooLarge) or
// more than MaxAliases aliases (Invalid), so a crafted tree of shared
// children is refused within a few steps per alias, not after the cap's
// worth of networks under them.
func (c *compiler) guard(db []byte) error {
	m := c.r.Metadata
	nodes := m.NodeCount
	nodeBytes := m.RecordSize / 4 // two records
	if uint64(len(db)) < uint64(nodes)*uint64(nodeBytes) {
		return fail(ReasonInvalid, "not a valid MaxMind DB: the search tree is cut short")
	}
	record := func(node uint, right bool) uint {
		b := db[node*nodeBytes : (node+1)*nodeBytes]
		switch m.RecordSize {
		case 24:
			if right {
				return uint(b[3])<<16 | uint(b[4])<<8 | uint(b[5])
			}
			return uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])
		case 28:
			if right {
				return uint(b[3]&0x0f)<<24 | uint(b[4])<<16 | uint(b[5])<<8 | uint(b[6])
			}
			return uint(b[3]&0xf0)<<20 | uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])
		default:
			if right {
				return uint(b[4])<<24 | uint(b[5])<<16 | uint(b[6])<<8 | uint(b[7])
			}
			return uint(b[0])<<24 | uint(b[1])<<16 | uint(b[2])<<8 | uint(b[3])
		}
	}
	// The IPv4 subtree: ::/96, as the library finds it. Pointing to it
	// from elsewhere is an alias, only in an IPv6 tree that has one.
	bits := uint(32)
	var v4 uint
	if m.IPVersion == 6 {
		bits = 128
		for i := 0; i < 96 && v4 < nodes; i++ {
			v4 = record(v4, false)
		}
	}
	aliasing := m.IPVersion == 6 && v4 != 0 && v4 < nodes
	type pending struct {
		node, bit uint
		// outside: a bit of the first 96 is set, the path leaves ::/96.
		outside bool
	}
	stack := []pending{{}}
	aliases := 0
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for {
			if aliasing && n.node == v4 && n.outside {
				if aliases++; aliases > geotable.MaxAliases {
					return fail(ReasonInvalid, "more than %d prefixes alias the IPv4 subtree", geotable.MaxAliases)
				}
				break
			}
			if n.node >= nodes {
				if err := c.step(); err != nil {
					return err
				}
				break
			}
			if n.bit >= bits {
				return fail(ReasonInvalid, "not a valid MaxMind DB: the search tree is deeper than %d bits", bits)
			}
			setsPrefix := bits == 128 && n.bit < 96
			stack = append(stack, pending{record(n.node, true), n.bit + 1, n.outside || setsPrefix})
			n = pending{record(n.node, false), n.bit + 1, n.outside}
		}
	}
	return nil
}

// addGap records a gap of the walk that skips aliases. Each gap holds one
// alias at least, so more than MaxAliases gaps fail the compile anyway:
// refused here, before a crafted tree of alternating aliases and empty
// leaves grows the list by a gap per network.
func (c *compiler) addGap(g span6) error {
	if len(c.gaps) >= geotable.MaxAliases {
		return fail(ReasonInvalid, "more than %d prefixes alias the IPv4 subtree", geotable.MaxAliases)
	}
	c.gaps = append(c.gaps, g)
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
		if err := c.addGap(span6{c.v6.next, prev}); err != nil {
			return err
		}
		c.v6.next = lo
	}
	if lo.less(c.v6.next) {
		lo = c.v6.next
	}
	return c.v6.add(lo, hi, code)
}

// code returns the country of a network's record: country.iso_code, else
// registered_country.iso_code; upper-cased; no country for ZZ or for a code
// that isn't two ASCII letters (counted per network).
func (c *compiler) code(res maxminddb.Result) (geotable.Country, error) {
	if !res.Found() {
		return geotable.NoCountry, nil
	}
	if k, ok := c.codes[res.Offset()]; ok {
		if k.bad {
			c.bad++
		}
		return k.c, nil
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
	k := code{}
	if s != "" {
		b := []byte(s)
		for i, ch := range b {
			if 'a' <= ch && ch <= 'z' {
				b[i] = ch - 'a' + 'A'
			}
		}
		var ok bool
		if k.c, ok = geotable.ParseCountry(string(b)); !ok {
			k.bad = true
			c.bad++
		} else if k.c.String() == "ZZ" {
			k.c = geotable.NoCountry
		}
	}
	if len(c.codes) < maxCachedRecords {
		c.codes[res.Offset()] = k
	}
	return k.c, nil
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
