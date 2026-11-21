// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"encoding/binary"
	"net/netip"

	geotable "github.com/inkwall-dev/inkwall/pkg/geo"
)

// ranges4 builds the IPv4 table from the walk's networks, in order, merging
// neighbours with the same country.
type ranges4 struct {
	starts []uint32
	codes  []byte
	// next is the first address not covered yet; 1<<32 when all are.
	next uint64
}

func (r *ranges4) full() bool { return r.next == 1<<32 }

func (r *ranges4) bytes() int { return 6 * len(r.starts) }

func (r *ranges4) add(p netip.Prefix, code geotable.Country) error {
	p = p.Masked()
	lo := uint64(binary.BigEndian.Uint32(p.Addr().AsSlice()))
	hi := lo + 1<<(32-p.Bits()) - 1
	if lo != r.next {
		return fail(ReasonInvalid, "IPv4 network %s out of order, after %s", p, uint32Addr(r.next))
	}
	r.next = hi + 1
	if n := len(r.codes); n > 0 && geotable.Country(r.codes[n-2])<<8|geotable.Country(r.codes[n-1]) == code {
		return nil
	}
	r.starts = append(r.starts, uint32(lo)) // #nosec G115 -- lo < 1<<32
	r.codes = append(r.codes, byte(code>>8), byte(code&0xff))
	return nil
}

// ranges6 builds the IPv6 table, which starts with ::/96 and its IPv4
// addresses: the IPv4 table holds those, the IPv6 one only a range at ::.
type ranges6 struct {
	starts []byte
	codes  []byte
	next   u128
	done   bool
}

func (r *ranges6) init() {
	r.starts = make([]byte, 16)
	r.codes = []byte{0, 0}
	r.next = u128{0, 1 << 32}
}

func (r *ranges6) full() bool { return r.done }

func (r *ranges6) bytes() int { return 18 * (len(r.starts) / 16) }

// add adds lo to hi, which starts at r.next.
func (r *ranges6) add(lo, hi u128, code geotable.Country) error {
	if r.done || lo != r.next {
		return fail(ReasonInvalid, "IPv6 network %s out of order", lo.addr())
	}
	next, ok := hi.next()
	r.next, r.done = next, !ok
	if n := len(r.codes); geotable.Country(r.codes[n-2])<<8|geotable.Country(r.codes[n-1]) == code {
		return nil
	}
	r.starts = binary.BigEndian.AppendUint64(r.starts, lo.hi)
	r.starts = binary.BigEndian.AppendUint64(r.starts, lo.lo)
	r.codes = append(r.codes, byte(code>>8), byte(code&0xff))
	return nil
}

type u128 struct{ hi, lo uint64 }

type span6 struct{ lo, hi u128 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

func (a u128) next() (u128, bool) {
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, true
	}
	if a.hi != ^uint64(0) {
		return u128{a.hi + 1, 0}, true
	}
	return u128{}, false
}

func (a u128) prev() (u128, bool) {
	if a.lo != 0 {
		return u128{a.hi, a.lo - 1}, true
	}
	if a.hi != 0 {
		return u128{a.hi - 1, ^uint64(0)}, true
	}
	return u128{}, false
}

func (a u128) addr() netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:], a.hi)
	binary.BigEndian.PutUint64(b[8:], a.lo)
	return netip.AddrFrom16(b)
}

func u128Of(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// prefixSpan returns the first and the last address of an IPv6 prefix.
func prefixSpan(p netip.Prefix) (u128, u128) {
	p = p.Masked()
	lo := u128Of(p.Addr())
	hi := lo
	host := 128 - p.Bits()
	switch {
	case host >= 64:
		hi.lo = ^uint64(0)
		if host == 128 {
			hi.hi = ^uint64(0)
		} else {
			hi.hi |= 1<<(host-64) - 1
		}
	case host > 0:
		hi.lo |= 1<<host - 1
	}
	return lo, hi
}
