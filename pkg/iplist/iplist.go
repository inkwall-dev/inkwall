// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package iplist matches client addresses against a set of CIDR prefixes:
// a policy's IP allow and deny lists (#358).
//
// A Set holds the prefixes as sorted, merged address ranges, one slice per
// family, so a lookup is a binary search: a few dozen comparisons at
// 10,000 prefixes, with no allocation.
package iplist

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Set is an immutable set of addresses. The nil Set is empty. It is safe
// for concurrent use.
type Set struct {
	v4 []span4
	v6 []span6
}

type span4 struct{ lo, hi uint32 }

type span6 struct{ lo, hi u128 }

type u128 struct{ hi, lo uint64 }

func (a u128) cmp(b u128) int {
	if c := cmp.Compare(a.hi, b.hi); c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

// next is a+1, and whether it didn't wrap.
func (a u128) next() (u128, bool) {
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, true
	}
	if a.hi != ^uint64(0) {
		return u128{a.hi + 1, 0}, true
	}
	return u128{}, false
}

func u128Of(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// MaxEntries bounds a Set, as the bundle and the CRD bound a policy's
// lists.
const MaxEntries = 100000

// Parse returns the set of the CIDR prefixes (10.0.0.0/8, 2001:db8::/32) or
// addresses in entries. An IPv4-mapped IPv6 prefix of at least /96 is its
// IPv4 prefix.
func Parse(entries []string) (*Set, error) {
	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("%d entries, more than %d", len(entries), MaxEntries)
	}
	s := &Set{}
	for _, e := range entries {
		p, err := parseEntry(e)
		if err != nil {
			return nil, err
		}
		if p.Addr().Is4() {
			lo := binary.BigEndian.Uint32(p.Addr().AsSlice())
			hi := lo | uint32(1<<(32-p.Bits())-1)
			if p.Bits() == 0 {
				hi = ^uint32(0)
			}
			s.v4 = append(s.v4, span4{lo, hi})
			continue
		}
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
		s.v6 = append(s.v6, span6{lo, hi})
	}
	s.v4 = merge4(s.v4)
	s.v6 = merge6(s.v6)
	return s, nil
}

// parseEntry parses one entry into a masked prefix, IPv4-mapped prefixes
// unmapped.
func parseEntry(e string) (netip.Prefix, error) {
	e = strings.TrimSpace(e)
	var p netip.Prefix
	if strings.Contains(e, "/") {
		var err error
		if p, err = netip.ParsePrefix(e); err != nil {
			return netip.Prefix{}, fmt.Errorf("IP list entry %q: %w", e, err)
		}
	} else {
		a, err := netip.ParseAddr(e)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("IP list entry %q: %w", e, err)
		}
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IP list entry %q: an address with a zone", e)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

func merge4(spans []span4) []span4 {
	slices.SortFunc(spans, func(a, b span4) int { return cmp.Compare(a.lo, b.lo) })
	var out []span4
	for _, sp := range spans {
		if n := len(out); n > 0 && (sp.lo <= out[n-1].hi || out[n-1].hi != ^uint32(0) && sp.lo == out[n-1].hi+1) {
			out[n-1].hi = max(out[n-1].hi, sp.hi)
			continue
		}
		out = append(out, sp)
	}
	return slices.Clip(out)
}

func merge6(spans []span6) []span6 {
	slices.SortFunc(spans, func(a, b span6) int { return a.lo.cmp(b.lo) })
	var out []span6
	for _, sp := range spans {
		if n := len(out); n > 0 {
			last := &out[n-1]
			next, ok := last.hi.next()
			if sp.lo.cmp(last.hi) <= 0 || ok && sp.lo == next {
				if sp.hi.cmp(last.hi) > 0 {
					last.hi = sp.hi
				}
				continue
			}
		}
		out = append(out, sp)
	}
	return slices.Clip(out)
}

// Contains reports whether a is in s. An IPv4-mapped IPv6 address is its
// IPv4 address; the zero Addr is in no set.
func (s *Set) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		x := binary.BigEndian.Uint32(a.AsSlice())
		// The first span starting after x; the one before it may hold x.
		i, _ := slices.BinarySearchFunc(s.v4, x, func(sp span4, x uint32) int {
			if sp.lo <= x {
				return -1
			}
			return 1
		})
		return i > 0 && x <= s.v4[i-1].hi
	}
	x := u128Of(a)
	i, _ := slices.BinarySearchFunc(s.v6, x, func(sp span6, x u128) int {
		if sp.lo.cmp(x) <= 0 {
			return -1
		}
		return 1
	})
	return i > 0 && x.cmp(s.v6[i-1].hi) <= 0
}

// Len is the number of address ranges s holds, after merging.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}
