// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

// Country is a two-letter country code, (c1 << 8) | c2 with each letter
// 'A' to 'Z': DE is 'D'<<8 | 'E'. The zero Country is no country.
type Country uint16

// NoCountry is the Country of an address the table has no country for.
const NoCountry Country = 0

// unknownCode is ZZ, which some databases use for "unknown or
// unspecified": a table holding it means no country (design 0011 §2.2).
const unknownCode Country = 'Z'<<8 | 'Z'

// ParseCountry returns the Country of s, two upper-case ASCII letters, and
// whether s is one. Lower case is refused rather than folded, as the CRD
// refuses it.
func ParseCountry(s string) (Country, bool) {
	if len(s) != 2 || !letter(s[0]) || !letter(s[1]) {
		return NoCountry, false
	}
	return Country(s[0])<<8 | Country(s[1]), true
}

func letter(c byte) bool { return 'A' <= c && c <= 'Z' }

// letters returns c's two bytes.
func (c Country) letters() (byte, byte) {
	return byte(c >> 8), byte(c & 0xff) // #nosec G115 -- the low byte
}

// valid reports whether c is two letters.
func (c Country) valid() bool {
	a, b := c.letters()
	return letter(a) && letter(b)
}

// String returns the two letters of c, "" for no country.
func (c Country) String() string {
	if !c.valid() {
		return ""
	}
	a, b := c.letters()
	return string([]byte{a, b})
}

// Set is a set of countries: a bit for each of the 26 × 26 two-letter
// codes, 88 bytes, so a policy's deny or allow list is one bit test. The
// zero Set is empty.
type Set struct{ w [11]uint64 }

func index(c Country) (int, bool) {
	if !c.valid() {
		return 0, false
	}
	a, b := c.letters()
	return int(a-'A')*26 + int(b-'A'), true
}

// Add adds c to s. No country is never added.
func (s *Set) Add(c Country) {
	if i, ok := index(c); ok {
		s.w[i/64] |= 1 << (i % 64)
	}
}

// Has reports whether c is in s. No country is in no Set.
func (s *Set) Has(c Country) bool {
	i, ok := index(c)
	return ok && s.w[i/64]&(1<<(i%64)) != 0
}

// Len is the number of countries in s.
func (s *Set) Len() int {
	n := 0
	for _, w := range s.w {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}
