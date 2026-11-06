// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package iplist

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestContains(t *testing.T) {
	s, err := Parse([]string{"10.0.0.0/8", "192.0.2.1", "198.51.100.0/24", "198.51.100.128/25", "2001:db8::/32", "::ffff:203.0.113.0/120", " 172.16.0.0/12 "})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true}, {"11.0.0.0", false}, {"9.255.255.255", false},
		{"192.0.2.1", true}, {"192.0.2.2", false},
		{"198.51.100.0", true}, {"198.51.100.255", true}, {"198.51.101.0", false},
		{"172.31.255.255", true}, {"172.32.0.0", false},
		{"2001:db8::1", true}, {"2001:db9::1", false},
		// IPv4-mapped addresses are their IPv4 address, and mapped prefixes
		// IPv4 prefixes.
		{"::ffff:10.0.0.1", true}, {"203.0.113.9", true}, {"::ffff:203.0.113.9", true},
		{"::1", false}, {"0.0.0.0", false},
	} {
		if got := s.Contains(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if s.Contains(netip.Addr{}) {
		t.Error("the zero address is in the set")
	}
	var empty *Set
	if empty.Contains(netip.MustParseAddr("10.0.0.1")) || empty.Len() != 0 {
		t.Error("a nil set contains something")
	}
	if s.Len() != 6 { // 198.51.100.128/25 is inside 198.51.100.0/24
		t.Errorf("Len = %d, want 6 ranges", s.Len())
	}
	all, err := Parse([]string{"0.0.0.0/0", "::/0"})
	if err != nil || !all.Contains(netip.MustParseAddr("255.255.255.255")) || !all.Contains(netip.MustParseAddr("ffff::1")) {
		t.Errorf("everything: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	for _, bad := range []string{"", "10.0.0.0/33", "10.0.0.0/8/8", "example.com", "10.0.0.1-10.0.0.9", "fe80::1%eth0"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

// naive is what Contains must agree with.
func naive(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func randomPrefixes(r *rand.Rand, n int) ([]string, []netip.Prefix) {
	var text []string
	var prefixes []netip.Prefix
	for range n {
		var p netip.Prefix
		if r.IntN(4) == 0 {
			var b [16]byte
			for i := range b {
				b[i] = byte(r.IntN(256))
			}
			p = netip.PrefixFrom(netip.AddrFrom16(b), 16+r.IntN(113)).Masked()
		} else {
			p = netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))}), 8+r.IntN(25)).Masked()
		}
		text = append(text, p.String())
		prefixes = append(prefixes, p)
	}
	return text, prefixes
}

func TestContainsAgreesWithPrefixes(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	text, prefixes := randomPrefixes(r, 2000)
	s, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	for range 20000 {
		var a netip.Addr
		if r.IntN(4) == 0 {
			var b [16]byte
			for i := range b {
				b[i] = byte(r.IntN(256))
			}
			a = netip.AddrFrom16(b)
		} else {
			a = netip.AddrFrom4([4]byte{byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
		}
		if got, want := s.Contains(a), naive(prefixes, a); got != want {
			t.Fatalf("Contains(%s) = %v, want %v", a, got, want)
		}
	}
}

// BenchmarkContains: the lookup at 10,000 prefixes must take well under
// 1 µs (#358).
func BenchmarkContains(b *testing.B) {
	r := rand.New(rand.NewPCG(3, 4))
	text, _ := randomPrefixes(r, 10000)
	s, err := Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	addrs := make([]netip.Addr, 1024)
	for i := range addrs {
		addrs[i] = netip.MustParseAddr(fmt.Sprintf("%d.%d.%d.%d", r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		s.Contains(addrs[i%len(addrs)])
		i++
	}
}

// FuzzParse: any list either fails to parse or gives a set that agrees
// with its prefixes.
func FuzzParse(f *testing.F) {
	f.Add("10.0.0.0/8", "192.0.2.1", "10.1.2.3")
	f.Add("2001:db8::/32", "::ffff:10.0.0.0/104", "::ffff:10.0.0.1")
	f.Add("0.0.0.0/0", "", "1.2.3.4")
	f.Fuzz(func(t *testing.T, a, b, addr string) {
		s, err := Parse([]string{a, b})
		if err != nil {
			return
		}
		x, err := netip.ParseAddr(addr)
		if err != nil || x.Zone() != "" {
			return
		}
		var prefixes []netip.Prefix
		for _, e := range []string{a, b} {
			p, err := parseEntry(e)
			if err != nil {
				t.Fatalf("Parse accepted %q, parseEntry refuses it: %v", e, err)
			}
			prefixes = append(prefixes, p)
		}
		if got, want := s.Contains(x), naive(prefixes, x); got != want {
			t.Errorf("%q, %q: Contains(%s) = %v, want %v", a, b, x, got, want)
		}
	})
}
