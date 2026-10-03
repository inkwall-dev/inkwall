// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package clientip

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestResolve(t *testing.T) {
	r, err := NewResolver([]string{"10.0.0.0/8", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		peer string
		xff  []string
		want string
	}{
		{name: "untrusted peer ignores header", peer: "203.0.113.9", xff: []string{"1.2.3.4"}, want: "203.0.113.9"},
		{name: "trusted peer without header", peer: "10.1.2.3", want: "10.1.2.3"},
		{name: "trusted peer single hop", peer: "10.1.2.3", xff: []string{"198.51.100.7"}, want: "198.51.100.7"},
		{name: "skips trusted hops right to left", peer: "10.1.2.3", xff: []string{"198.51.100.7, 10.9.9.9, 192.0.2.1"}, want: "198.51.100.7"},
		{name: "spoofed left entries are ignored", peer: "10.1.2.3", xff: []string{"6.6.6.6, 198.51.100.7"}, want: "198.51.100.7"},
		{name: "multiple header lines", peer: "10.1.2.3", xff: []string{"198.51.100.7", "10.9.9.9"}, want: "198.51.100.7"},
		{name: "all hops trusted returns leftmost", peer: "10.1.2.3", xff: []string{"10.5.5.5, 10.6.6.6"}, want: "10.5.5.5"},
		{name: "malformed entry stops the walk", peer: "10.1.2.3", xff: []string{"198.51.100.7, garbage, 10.6.6.6"}, want: "10.6.6.6"},
		{name: "ipv4-mapped ipv6 peer is unmapped", peer: "::ffff:10.1.2.3", xff: []string{"198.51.100.7"}, want: "198.51.100.7"},
		{name: "ipv6 client", peer: "10.1.2.3", xff: []string{"2001:db8::1"}, want: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tt.xff {
				h.Add("X-Forwarded-For", v)
			}
			got := r.Resolve(netip.MustParseAddr(tt.peer), h)
			if got != netip.MustParseAddr(tt.want) {
				t.Fatalf("Resolve() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestZeroResolverTrustsNothing(t *testing.T) {
	var r Resolver
	h := http.Header{"X-Forwarded-For": {"1.2.3.4"}}
	if got := r.Resolve(netip.MustParseAddr("10.0.0.1"), h); got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("Resolve() = %s, want peer", got)
	}
}

func TestNewResolverRejectsInvalid(t *testing.T) {
	for _, s := range []string{"not-an-ip", "10.0.0.0/33"} {
		if _, err := NewResolver([]string{s}); err == nil {
			t.Errorf("NewResolver(%q) succeeded, want error", s)
		}
	}
}
