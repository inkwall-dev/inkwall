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

func TestResolveHopsPortsAndForwarded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   Options
		peer   string
		header http.Header
		want   string
	}{
		// Ports, as some load balancers append them.
		{"ipv4 with a port", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"198.51.100.7:4711"}}, "198.51.100.7"},
		{"ipv6 with a port", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"[2001:db8::1]:4711"}}, "2001:db8::1"},
		{"bracketed ipv6", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"[2001:db8::1]"}}, "2001:db8::1"},
		{"trusted proxy with a port is skipped", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 10.9.9.9:80"}}, "198.51.100.7"},
		{"bad port stops the walk", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 10.9.9.9:http"}}, "10.1.2.3"},
		// Hops: the load balancer's address isn't fixed.
		{"one hop", Options{TrustedProxies: []string{"127.0.0.1"}, TrustedHops: 1}, "127.0.0.1",
			http.Header{"X-Forwarded-For": {"6.6.6.6, 198.51.100.7, 172.16.5.4"}}, "198.51.100.7"},
		{"two hops", Options{TrustedProxies: []string{"127.0.0.1"}, TrustedHops: 2}, "127.0.0.1",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 172.16.5.4", "172.16.9.9"}}, "198.51.100.7"},
		{"hops, then CIDRs", Options{TrustedProxies: []string{"127.0.0.1", "10.0.0.0/8"}, TrustedHops: 1}, "127.0.0.1",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 10.1.1.1, 172.16.5.4"}}, "198.51.100.7"},
		{"more hops than entries", Options{TrustedProxies: []string{"127.0.0.1"}, TrustedHops: 3}, "127.0.0.1",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 172.16.5.4"}}, "198.51.100.7"},
		{"hops need a trusted peer", Options{TrustedHops: 1}, "203.0.113.9",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 172.16.5.4"}}, "203.0.113.9"},
		// Forwarded (RFC 7239).
		{"forwarded", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {`for=6.6.6.6, for=198.51.100.7;proto=https, For="10.9.9.9:80"`}}, "198.51.100.7"},
		{"forwarded ipv6", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {`for="[2001:db8::1]:4711";by=10.1.2.3`}}, "2001:db8::1"},
		{"forwarded lines", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {"for=198.51.100.7", "for=10.9.9.9"}}, "198.51.100.7"},
		{"forwarded unknown stops the walk", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {"for=198.51.100.7, for=unknown, for=10.9.9.9"}}, "10.9.9.9"},
		{"forwarded without for stops the walk", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {"for=198.51.100.7, proto=https"}}, "10.1.2.3"},
		{"forwarded quoted comma", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"Forwarded": {`for=198.51.100.7;x="a,b"`}}, "198.51.100.7"},
		{"forwarded ignores x-forwarded-for", Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded}, "10.1.2.3",
			http.Header{"X-Forwarded-For": {"198.51.100.7"}}, "10.1.2.3"},
		{"x-forwarded-for ignores forwarded", Options{TrustedProxies: []string{"10.0.0.0/8"}}, "10.1.2.3",
			http.Header{"Forwarded": {"for=198.51.100.7"}}, "10.1.2.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := r.Resolve(netip.MustParseAddr(tc.peer), tc.header); got != netip.MustParseAddr(tc.want) {
				t.Errorf("Resolve() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	for _, o := range []Options{
		{TrustedHops: -1},
		{TrustedHops: MaxTrustedHops + 1},
		{Header: "X-Real-IP"},
		{TrustedProxies: []string{"10.0.0.0/8, 10.1.0.0/16"}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("New(%+v) succeeded, want error", o)
		}
	}
	if _, err := New(Options{Header: "forwarded"}); err != nil {
		t.Errorf("header names are case-insensitive: %v", err)
	}
}
