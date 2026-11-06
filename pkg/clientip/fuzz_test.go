// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package clientip

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// FuzzResolve walks arbitrary X-Forwarded-For values, with and without
// trusted hops. A peer that isn't a trusted proxy is the client whatever the
// header says; otherwise the client is the peer or an address of the header:
// the first one from the right past the trusted hops that isn't a trusted
// proxy.
func FuzzResolve(f *testing.F) {
	f.Add("10.1.2.3", "198.51.100.7, 10.9.9.9:80", "[2001:db8::1]:4711", uint8(0))
	f.Add("127.0.0.1", "6.6.6.6, 198.51.100.7", "172.16.5.4", uint8(1))
	f.Fuzz(func(t *testing.T, peer, xff1, xff2 string, hops uint8) {
		p, err := netip.ParseAddr(peer)
		if err != nil {
			return
		}
		r, err := New(Options{TrustedProxies: []string{"10.0.0.0/8", "192.0.2.1", "127.0.0.1"}, TrustedHops: int(hops % 4)})
		if err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		for _, v := range []string{xff1, xff2} {
			if v != "" {
				h.Add("X-Forwarded-For", v)
			}
		}
		got := r.Resolve(p, h)
		if got.Is4In6() {
			t.Errorf("Resolve = %v, not unmapped", got)
		}
		if !r.Trusts(p) {
			if got != p.Unmap() {
				t.Errorf("untrusted peer %v: client %v", p, got)
			}
			return
		}
		// The hops, right to left, up to the first malformed one.
		var chain []netip.Addr
	walk:
		for i := len(h.Values("X-Forwarded-For")) - 1; i >= 0; i-- {
			parts := strings.Split(h.Values("X-Forwarded-For")[i], ",")
			for j := len(parts) - 1; j >= 0; j-- {
				a, ok := parseNode(parts[j])
				if !ok {
					break walk
				}
				chain = append(chain, a)
			}
		}
		want := p.Unmap()
		for i, a := range chain {
			want = a
			if i >= int(hops%4) && !r.Trusts(a) {
				break
			}
		}
		if got != want {
			t.Errorf("peer %v, X-Forwarded-For %q, hops %d: client %v, want %v", p, h.Values("X-Forwarded-For"), hops%4, got, want)
		}
	})
}

// FuzzResolveForwarded parses arbitrary Forwarded values: the client is the
// peer or one of the header's for= nodes, never a panic.
func FuzzResolveForwarded(f *testing.F) {
	f.Add(`for=6.6.6.6, for=198.51.100.7;proto=https, For="10.9.9.9:80"`)
	f.Add(`for="[2001:db8::1]:4711";by=10.1.2.3, for=unknown`)
	f.Add(`for="\"a,b\";x`)
	r, err := New(Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded})
	if err != nil {
		f.Fatal(err)
	}
	peer := netip.MustParseAddr("10.1.2.3")
	f.Fuzz(func(t *testing.T, v string) {
		got := r.Resolve(peer, http.Header{"Forwarded": {v}})
		if !got.IsValid() || got.Is4In6() {
			t.Fatalf("Forwarded %q: client %v", v, got)
		}
		if got == peer {
			return
		}
		found := false
		for _, n := range forwardedFor(v) {
			if a, ok := parseNode(n); ok && a == got {
				found = true
			}
		}
		if !found {
			t.Errorf("Forwarded %q: client %v is none of its nodes", v, got)
		}
	})
}
