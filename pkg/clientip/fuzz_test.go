// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package clientip

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// FuzzResolve walks arbitrary X-Forwarded-For values. A peer that isn't a
// trusted proxy is the client whatever the header says; otherwise the
// client is the peer or an address of the header, never a trusted proxy
// while an untrusted address follows it.
func FuzzResolve(f *testing.F) {
	r, err := NewResolver([]string{"10.0.0.0/8", "192.0.2.1"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, peer, xff1, xff2 string) {
		p, err := netip.ParseAddr(peer)
		if err != nil {
			return
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
		var hops []netip.Addr
	walk:
		for i := len(h.Values("X-Forwarded-For")) - 1; i >= 0; i-- {
			parts := strings.Split(h.Values("X-Forwarded-For")[i], ",")
			for j := len(parts) - 1; j >= 0; j-- {
				a, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
				if err != nil {
					break walk
				}
				hops = append(hops, a.Unmap())
			}
		}
		want := p.Unmap()
		for _, a := range hops {
			want = a
			if !r.Trusts(a) {
				break
			}
		}
		if got != want {
			t.Errorf("peer %v, X-Forwarded-For %q: client %v, want %v", p, h.Values("X-Forwarded-For"), got, want)
		}
	})
}
