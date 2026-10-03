// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package clientip resolves the real client address of a request that may
// have passed through load balancers or proxies.
//
// A WAF that keys rate limits and IP lists on the wrong address is worse than
// none, so forwarding headers are only trusted when the request arrives from a
// configured trusted proxy, and X-Forwarded-For is walked right to left.
package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver resolves client IPs. The zero value trusts no proxies and always
// returns the peer address.
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver returns a Resolver that trusts forwarding headers set by peers
// in the given CIDR prefixes (for example the cloud load balancer ranges).
// Plain addresses are accepted and treated as single-host prefixes.
func NewResolver(trustedProxies []string) (*Resolver, error) {
	r := &Resolver{}
	for _, s := range trustedProxies {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
			}
			addr = addr.Unmap()
			r.trusted = append(r.trusted, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
		}
		r.trusted = append(r.trusted, p.Masked())
	}
	return r, nil
}

// Resolve returns the client address for a request received from peer.
//
// If peer is not a trusted proxy, peer is the client. Otherwise the
// X-Forwarded-For chain is walked from right to left, skipping trusted
// proxies; the first untrusted address is the client. If every hop is
// trusted, the leftmost valid address is returned. A malformed entry stops the
// walk, and the last valid address seen is returned.
//
// The Forwarded header (RFC 7239) is not consulted yet.
func (r *Resolver) Resolve(peer netip.Addr, h http.Header) netip.Addr {
	peer = peer.Unmap()
	if !r.isTrusted(peer) {
		return peer
	}

	client := peer
	values := h.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		hops := strings.Split(values[i], ",")
		for j := len(hops) - 1; j >= 0; j-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(hops[j]))
			if err != nil {
				return client
			}
			client = addr.Unmap()
			if !r.isTrusted(client) {
				return client
			}
		}
	}
	return client
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	if r == nil {
		return false
	}
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
