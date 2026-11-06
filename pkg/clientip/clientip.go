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
	hops    int
	header  string // canonical: HeaderXForwardedFor or HeaderForwarded
}

// The headers a Resolver reads the forwarding chain from.
const (
	HeaderXForwardedFor = "X-Forwarded-For"
	// HeaderForwarded is RFC 7239's Forwarded, its for= parameters.
	HeaderForwarded = "Forwarded"
)

// MaxTrustedHops bounds Options.TrustedHops.
const MaxTrustedHops = 10

// Options configure a Resolver.
type Options struct {
	// TrustedProxies are CIDR prefixes (or plain addresses) of proxies whose
	// forwarding header is trusted.
	TrustedProxies []string
	// TrustedHops is how many entries of the forwarding header, from the
	// right, are proxies whatever their address (load balancers whose
	// addresses aren't fixed). It applies only to a request from a trusted
	// peer, before the address checks.
	TrustedHops int
	// Header is HeaderXForwardedFor (the default, "") or HeaderForwarded,
	// case-insensitively.
	Header string
}

// NewResolver returns a Resolver that trusts forwarding headers set by peers
// in the given CIDR prefixes (for example the cloud load balancer ranges).
// Plain addresses are accepted and treated as single-host prefixes.
func NewResolver(trustedProxies []string) (*Resolver, error) {
	return New(Options{TrustedProxies: trustedProxies})
}

// New returns a Resolver configured by o.
func New(o Options) (*Resolver, error) {
	r := &Resolver{hops: o.TrustedHops, header: HeaderXForwardedFor}
	if o.TrustedHops < 0 || o.TrustedHops > MaxTrustedHops {
		return nil, fmt.Errorf("trusted hops %d out of range 0-%d", o.TrustedHops, MaxTrustedHops)
	}
	switch {
	case o.Header == "" || strings.EqualFold(o.Header, HeaderXForwardedFor):
	case strings.EqualFold(o.Header, HeaderForwarded):
		r.header = HeaderForwarded
	default:
		return nil, fmt.Errorf("client IP header %q: want %s or %s", o.Header, HeaderXForwardedFor, HeaderForwarded)
	}
	for _, s := range o.TrustedProxies {
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
// forwarding chain (X-Forwarded-For, or Forwarded's for= parameters) is
// walked from right to left, skipping the first TrustedHops entries and
// then trusted proxies; the first other address is the client. If every
// hop is trusted, the leftmost valid address is returned. An entry may
// carry a port ("198.51.100.7:4711", "[2001:db8::1]:4711"). A malformed
// entry (or, in Forwarded, one without for= or with an obfuscated or
// "unknown" node) stops the walk, and the last valid address seen is
// returned.
func (r *Resolver) Resolve(peer netip.Addr, h http.Header) netip.Addr {
	peer = peer.Unmap()
	if !r.isTrusted(peer) {
		return peer
	}

	client := peer
	values := h.Values(r.header)
	n := 0
	for i := len(values) - 1; i >= 0; i-- {
		var hops []string
		if r.header == HeaderForwarded {
			hops = forwardedFor(values[i])
		} else {
			hops = strings.Split(values[i], ",")
		}
		for j := len(hops) - 1; j >= 0; j-- {
			addr, ok := parseNode(hops[j])
			if !ok {
				return client
			}
			client = addr
			if n < r.hops {
				n++
				continue
			}
			if !r.isTrusted(client) {
				return client
			}
		}
	}
	return client
}

// parseNode parses an address, with or without a port, IPv6 in brackets
// or not.
func parseNode(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if inner, ok := strings.CutPrefix(s, "["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			if addr, err := netip.ParseAddr(inner); err == nil && addr.Is6() {
				return addr.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

// forwardedFor returns the for= node of each element of a Forwarded header
// value, unquoted; "" for an element without one, which stops the walk.
// Commas and semicolons inside quoted strings don't split.
func forwardedFor(value string) []string {
	var nodes []string
	for _, element := range splitQuoted(value, ',') {
		node := ""
		for _, pair := range splitQuoted(element, ';') {
			k, v, ok := strings.Cut(pair, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "for") {
				node = unquote(strings.TrimSpace(v))
				break
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// splitQuoted splits s at sep outside quoted strings.
func splitQuoted(s string, sep byte) []string {
	var out []string
	quoted, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// unquote removes a quoted string's quotes and escapes.
func unquote(s string) string {
	inner, ok := strings.CutPrefix(s, `"`)
	if !ok {
		return s
	}
	inner, ok = strings.CutSuffix(inner, `"`)
	if !ok {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}

// Trusts reports whether addr is a trusted proxy, whose forwarding headers
// may be relied on and passed on.
func (r *Resolver) Trusts(addr netip.Addr) bool {
	return r.isTrusted(addr.Unmap())
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
