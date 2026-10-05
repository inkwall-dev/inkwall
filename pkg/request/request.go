// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package request defines the canonical HTTP request that every Inkwall
// adapter produces and the inspection pipeline consumes. Adapters translate
// proxy-native messages (ext_proc, SPOE, forward-auth, net/http, ...) into a
// Request, so detection code never depends on which proxy asked.
package request

import (
	"net/http"
	"net/netip"
)

// Request is an adapter-independent view of one HTTP request.
type Request struct {
	// ID correlates the request across proxy, engine and events. Empty means
	// the engine generates one.
	ID string

	// Proto is the protocol version, e.g. "HTTP/1.1" or "HTTP/2.0".
	Proto string
	// Method is the HTTP method.
	Method string
	// Scheme is "http" or "https" as seen by the proxy.
	Scheme string
	// Host is the request authority (Host header or :authority).
	Host string
	// RawURI is the path and query exactly as received, before any
	// normalization. Rules apply their own transformations.
	RawURI string

	// Headers holds request headers. The Host header is carried in Host.
	Headers http.Header

	// ClientIP is the end client's address, resolved through trusted proxies.
	ClientIP netip.Addr
	// PeerIP is the address of the direct TCP peer.
	PeerIP netip.Addr

	// Body holds the inspected prefix of the request body, at most the
	// configured inspection limit. It is nil when the body is not inspected.
	Body []byte
	// BodyTruncated reports that the body was longer than Body.
	BodyTruncated bool
}
