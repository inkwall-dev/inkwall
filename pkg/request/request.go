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

	// GRPC reports that the pipeline found the request to be a gRPC call:
	// a POST with a gRPC content type whose body is gRPC messages. Its
	// body is binary protobuf, which text rules can't read: the pipeline
	// passes it to the rules without its body, and the rules allow its
	// content type.
	GRPC bool
}

// Response is an adapter-independent view of the upstream's response to a
// Request, for the policies that inspect responses.
type Response struct {
	// Status is the response's HTTP status code.
	Status int
	// Proto is the protocol version, as in Request.
	Proto string
	// Headers holds the response headers, without pseudo-headers.
	Headers http.Header

	// Body holds the inspected prefix of the response body, decoded when
	// it came gzip- or deflate-encoded: at most the configured limit. It
	// is nil when the body is not inspected.
	Body []byte
	// BodyTruncated reports that the body was longer than Body: only its
	// prefix was inspected.
	BodyTruncated bool
	// BodyUninspected reports that the body should have been inspected
	// but couldn't be: an encoding the engine can't decode, or a body the
	// proxy didn't send. Body is then nil.
	BodyUninspected bool
}
