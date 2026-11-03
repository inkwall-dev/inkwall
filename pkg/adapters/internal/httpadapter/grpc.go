// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
)

// GRPCProtocol is the gRPC variant a request asks for by its Content-Type,
// and so how a denial is answered.
type GRPCProtocol uint8

const (
	// NotGRPC is any other request: denied with a plain HTTP answer.
	NotGRPC GRPCProtocol = iota
	// GRPC is gRPC over HTTP/2: application/grpc, with any codec.
	GRPC
	// GRPCWeb is gRPC-Web: application/grpc-web, with any codec.
	GRPCWeb
	// GRPCWebText is gRPC-Web in base64: application/grpc-web-text.
	GRPCWebText
)

func (p GRPCProtocol) String() string {
	switch p {
	case GRPC:
		return "grpc"
	case GRPCWeb:
		return "grpc-web"
	case GRPCWebText:
		return "grpc-web-text"
	default:
		return "none"
	}
}

// ContentType is the media type of a denial's answer: the protocol's,
// without a codec (a trailers-only answer carries no message).
func (p GRPCProtocol) ContentType() string {
	switch p {
	case GRPCWeb:
		return "application/grpc-web"
	case GRPCWebText:
		return "application/grpc-web-text"
	default:
		return "application/grpc"
	}
}

// GRPCOf returns the gRPC variant a request with headers h asks for: by
// its one Content-Type, as Envoy tells a gRPC request (application/grpc,
// alone or with a "+codec" suffix). Unlike the pipeline's test of a gRPC
// call, the body doesn't matter: this only chooses the form of an answer
// the client can read.
func GRPCOf(h http.Header) GRPCProtocol {
	ct := h.Values("Content-Type")
	if len(ct) != 1 {
		return NotGRPC
	}
	mediaType, _, _ := strings.Cut(ct[0], ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	for _, v := range []struct {
		prefix string
		proto  GRPCProtocol
	}{
		{"application/grpc-web-text", GRPCWebText},
		{"application/grpc-web", GRPCWeb},
		{"application/grpc", GRPC},
	} {
		if rest, ok := strings.CutPrefix(mediaType, v.prefix); ok && (rest == "" || rest[0] == '+') {
			return v.proto
		}
	}
	return NotGRPC
}

// GRPCCode is the gRPC status of a denial with HTTP status code: gRPC's
// own mapping of HTTP statuses (doc/http-grpc-status-mapping.md), which
// clients apply to an HTTP answer, so a client sees the same code through
// every proxy; and RESOURCE_EXHAUSTED for an oversized body (413), which
// that mapping leaves UNKNOWN.
func GRPCCode(code int) codes.Code {
	switch code {
	case http.StatusBadRequest:
		return codes.Internal
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.Unimplemented
	case http.StatusRequestEntityTooLarge:
		return codes.ResourceExhausted
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return codes.Unavailable
	default:
		return codes.Unknown
	}
}

// GRPCMessage is the grpc-message of a denial with HTTP status code: the
// status text, as the body of an HTTP denial, and the request ID, which a
// gRPC client usually logs with the status. It is percent-encoded, as the
// gRPC spec says.
func GRPCMessage(code int, id string) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Denied"
	}
	return percentEncode(text + " (request ID " + id + ")")
}

// percentEncode encodes the bytes of s outside 0x20-0x7E, and '%'.
func percentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// WriteGRPCDenial answers a denied gRPC call in the trailers-only form:
// the gRPC status in the headers, no message. httpStatus is the HTTP
// status: 200, as a gRPC server answers, unless the proxy needs another to
// deny (forward-auth); gRPC clients read the gRPC status either way. code
// is the verdict's HTTP status, which gives the gRPC status.
func WriteGRPCDenial(w http.ResponseWriter, p GRPCProtocol, httpStatus, code int, id string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", p.ContentType())
	h.Set("Grpc-Status", strconv.Itoa(int(GRPCCode(code))))
	h.Set("Grpc-Message", GRPCMessage(code, id))
	h.Set("X-Request-Id", id)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(httpStatus)
}
