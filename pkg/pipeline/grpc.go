// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"encoding/binary"
	"net/http"
	"strings"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// grpcContentTypes are the gRPC media types whose messages are binary
// protobuf: gRPC and gRPC-Web. gRPC with another codec (application/grpc+json)
// and gRPC-Web text (base64) are inspected like any other request.
var grpcContentTypes = map[string]bool{
	"application/grpc":           true,
	"application/grpc+proto":     true,
	"application/grpc-web":       true,
	"application/grpc-web+proto": true,
}

// grpcFrameHeader is a gRPC message's prefix: a compressed flag (0 or 1)
// and the message length, 4 bytes big-endian.
const grpcFrameHeader = 5

// asGRPC returns r as a gRPC call (request.Request.GRPC) without its body,
// or nil when r isn't one: not a POST, not exactly one gRPC content type,
// or a body that isn't gRPC messages. The body check keeps a request that
// only claims to be gRPC, to slip a JSON or form body past the rules, from
// being treated as one: such a body doesn't start with a message prefix.
// A truncated body is checked as far as it goes, but must show at least
// one message prefix.
func asGRPC(r *request.Request) *request.Request {
	if r.Method != http.MethodPost {
		return nil
	}
	ct := r.Headers.Values("Content-Type")
	if len(ct) != 1 {
		return nil
	}
	mediaType, _, _ := strings.Cut(ct[0], ";")
	if !grpcContentTypes[strings.ToLower(strings.TrimSpace(mediaType))] || !grpcFramed(r.Body, r.BodyTruncated) {
		return nil
	}
	call := *r
	call.Body = nil
	call.BodyTruncated = false
	call.GRPC = true
	return &call
}

// grpcFramed reports whether body is a sequence of gRPC messages. The last
// message of a truncated body may be cut.
func grpcFramed(body []byte, truncated bool) bool {
	if truncated && len(body) < grpcFrameHeader {
		return false
	}
	for len(body) > 0 {
		if len(body) < grpcFrameHeader {
			return truncated
		}
		if body[0] > 1 {
			return false
		}
		n := uint64(binary.BigEndian.Uint32(body[1:grpcFrameHeader]))
		body = body[grpcFrameHeader:]
		if n > uint64(len(body)) {
			return truncated
		}
		body = body[n:]
	}
	return true
}

// grpcTextLimits bound the reading of one call's messages: nesting, text
// fields, and the bytes gzip messages decompress to, in all.
var grpcTextLimits = grpcwire.Limits{Depth: 16, Fields: 4096}

const grpcMaxDecompressed = 1 << 20

// grpcText returns the text fields of r's messages, r being a gRPC call
// (asGRPC), and reports whether every message was read whole: not cut,
// not compressed other than with gzip (grpc-encoding), protobuf, and
// within the limits.
func grpcText(r *request.Request) ([]request.Arg, bool) {
	msgs, ok := grpcwire.Messages(r.Body, r.BodyTruncated)
	complete := ok && !r.BodyTruncated
	encoding := strings.ToLower(strings.TrimSpace(r.Headers.Get("Grpc-Encoding")))
	budget := int64(grpcMaxDecompressed)
	var fields []grpcwire.Field
	for _, m := range msgs {
		data := m.Data
		if m.Compressed {
			if encoding != "gzip" || m.Cut {
				complete = false
				continue
			}
			out, whole := grpcwire.Gunzip(data, budget)
			budget -= int64(len(out))
			if !whole {
				complete = false
			}
			data = out
		}
		var whole bool
		fields, whole = grpcwire.Strings(data, grpcTextLimits, fields)
		if !whole {
			complete = false
		}
	}
	if len(fields) == 0 {
		return nil, complete
	}
	args := make([]request.Arg, len(fields))
	for i, f := range fields {
		args[i] = request.Arg{Name: f.Name, Value: f.Value}
	}
	return args, complete
}
