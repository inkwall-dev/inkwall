// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// grpcContentTypes are the gRPC media types whose messages are protobuf:
// gRPC, gRPC-Web, and gRPC-Web text, whose body is base64 (true). gRPC
// with another codec (application/grpc+json) is inspected like any other
// request.
var grpcContentTypes = map[string]bool{
	"application/grpc":                false,
	"application/grpc+proto":          false,
	"application/grpc-web":            false,
	"application/grpc-web+proto":      false,
	"application/grpc-web-text":       true,
	"application/grpc-web-text+proto": true,
}

// GRPCContentType reports whether r's content type is a gRPC or gRPC-Web
// one (application/grpc, application/grpc+json, application/grpc-web...),
// whatever its body: what DenyGRPC refuses.
func GRPCContentType(r *request.Request) bool {
	for _, ct := range r.Headers.Values("Content-Type") {
		mediaType, _, _ := strings.Cut(ct, ";")
		mediaType = strings.ToLower(strings.TrimSpace(mediaType))
		if mediaType == "application/grpc" || mediaType == "application/grpc-web" ||
			strings.HasPrefix(mediaType, "application/grpc+") || strings.HasPrefix(mediaType, "application/grpc-web+") ||
			strings.HasPrefix(mediaType, "application/grpc-web-text") {
			return true
		}
	}
	return false
}

// grpcFrameHeader is a gRPC message's prefix: a compressed flag (0 or 1)
// and the message length, 4 bytes big-endian.
const grpcFrameHeader = 5

// asGRPC returns r as a gRPC call (request.Request.GRPC) without its body,
// and the body's gRPC messages (gRPC-Web text decoded), or nil when r
// isn't one: not a POST, not exactly one gRPC content type, or a body that
// isn't gRPC messages. The body check keeps a request that only claims to
// be gRPC, to slip a JSON or form body past the rules, from being treated
// as one: such a body doesn't start with a message prefix, or, for
// gRPC-Web text, isn't base64. A truncated body is checked as far as it
// goes, but must show at least one message prefix.
func asGRPC(r *request.Request) (*request.Request, []byte) {
	if r.Method != http.MethodPost {
		return nil, nil
	}
	ct := r.Headers.Values("Content-Type")
	if len(ct) != 1 {
		return nil, nil
	}
	mediaType, _, _ := strings.Cut(ct[0], ";")
	text, ok := grpcContentTypes[strings.ToLower(strings.TrimSpace(mediaType))]
	if !ok {
		return nil, nil
	}
	messages := r.Body
	if text {
		if messages, ok = grpcWebText(r.Body, r.BodyTruncated); !ok {
			return nil, nil
		}
	}
	if !grpcFramed(messages, r.BodyTruncated) {
		return nil, nil
	}
	call := *r
	call.Body = nil
	call.BodyTruncated = false
	call.GRPC = true
	return &call, messages
}

// grpcWebText decodes a gRPC-Web text body: base64 in groups of four
// characters, each piece the client encoded on its own ending with its
// padding. A truncated body is decoded up to its last whole group.
func grpcWebText(body []byte, truncated bool) ([]byte, bool) {
	if truncated {
		body = body[:len(body)/4*4]
	} else if len(body)%4 != 0 {
		return nil, false
	}
	// The decoder skips line breaks, which would shift the groups.
	if bytes.ContainsAny(body, "\r\n") {
		return nil, false
	}
	out := make([]byte, 0, len(body)/4*3)
	var group [3]byte
	for i := 0; i < len(body); i += 4 {
		n, err := base64.StdEncoding.Decode(group[:], body[i:i+4])
		if err != nil {
			return nil, false
		}
		out = append(out, group[:n]...)
	}
	return out, true
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

// grpcText returns the text fields of messages, the gRPC messages of r
// (asGRPC), and reports whether every message was read whole: not cut,
// not compressed other than with gzip (grpc-encoding), protobuf, and
// within the limits.
func grpcText(r *request.Request, messages []byte) ([]request.Arg, bool) {
	msgs, ok := grpcwire.Messages(messages, r.BodyTruncated)
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
