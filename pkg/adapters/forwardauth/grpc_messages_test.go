// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// TestGRPCMessages: with the policy's grpcMessages, a gRPC client behind
// (a fake) Traefik that sends an attack in its message, not its metadata,
// gets PERMISSION_DENIED; without, the call reaches the upstream.
func TestGRPCMessages(t *testing.T) {
	for _, on := range []bool{true, false} {
		eval, err := coraza.New(coraza.Config{})
		if err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: on}),
			Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
		if err != nil {
			t.Fatal(err)
		}
		addr := traefik(t, h)
		conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		check := func(service string) codes.Code {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service})
			return status.Code(err)
		}
		if got := check("shop.Catalog"); got != codes.OK {
			t.Errorf("grpcMessages %v: clean call %v", on, got)
		}
		want := codes.OK
		if on {
			want = codes.PermissionDenied
		}
		if got := check("1' OR '1'='1' -- "); got != want {
			t.Errorf("grpcMessages %v: attack in the message %v, want %v; events %s", on, got, want, logs.String())
		}
		_ = conn.Close()
	}
}

// TestGRPCWebText: a gRPC-Web text call (base64) through Traefik passes
// when clean; an attack in its message is denied with grpc-status 7.
// Before v0.4.0 every one was denied (920420).
func TestGRPCWebText(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: true}),
		Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	call := func(message string) *httptest.ResponseRecorder {
		r := grpcSubrequest("/helloworld.Greeter/SayHello", base64.StdEncoding.EncodeToString([]byte(grpcMessages(message))))
		r.Header.Set("Content-Type", "application/grpc-web-text")
		return serve(h, r)
	}
	if w := call("world"); w.Code != http.StatusOK {
		t.Fatalf("clean: %d; events %s", w.Code, logs.String())
	}
	if w := call("1' OR '1'='1' -- "); w.Code != http.StatusForbidden || w.Header().Get("Grpc-Status") != "7" {
		t.Fatalf("attack: %d %v", w.Code, w.Header())
	}
}
