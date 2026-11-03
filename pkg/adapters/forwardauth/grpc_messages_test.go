// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"context"
	"log/slog"
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
