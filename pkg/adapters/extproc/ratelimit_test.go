// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

type cleanEvaluator struct{}

func (cleanEvaluator) Evaluate(context.Context, *request.Request) (rules.Result, error) {
	return rules.Result{}, nil
}

// Over a limit, Envoy answers 429 with Retry-After in the
// ImmediateResponse (#705).
func TestRateLimitDenial(t *testing.T) {
	rl, err := pipeline.CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "shop/web",
		[]pipeline.RateLimitConfig{{Name: "all", Requests: 1, Period: time.Minute, Burst: 1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pipeline.New(cleanEvaluator{}, pipeline.Config{Mode: pipeline.ModeBlock, RateLimits: rl}),
		Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	// On the Unix socket Envoy is a loopback peer: the client IP the limit
	// counts by (bufconn has no address, and no address isn't limited).
	sock := filepath.Join(t.TempDir(), "extproc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	})
	if resps := e.exchange(t, headers("GET", "/", true)); resps[0].GetImmediateResponse() != nil {
		t.Fatalf("first request denied: %v", resps[0])
	}
	resps := e.exchange(t, headers("GET", "/", true))
	got := map[string]string{}
	for _, h := range resps[0].GetImmediateResponse().GetHeaders().GetSetHeaders() {
		got[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	if denied(t, resps[0]) != 429 || got["retry-after"] != "60" || got["x-request-id"] == "" {
		t.Errorf("over the limit: headers %v, want 429 with retry-after 60", got)
	}
	// A gRPC call over the limit: RESOURCE_EXHAUSTED (8), Retry-After too.
	resps = e.exchange(t, headers("POST", "/shop.Cart/Add", false, "content-type", "application/grpc"))
	got = map[string]string{}
	for _, h := range resps[0].GetImmediateResponse().GetHeaders().GetSetHeaders() {
		got[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	if resps[0].GetImmediateResponse().GetGrpcStatus().GetStatus() != 8 && got["grpc-status"] != "8" || got["retry-after"] == "" {
		t.Errorf("gRPC over the limit: %v, headers %v; want grpc-status 8 and retry-after", resps[0].GetImmediateResponse().GetGrpcStatus(), got)
	}
}
