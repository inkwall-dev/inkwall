// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"strings"
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

// Over a limit, Traefik gets 429 with Retry-After, which it copies to the
// client with the request ID; a gRPC call, RESOURCE_EXHAUSTED (#705).
func TestRateLimitDenial(t *testing.T) {
	var logs bytes.Buffer
	rl, err := pipeline.CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "shop/web",
		[]pipeline.RateLimitConfig{{Name: "all", Requests: 1, Period: time.Hour, Burst: 1}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(pipeline.New(cleanEvaluator{}, pipeline.Config{Mode: pipeline.ModeBlock, RateLimits: rl}),
		Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(h, subrequest("GET", "/", "", "")); w.Code != 200 {
		t.Fatalf("first request: %d", w.Code)
	}
	w := serve(h, subrequest("GET", "/", "", ""))
	ra, _ := strconv.Atoi(w.Header().Get("Retry-After"))
	if w.Code != 429 || ra < 3599 || ra > 3600 || w.Header().Get("X-Request-Id") == "" || w.Body.String() != "Too Many Requests\n" {
		t.Fatalf("over the limit: %d, Retry-After %q, X-Request-Id %q, body %q", w.Code, w.Header().Get("Retry-After"), w.Header().Get("X-Request-Id"), w.Body.String())
	}
	// The event's log line names the limit and its count (inkwallctl
	// explain reads them).
	if !strings.Contains(logs.String(), `"reason":"rate-limit"`) || !strings.Contains(logs.String(), `"rate_limit":"all"`) || !strings.Contains(logs.String(), `"sampled_count":1`) {
		t.Errorf("log: %s", logs.String())
	}
	w = serve(h, grpcSubrequest("/shop.Cart/Add", grpcMessages("x")))
	if w.Header().Get("Grpc-Status") != "8" || w.Header().Get("Retry-After") == "" {
		t.Errorf("gRPC over the limit: grpc-status %q, Retry-After %q; want 8 (RESOURCE_EXHAUSTED)", w.Header().Get("Grpc-Status"), w.Header().Get("Retry-After"))
	}
}
