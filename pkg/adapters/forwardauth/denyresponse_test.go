// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
)

// Traefik copies the engine's denial to the client: with a policy's
// spec.denyResponse, its body, with the verdict's status, Retry-After and
// request ID (#725). A gRPC call keeps its gRPC status and no body; an
// invalid subrequest the fixed 400.
func TestDenyResponse(t *testing.T) {
	deny, err := pipeline.CompileDenyResponse("application/json", `{"error":"slow down","id":"{{request_id}}"}`)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := pipeline.CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "shop/web",
		[]pipeline.RateLimitConfig{{Name: "all", Requests: 1, Period: time.Minute, Burst: 1}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(pipeline.New(cleanEvaluator{}, pipeline.Config{Mode: pipeline.ModeBlock, RateLimits: rl, DenyResponse: deny}),
		Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	serve(h, subrequest("GET", "/", "", ""))
	r := subrequest("GET", "/", "", "")
	r.Header.Set("X-Request-Id", `x","admin":true,"y":"`)
	w := serve(h, r)
	id := w.Header().Get("X-Request-Id")
	want := `{"error":"slow down","id":"` + id + `"}`
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" || w.Header().Get("Content-Type") != "application/json" ||
		w.Header().Get("Content-Length") != strconv.Itoa(len(want)) || w.Body.String() != want || strings.Contains(id, `"`) {
		t.Errorf("denial: %d, headers %v, body %q; want 429 and %q", w.Code, w.Header(), w.Body.String(), want)
	}

	w = serve(h, grpcSubrequest("/shop.Cart/Add", grpcMessages("x")))
	if w.Header().Get("Grpc-Status") != "8" || w.Body.Len() != 0 {
		t.Errorf("gRPC: grpc-status %q, body %q; want 8 and none", w.Header().Get("Grpc-Status"), w.Body.String())
	}

	r = subrequest("GET", "/", "", "")
	r.Header.Del("X-Forwarded-Method")
	if w = serve(h, r); w.Code != 400 || w.Body.String() != "Bad Request\n" {
		t.Errorf("invalid subrequest: %d %q", w.Code, w.Body.String())
	}
}
