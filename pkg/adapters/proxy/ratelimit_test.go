// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
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

// Over a limit, the standalone proxy answers 429 with Retry-After, and
// the upstream never sees the request (#705).
func TestRateLimitDenial(t *testing.T) {
	up := newUpstream(t)
	rl, err := pipeline.CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "shop/web",
		[]pipeline.RateLimitConfig{{Name: "all", Requests: 1, Period: time.Minute, Burst: 1}})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(up.srv.URL)
	h, err := New(pipeline.New(cleanEvaluator{}, pipeline.Config{Mode: pipeline.ModeBlock, RateLimits: rl}),
		Config{Upstream: target, MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("first request: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" || w.Header().Get("X-Request-Id") == "" {
		t.Errorf("over the limit: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
}
