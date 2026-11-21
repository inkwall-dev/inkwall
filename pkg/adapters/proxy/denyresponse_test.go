// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// A policy's spec.denyResponse replaces the proxy's own body on each of its
// denials, the request's and the response's, with the verdict's status and
// headers (#725); a gRPC call keeps its trailers-only denial, and a request
// the proxy can't read its fixed 400.
func TestDenyResponse(t *testing.T) {
	deny, err := pipeline.CompileDenyResponse("text/html", "<h1>Blocked</h1><p>Request {{request_id}}</p>")
	if err != nil {
		t.Fatal(err)
	}
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rl, err := pipeline.CompileRateLimits(ratelimit.New(1024, 0), ratelimit.NewLive(), "shop/web",
		[]pipeline.RateLimitConfig{{Name: "login", Requests: 1, Period: time.Hour, Burst: 1, Paths: []string{"/login"}}})
	if err != nil {
		t.Fatal(err)
	}
	up := newResponder(t, 500, http.Header{"Content-Type": {"text/html"}}, sqlError)
	target, _ := url.Parse(up.srv.URL)
	var logs bytes.Buffer
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
		Responses: inspect(64 << 10), RateLimits: rl, DenyResponse: deny}),
		Config{Upstream: target, MaxBodyBytes: 64 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil)), JSONDenials: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// answer is what the client got, its body read and closed.
	type answer struct {
		StatusCode int
		Header     http.Header
	}
	get := func(path string, header ...string) (answer, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
		req.Header.Set("Accept", "application/json")
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return answer{resp.StatusCode, resp.Header}, string(b)
	}
	custom := func(name string, resp answer, body string, status int) {
		t.Helper()
		id := resp.Header.Get("X-Request-Id")
		want := "<h1>Blocked</h1><p>Request " + id + "</p>"
		if resp.StatusCode != status || id == "" || body != want || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" ||
			resp.Header.Get("Content-Length") != strconv.Itoa(len(want)) || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %d, X-Request-Id %q, Content-Type %q, Content-Length %q, body %q; want %d and %q", name, resp.StatusCode, id,
				resp.Header.Get("Content-Type"), resp.Header.Get("Content-Length"), body, status, want)
		}
	}

	// A rule's denial: the custom body even though the client accepts
	// JSON and JSON denials are on; the client's request ID in it.
	resp, body := get("/products?id=1%27%20OR%20%271%27%3D%271", "X-Request-Id", "client-id-1")
	custom("rule", resp, body, 403)
	if resp.Header.Get("X-Request-Id") != "client-id-1" {
		t.Errorf("rule: X-Request-Id %q, want the client's", resp.Header.Get("X-Request-Id"))
	}
	// An X-Request-Id that would be markup is replaced, never echoed.
	resp, body = get("/products?id=1%27%20OR%20%271%27%3D%271", "X-Request-Id", `"><script>alert(1)</script>`)
	custom("hostile request ID", resp, body, 403)
	if bytes.Contains([]byte(body), []byte("<script>")) {
		t.Errorf("hostile request ID: %q", body)
	}

	// The response phase: the leaked SQL error replaced by the custom body.
	resp, body = get("/products/42")
	custom("response", resp, body, 403)

	// A rate limit: 429 with Retry-After, and the custom body.
	get("/login") // within the limit (its response then replaced: the upstream leaks)
	resp, body = get("/login")
	custom("rate limit", resp, body, 429)
	if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra < 3599 || ra > 3600 {
		t.Errorf("rate limit: Retry-After %q", resp.Header.Get("Retry-After"))
	}

	// gRPC: HTTP 200 and the gRPC status, no body.
	resp, body = get("/shop.Cart/Add?id=1%27%20OR%20%271%27%3D%271", "Content-Type", "application/grpc-web")
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "7" || body != "" {
		t.Errorf("gRPC-Web: %d, grpc-status %q, body %q; want 200, 7 and none", resp.StatusCode, resp.Header.Get("Grpc-Status"), body)
	}

	// A request the proxy can't read: the fixed 400.
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "bad host"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || w.Body.String() != "Bad Request\n" {
		t.Errorf("400: %d %q", w.Code, w.Body.String())
	}
}
