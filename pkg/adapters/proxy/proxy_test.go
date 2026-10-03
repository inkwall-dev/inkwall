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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

type upstream struct {
	srv      *httptest.Server
	hits     atomic.Int32
	lastBody atomic.Value
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		u.lastBody.Store(string(b))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream ok")
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func newHandler(t *testing.T, mode pipeline.Mode, maxBody int64, up *upstream, logs *bytes.Buffer) *Handler {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// A generous timeout keeps the race detector from tripping the deadline.
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 500 * time.Millisecond}), Config{
		Upstream:     target,
		MaxBodyBytes: maxBody,
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func do(h http.Handler, method, target, contentType, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = "shop.example.com"
	r.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBlockMode(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, up, &logs)

	if w := do(h, "GET", "/products?id=42", "", ""); w.Code != http.StatusOK || w.Body.String() != "upstream ok" {
		t.Fatalf("benign request: got %d %q, want 200 from upstream", w.Code, w.Body.String())
	}
	if w := do(h, "GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("sqli request: got %d, want 403", w.Code)
	}
	if w := do(h, "POST", "/comments", "application/x-www-form-urlencoded", "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); w.Code != http.StatusForbidden {
		t.Fatalf("xss body: got %d, want 403", w.Code)
	}
	if got := up.hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (attacks must not reach it)", got)
	}
	if !strings.Contains(logs.String(), `"action":"deny"`) {
		t.Fatalf("no deny event logged:\n%s", logs.String())
	}
}

func TestDetectModeForwardsAndLogs(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeDetect, 64<<10, up, &logs)

	if w := do(h, "GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""); w.Code != http.StatusOK {
		t.Fatalf("detect mode: got %d, want 200", w.Code)
	}
	if got := up.hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	if !strings.Contains(logs.String(), `"action":"log"`) || !strings.Contains(logs.String(), `"rule_ids":[`) {
		t.Fatalf("detect event missing or incomplete:\n%s", logs.String())
	}
}

func TestBenignRequestsAreNotLogged(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, up, &logs)
	do(h, "GET", "/products?id=42", "", "")
	if logs.Len() != 0 {
		t.Fatalf("benign request produced log output:\n%s", logs.String())
	}
}

func TestBodyIsForwardedIntact(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	// Inspect only the first 16 bytes; the upstream must still get everything.
	h := newHandler(t, pipeline.ModeBlock, 16, up, &logs)

	body := "user=alice&note=" + strings.Repeat("a", 1000)
	if w := do(h, "POST", "/notes", "application/x-www-form-urlencoded", body); w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if got, _ := up.lastBody.Load().(string); got != body {
		t.Fatalf("upstream received %d bytes, want %d", len(got), len(body))
	}
}

func TestOversizedBodies(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	// Inspect only the first 1 KB of each body.
	h := newHandler(t, pipeline.ModeBlock, 1<<10, up, &logs)
	pad := strings.Repeat("a", 4<<10)

	// A valid JSON body larger than the limit must not be rejected because
	// its truncated prefix does not parse.
	if w := do(h, "POST", "/upload", "application/json", `{"blob":"`+pad+`"}`); w.Code != http.StatusOK {
		t.Fatalf("valid oversized JSON: got %d, want 200\n%s", w.Code, logs.String())
	}
	// URL-encoded prefixes are still inspected: an attack in the first 1 KB
	// is blocked even when the body is longer.
	if w := do(h, "POST", "/comments", "application/x-www-form-urlencoded",
		"comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E&pad="+pad); w.Code != http.StatusForbidden {
		t.Fatalf("attack in form prefix: got %d, want 403", w.Code)
	}
	// Complete JSON bodies within the limit are still inspected.
	if w := do(h, "POST", "/api/search", "application/json", `{"q":"1' OR '1'='1' -- "}`); w.Code != http.StatusForbidden {
		t.Fatalf("attack in small JSON: got %d, want 403", w.Code)
	}
}

func TestBodyInspectionDisabled(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 0, up, &logs)

	// With body inspection off, an attack in the body is not seen.
	if w := do(h, "POST", "/comments", "application/x-www-form-urlencoded", "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body not inspected)", w.Code)
	}
}

func TestTransferEncodingIsRestored(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, up, &logs)

	r := httptest.NewRequest("POST", "/notes", strings.NewReader("note=hello"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TransferEncoding = []string{"chunked"}
	r.ContentLength = -1

	req, err := h.toRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Headers.Get("Transfer-Encoding"); got != "chunked" {
		t.Fatalf("Transfer-Encoding = %q, want chunked", got)
	}
	if r.Header.Get("Transfer-Encoding") != "" {
		t.Fatal("original request headers were modified")
	}
}

func TestContentLengthIsRestored(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, up, &logs)

	r := httptest.NewRequest("POST", "/notes", strings.NewReader("note=hello"))
	r.Header.Del("Content-Length")
	req, err := h.toRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Headers.Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length = %q, want 10", got)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	eval, err := coraza.New(coraza.Config{DisableCRS: true})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{})
	if _, err := New(p, Config{}); err == nil {
		t.Error("missing upstream accepted")
	}
	if _, err := New(p, Config{Upstream: &url.URL{Path: "/relative"}}); err == nil {
		t.Error("relative upstream accepted")
	}
	if _, err := New(p, Config{Upstream: &url.URL{Scheme: "http", Host: "app"}, MaxBodyBytes: -1}); err == nil {
		t.Error("negative body limit accepted")
	}
}

// noContentTransport answers every request in memory, so the benchmark
// measures Inkwall's overhead rather than network time.
type noContentTransport struct{}

func (noContentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{},
		Body:    http.NoBody,
		Request: r,
	}, nil
}

func BenchmarkServeHTTP(b *testing.B) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		b.Fatal(err)
	}
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock}), Config{
		Upstream:     &url.URL{Scheme: "http", Host: "upstream.invalid"},
		MaxBodyBytes: 64 << 10,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		b.Fatal(err)
	}
	h.proxy.Transport = noContentTransport{}

	cases := []struct{ name, method, target, body string }{
		{"benign_get", "GET", "/products?id=42&sort=price", ""},
		{"benign_form", "POST", "/login", "user=alice&password=correct-horse"},
		{"attack_sqli", "GET", "/products?id=1%27%20OR%20%271%27%3D%271", ""},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				w := do(h, c.method, c.target, "application/x-www-form-urlencoded", c.body)
				if w.Code == 0 {
					b.Fatal("no response")
				}
			}
		})
	}
}
