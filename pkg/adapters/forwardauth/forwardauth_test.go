// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func newPipeline(t *testing.T, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// A generous timeout keeps the race detector from tripping the deadline.
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 500 * time.Millisecond})
}

func newHandler(t *testing.T, mode pipeline.Mode, maxBody int64, logs *bytes.Buffer) *Handler {
	t.Helper()
	h, err := New(newPipeline(t, mode), Config{
		MaxBodyBytes: maxBody,
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// subrequest builds what Traefik's ForwardAuth (trustForwardHeader: false,
// forwardBody: true) sends for a client request.
func subrequest(method, uri, contentType, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(http.MethodGet, Path, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
	} else {
		r = httptest.NewRequest(http.MethodGet, Path, nil)
	}
	r.Host = "127.0.0.1:9001"
	r.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Host", "shop.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Port", "443")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBlockMode(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, &logs)

	w := serve(h, subrequest("GET", "/products?id=42", "", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("benign request: got %d, want 200", w.Code)
	}
	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("allowed request has no X-Request-Id for the upstream")
	}
	if w := serve(h, subrequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", "")); w.Code != http.StatusForbidden {
		t.Fatalf("sqli in the URI: got %d, want 403", w.Code)
	}
	if w := serve(h, subrequest("POST", "/comments", "application/x-www-form-urlencoded", "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E")); w.Code != http.StatusForbidden {
		t.Fatalf("xss in the body: got %d, want 403", w.Code)
	}
	if !strings.Contains(logs.String(), `"action":"deny"`) || !strings.Contains(logs.String(), `"path":"/products"`) {
		t.Fatalf("deny event missing or incomplete:\n%s", logs.String())
	}
}

func TestDetectModeAllowsAndLogs(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeDetect, 64<<10, &logs)
	if w := serve(h, subrequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", "", "")); w.Code != http.StatusOK {
		t.Fatalf("detect mode: got %d, want 200", w.Code)
	}
	if !strings.Contains(logs.String(), `"action":"log"`) {
		t.Fatalf("detect event missing:\n%s", logs.String())
	}
}

func TestOversizedBodyIsDeniedInBlockMode(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 16, &logs)
	w := serve(h, subrequest("POST", "/upload", "application/octet-stream", strings.Repeat("a", 17)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got %d, want 413", w.Code)
	}
}

func TestReconstructsTheClientRequest(t *testing.T) {
	var logs bytes.Buffer
	resolver, err := clientip.NewResolver([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(newPipeline(t, pipeline.ModeBlock), Config{ClientIP: resolver, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	r := subrequest("PUT", "/a%2Fb?x=1;y", "", "")
	r.RemoteAddr = "192.0.2.10:4000"
	r.Header.Set("X-Request-Id", "client-id-1")

	req, path, err := h.toRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "PUT" || req.RawURI != "/a%2Fb?x=1;y" || req.Host != "shop.example.com" || req.Scheme != "https" {
		t.Fatalf("request line not reconstructed: %+v", req)
	}
	if path != "/a/b" {
		t.Fatalf("path = %q, want /a/b", path)
	}
	if req.ClientIP != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("client IP = %s, want 203.0.113.7 from the trusted proxy's X-Forwarded-For", req.ClientIP)
	}
	if req.ID != "client-id-1" {
		t.Fatalf("request ID = %q, want the client's", req.ID)
	}
	for _, name := range synthesized {
		if req.Headers.Get(name) != "" {
			t.Errorf("proxy-added header %s is inspected as a client header", name)
		}
	}
	if req.Headers.Get("User-Agent") == "" {
		t.Error("client headers were not kept")
	}
}

func TestInvalidSubrequestsAreRejected(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeDetect, 64<<10, &logs)
	for name, mutate := range map[string]func(r *http.Request){
		"missing method":   func(r *http.Request) { r.Header.Del("X-Forwarded-Method") },
		"missing uri":      func(r *http.Request) { r.Header.Del("X-Forwarded-Uri") },
		"invalid method":   func(r *http.Request) { r.Header.Set("X-Forwarded-Method", "GE T") },
		"two uris":         func(r *http.Request) { r.Header.Add("X-Forwarded-Uri", "/other") },
		"two hosts":        func(r *http.Request) { r.Header.Add("X-Forwarded-Host", "evil.example") },
		"absolute uri":     func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "http://shop.example.com/") },
		"fragment":         func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "/a#?id=1") },
		"relative uri":     func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "products") },
		"wrong path":       func(r *http.Request) { r.URL.Path = "/v1/check" },
		"empty uri header": func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "") },
	} {
		r := subrequest("GET", "/", "", "")
		mutate(r)
		// Detect mode would allow an attack; a malformed subrequest must
		// still not be answered with 2xx.
		if w := serve(h, r); w.Code < 400 {
			t.Errorf("%s: got %d, want an error status", name, w.Code)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(newPipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: -1}); err == nil {
		t.Error("negative body limit accepted")
	}
}

// TestSameVerdictAsReverseProxy checks the package contract: the reverse
// proxy is the reference adapter, and forward-auth must reach the same
// verdict for the same client request.
func TestSameVerdictAsReverseProxy(t *testing.T) {
	var logs bytes.Buffer
	fa := newHandler(t, pipeline.ModeBlock, 64<<10, &logs)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	rp, err := proxy.New(newPipeline(t, pipeline.ModeBlock), proxy.Config{Upstream: target, MaxBodyBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ method, uri, contentType, body string }{
		{"GET", "/products?id=42", "", ""},
		{"GET", "/search?q=running+shoes&page=2", "", ""},
		{"POST", "/login", "application/x-www-form-urlencoded", "user=alice&password=hunter2"},
		{"POST", "/api/cart", "application/json", `{"sku":"A-1","qty":2}`},
		{"GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""},
		{"GET", "/?file=../../../../etc/passwd", "", ""},
		{"POST", "/ping", "application/x-www-form-urlencoded", "host=127.0.0.1;cat /etc/passwd"},
		{"POST", "/api/notes", "application/json", `{"note":"<script>alert(1)</script>"}`},
	} {
		direct := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(tc.body))
		direct.Host = "shop.example.com"
		direct.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
		direct.Header.Set("Accept", "text/html")
		if tc.body != "" {
			direct.Header.Set("Content-Type", tc.contentType)
		}
		want := serve(rp, direct).Code
		got := serve(fa, subrequest(tc.method, tc.uri, tc.contentType, tc.body)).Code
		allowed := func(code int) bool { return code < 300 }
		if allowed(got) != allowed(want) || (!allowed(got) && got != want) {
			t.Errorf("%s %s: forward-auth %d, reverse proxy %d", tc.method, tc.uri, got, want)
		}
	}
}
