// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqlError = "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax</body></html>"

// responder is an upstream that answers every request with one response,
// and records the last request's Accept-Encoding.
type responder struct {
	srv            *httptest.Server
	mu             sync.Mutex
	acceptEncoding string
}

func newResponder(t testing.TB, status int, header http.Header, body string) *responder {
	t.Helper()
	r := &responder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.acceptEncoding = req.Header.Get("Accept-Encoding")
		r.mu.Unlock()
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func newResponseHandler(t testing.TB, mode pipeline.Mode, responses pipeline.ResponseConfig, up *httptest.Server, logs io.Writer, maxHeld int64) *Handler {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second, Responses: responses}), Config{
		Upstream:             target,
		MaxBodyBytes:         64 << 10,
		Logger:               slog.New(slog.NewJSONHandler(logs, nil)),
		MaxHeldResponseBytes: maxHeld,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func inspect(max int64) pipeline.ResponseConfig {
	return pipeline.ResponseConfig{Inspect: true, MaxBytes: max}
}

func gzipped(t testing.TB, s string) string {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = io.WriteString(zw, s)
	_ = zw.Close()
	return b.String()
}

// The reverse proxy inspects responses as ext_proc does (#323): a leaked
// SQL error is replaced in block mode, logged in detect mode; a benign
// response reaches the client intact, with its body read for inspection
// put back.
func TestResponses(t *testing.T) {
	html := http.Header{"Content-Type": {"text/html"}}
	long := strings.Repeat("<p>catalogue</p>", 20000) // 320 KB, over the limit
	for _, tc := range []struct {
		name       string
		mode       pipeline.Mode
		responses  pipeline.ResponseConfig
		header     http.Header
		body       string
		wantStatus int
		wantBody   string // "": the upstream's body
		wantEvent  bool
	}{
		{name: "leak blocked", mode: pipeline.ModeBlock, responses: inspect(64 << 10), header: html, body: sqlError, wantStatus: 403, wantBody: "Forbidden", wantEvent: true},
		{name: "leak logged in detect mode", mode: pipeline.ModeDetect, responses: inspect(64 << 10), header: html, body: sqlError, wantStatus: 500, wantEvent: true},
		{name: "gzip leak blocked", mode: pipeline.ModeBlock, responses: inspect(64 << 10),
			header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, body: gzipped(t, sqlError), wantStatus: 403, wantBody: "Forbidden", wantEvent: true},
		{name: "benign passes intact", mode: pipeline.ModeBlock, responses: inspect(64 << 10), header: html, body: "<p>hello</p>", wantStatus: 500},
		{name: "not inspected without the setting", mode: pipeline.ModeBlock, responses: pipeline.ResponseConfig{}, header: html, body: sqlError, wantStatus: 500},
		{name: "an image passes uninspected", mode: pipeline.ModeBlock, responses: inspect(64 << 10),
			header: http.Header{"Content-Type": {"image/png"}}, body: sqlError, wantStatus: 500},
		{name: "oversized: deny in block mode", mode: pipeline.ModeBlock, responses: inspect(1 << 10), header: html, body: long, wantStatus: 502, wantBody: "Bad Gateway", wantEvent: true},
		{name: "oversized allowed: forwarded whole", mode: pipeline.ModeBlock,
			responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 1 << 10, Oversize: pipeline.OversizeAllow}, header: html, body: long, wantStatus: 500, wantEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := 500
			up := newResponder(t, status, tc.header, tc.body)
			var logs bytes.Buffer
			h := newResponseHandler(t, tc.mode, tc.responses, up.srv, &logs, 0)
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			req, _ := http.NewRequest("GET", srv.URL+"/products/42", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Encoding", "br")
			// Read the body as it came, gzip or not.
			tr := &http.Transport{DisableCompression: true}
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if want := cmpBody(tc.wantBody, tc.body); !strings.Contains(string(got), want) || tc.wantBody == "" && string(got) != tc.body {
				t.Errorf("body %.80q, want %.80q", got, want)
			}
			if tc.wantBody != "" && resp.Header.Get("X-Request-Id") == "" {
				t.Error("a replaced response has no X-Request-Id")
			}
			event := strings.Contains(logs.String(), `"phase":"response"`)
			if event != tc.wantEvent {
				t.Errorf("response event %v, want %v; logs: %s", event, tc.wantEvent, logs.String())
			}
			// When bodies are inspected, the client's Accept-Encoding is
			// removed, so the upstream doesn't answer in an encoding the
			// rules can't read (Go's transport asks for gzip itself, and
			// decodes it).
			up.mu.Lock()
			ae := up.acceptEncoding
			up.mu.Unlock()
			if removed := tc.responses.Inspect && tc.responses.MaxBytes > 0; (ae != "br") != removed {
				t.Errorf("Accept-Encoding to the upstream %q; the client's removed: want %v", ae, removed)
			}
		})
	}
}

func cmpBody(want, upstream string) string {
	if want == "" {
		return upstream
	}
	return want
}

// Held response bodies are bounded (#323): each to its limit, and all of
// them together to MaxHeldResponseBytes. Past it, a response gets the
// failure mode, as an evaluation refused for overload: 503 in block mode.
func TestHeldResponsesAreBounded(t *testing.T) {
	html := http.Header{"Content-Type": {"text/html"}}
	// The upstream sends the first part of the body, then waits: the
	// first response holds its share until released.
	release := make(chan struct{})
	first := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range html {
			w.Header()[k] = v
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "<p>part one</p>")
		w.(http.Flusher).Flush()
		if r.URL.Path == "/slow" {
			first <- struct{}{}
			<-release
		}
		_, _ = io.WriteString(w, "<p>part two</p>")
	}))
	t.Cleanup(slow.Close)
	var logs bytes.Buffer
	// Room for one held body of 1 KiB (and its extra byte).
	h := newResponseHandler(t, pipeline.ModeBlock, inspect(1<<10), slow, &logs, 1<<10+1)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Error(err)
			return 0, ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if code, body := get("/slow"); code != 200 || body != "<p>part one</p><p>part two</p>" {
			t.Errorf("held response: %d %q", code, body)
		}
	}()
	<-first
	if code, _ := get("/fast"); code != http.StatusServiceUnavailable {
		t.Errorf("a response past the held bytes: %d, want 503", code)
	}
	close(release)
	<-done
	// Released once the proxy closed the held body, just after the client
	// read it: the next one is held and inspected again.
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := get("/fast")
		if code == 200 && body == "<p>part one</p><p>part two</p>" {
			break
		}
		if code != http.StatusServiceUnavailable || time.Now().After(deadline) {
			t.Fatalf("after the release: %d %q", code, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The latency response inspection adds through the proxy (#323), against
// the same responses not inspected.
func BenchmarkResponses(b *testing.B) {
	page := strings.Repeat("<p>catalogue entry</p>\n", 700) // about 16 KB of HTML
	for _, c := range []struct {
		name  string
		resp  pipeline.ResponseConfig
		ctype string
		body  string
	}{
		{"html_16k_off", pipeline.ResponseConfig{}, "text/html", page},
		{"html_16k_on", inspect(64 << 10), "text/html", page},
		{"json_1k_on", inspect(64 << 10), "application/json", `{"items":[` + strings.Repeat(`{"id":42,"name":"widget"},`, 40) + `{}]}`},
		{"image_on", inspect(64 << 10), "image/png", page},
	} {
		b.Run(c.name, func(b *testing.B) {
			up := newResponder(b, 200, http.Header{"Content-Type": {c.ctype}}, c.body)
			h := newResponseHandler(b, pipeline.ModeBlock, c.resp, up.srv, io.Discard, 0)
			b.ReportAllocs()
			for b.Loop() {
				w := do(h, "GET", "/products?id=42", "", "")
				if w.Code != 200 || w.Body.Len() != len(c.body) {
					b.Fatalf("%d, %d bytes", w.Code, w.Body.Len())
				}
			}
		})
	}
}
