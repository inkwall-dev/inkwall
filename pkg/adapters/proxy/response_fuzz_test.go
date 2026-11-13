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
	"sync"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// fuzzResponse is what the fuzzed upstream answers.
type fuzzResponse struct {
	contentType string
	body        []byte
	// length is the Content-Length sent: the body's, or a lie (shorter).
	length int
}

var fuzzContentTypes = []string{"text/html", "application/json", "text/plain; charset=utf-8", "image/png", "text/event-stream", ""}

// FuzzProxyResponse fuzzes the proxy's response path (#323): it reads a
// response body's prefix for inspection and puts it back. In Detect mode
// every response is forwarded, so the client must get the upstream's body
// byte for byte, whatever the body, its media type, its length against the
// limit, or a Content-Length that lies (then the response is cut, never
// made up), and no held bytes may leak.
func FuzzProxyResponse(f *testing.F) {
	f.Add([]byte(sqlError), uint8(0), false)
	f.Add([]byte("{\"a\":1}"), uint8(1), false)
	f.Add(bytes.Repeat([]byte("x"), 300), uint8(2), true)
	f.Add([]byte{}, uint8(3), false)

	var (
		mu  sync.Mutex
		cur fuzzResponse
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		c := cur
		mu.Unlock()
		if c.contentType != "" {
			w.Header().Set("Content-Type", c.contentType)
		}
		w.Header().Set("Content-Length", strconv.Itoa(c.length))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(c.body[:min(len(c.body), c.length)])
	}))
	f.Cleanup(up.Close)
	target, _ := url.Parse(up.URL)
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		f.Fatal(err)
	}
	// A small limit, so bodies are often longer: the prefix and the rest.
	const limit = 128
	const held = 4 * (limit + 1)
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeDetect, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: limit}}),
		Config{Upstream: target, MaxBodyBytes: 1 << 10, Logger: slog.New(slog.DiscardHandler), MaxHeldResponseBytes: held})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(h.proxy.Transport.(*http.Transport).CloseIdleConnections)
	front := httptest.NewServer(h)
	f.Cleanup(front.Close)
	client := front.Client()

	f.Fuzz(func(t *testing.T, body []byte, kind uint8, lie bool) {
		c := fuzzResponse{contentType: fuzzContentTypes[int(kind)%len(fuzzContentTypes)], body: body, length: len(body)}
		if lie && len(body) > 0 {
			// Claim more than is sent: the upstream's connection ends short.
			c.length = len(body) + 1
		}
		mu.Lock()
		cur = c
		mu.Unlock()
		resp, err := client.Get(front.URL + "/fuzz")
		if err != nil {
			if c.length == len(body) {
				t.Fatal(err)
			}
			// A cut upstream response aborts the client's, as ReverseProxy
			// does without inspection: the error can come before the
			// headers, which were still buffered.
			resp = nil
		}
		if resp == nil {
			waitReleased(t, h, held)
			return
		}
		got, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch {
		case c.length == len(body):
			if resp.StatusCode != http.StatusOK || readErr != nil || !bytes.Equal(got, body) {
				t.Fatalf("%s, %d bytes: got %d, %d bytes, %v", c.contentType, len(body), resp.StatusCode, len(got), readErr)
			}
		case resp.StatusCode == http.StatusOK && !bytes.HasPrefix(body, got):
			// A cut response: what arrives is the upstream's, never more.
			t.Fatalf("a cut response: got %d bytes that aren't the body's prefix", len(got))
		}
		waitReleased(t, h, held)
	})
}

// waitReleased fails t unless every held byte is given back once the
// response is done.
func waitReleased(t *testing.T, h *Handler, held int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !h.held.TryAcquire(held) {
		if time.Now().After(deadline) {
			t.Fatal("held response bytes not released")
		}
		time.Sleep(time.Millisecond)
	}
	h.held.Release(held)
}
