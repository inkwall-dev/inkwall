// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

const leakData = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"

// chunkedSSE is an upstream that writes body in chunks of size bytes, each
// flushed on its own.
func chunkedSSE(t testing.TB, body string, size int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < len(body); i += size {
			_, _ = io.WriteString(w, body[i:min(i+size, len(body))])
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func inspectStreams(max int64) pipeline.ResponseConfig {
	return pipeline.ResponseConfig{Inspect: true, MaxBytes: max, Streams: true}
}

// getStream gets path through h and returns once h's handler is done, its
// logs written: Close waits for the requests in flight.
func getStream(t testing.TB, h *Handler, path string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Through the proxy, a stream is inspected event by event (#323), as
// through ext_proc: whatever the chunks the upstream writes, a clean stream
// arrives byte for byte; in block mode a leaking event ends the stream
// before any of it goes out, the events before it delivered; detect mode
// forwards it and logs it with its index.
func TestStreamedResponses(t *testing.T) {
	clean := "data: hello\n\n: keep-alive\n\nevent: x\ndata: wor\ndata: ld\r\n\r\n"
	for size := 1; size <= len(clean); size++ {
		up := chunkedSSE(t, clean, size)
		h := newResponseHandler(t, pipeline.ModeBlock, inspectStreams(64), up, io.Discard, 0)
		got, err := getStream(t, h, "/sse")
		if err != nil || got != clean {
			t.Fatalf("chunks of %d: %q, %v", size, got, err)
		}
	}

	leaky := "data: hello\n\ndata: " + leakData + "\n\ndata: after\n\n"
	for _, size := range []int{1, 7, 40, len(leaky)} {
		var logs bytes.Buffer
		h := newResponseHandler(t, pipeline.ModeBlock, inspectStreams(1<<10), chunkedSSE(t, leaky, size), &logs, 0)
		got, gerr := getStream(t, h, "/sse-leak")
		if got != "data: hello\n\n" {
			t.Errorf("block, chunks of %d: got %q, want the first event only (%v)", size, got, gerr)
		}
		if !strings.Contains(logs.String(), `"stream_event":2`) || !strings.Contains(logs.String(), `"action":"deny"`) {
			t.Errorf("block, chunks of %d: logs %s", size, logs.String())
		}
	}

	var logs bytes.Buffer
	h := newResponseHandler(t, pipeline.ModeDetect, inspectStreams(1<<10), chunkedSSE(t, leaky, 9), &logs, 0)
	if got, err := getStream(t, h, "/sse-leak"); got != leaky || err != nil {
		t.Errorf("detect: %q, %v", got, err)
	}
	if !strings.Contains(logs.String(), `"stream_event":2`) {
		t.Errorf("detect: logs %s", logs.String())
	}

	// Off: the stream passes, uninspected, as before.
	logs.Reset()
	h = newResponseHandler(t, pipeline.ModeBlock, inspect(1<<10), chunkedSSE(t, leaky, 9), &logs, 0)
	if got, _ := getStream(t, h, "/sse-leak"); got != leaky || logs.Len() != 0 {
		t.Errorf("off: %q, logs %s", got, logs.String())
	}
}

// A stream holds its bound's share for its life (#323): past the bound, a
// new one gets the failure mode; ended, its share is given back.
func TestStreamsAreBounded(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		if r.URL.Path == "/long" {
			started <- struct{}{}
			<-release
		}
	}))
	t.Cleanup(up.Close)
	h := newResponseHandler(t, pipeline.ModeBlock, inspectStreams(64), up, io.Discard, 65)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get(srv.URL + "/long")
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}()
	<-started
	// Errorf, not Fatalf: the long stream must still be released.
	if resp, err := http.Get(srv.URL + "/short"); err != nil {
		t.Errorf("a stream past the bound: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("a stream past the bound: %d, want 503", resp.StatusCode)
		}
	}
	close(release)
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := getStream(t, h, "/short")
		if err == nil && got == "data: one\n\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the release: %q, %v", got, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A stream the proxy ends at a denied event is a security event, not an
// error (#615): ReverseProxy's "read error during body copy" isn't logged
// for it, while an upstream that breaks off a stream still logs one at
// error level.
func TestDeniedStreamLogsNoError(t *testing.T) {
	leaky := "data: hello\n\ndata: " + leakData + "\n\ndata: after\n\n"
	var logs bytes.Buffer
	h := newResponseHandler(t, pipeline.ModeBlock, inspectStreams(1<<10), chunkedSSE(t, leaky, 7), &logs, 0)
	if got, _ := getStream(t, h, "/sse-leak"); got != "data: hello\n\n" {
		t.Errorf("denied: got %q, want the first event only", got)
	}
	if !strings.Contains(logs.String(), `"action":"deny"`) {
		t.Errorf("denied: no security event in %s", logs.String())
	}
	if strings.Contains(logs.String(), `"level":"ERROR"`) {
		t.Errorf("denied: logged an error: %s", logs.String())
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		// The connection drops in the middle of the chunked body.
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(broken.Close)
	for _, responses := range []pipeline.ResponseConfig{inspectStreams(1 << 10), inspect(1 << 10)} {
		logs.Reset()
		h = newResponseHandler(t, pipeline.ModeBlock, responses, broken, &logs, 0)
		_, _ = getStream(t, h, "/sse")
		if !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), "read error during body copy") {
			t.Errorf("broken upstream (streams %t): no error logged: %s", responses.Streams, logs.String())
		}
	}
}
