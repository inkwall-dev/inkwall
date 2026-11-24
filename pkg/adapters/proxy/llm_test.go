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
	"sync"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/llmtest"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// The proxy reads an LLM endpoint's body past the policy's body limit and
// checks it (design 0012): a clean request reaches the model server whole,
// a failed check is a 400 with the request ID, and the rules don't read
// the prompt.
func TestLLMEndpoint(t *testing.T) {
	var mu sync.Mutex
	var got []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	t.Cleanup(up.Close)
	target, _ := url.Parse(up.URL)
	var logs bytes.Buffer
	h, err := New(llmtest.Set(t), Config{Upstream: target, MaxBodyBytes: policy.MaxBodyBytes, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	post := func(body string) (int, http.Header, string) {
		t.Helper()
		resp, err := srv.Client().Post(srv.URL+llmtest.Path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}
	if status, _, _ := post(llmtest.Clean); status != 200 {
		t.Fatalf("a clean request: %d", status)
	}
	status, header, body := post(llmtest.Over)
	if status != 400 || header.Get("X-Request-Id") == "" || body != "Bad Request\n" {
		t.Fatalf("over the output cap: %d %q", status, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != llmtest.Clean {
		t.Errorf("the model server got %d requests", len(got))
	}
	if l := logs.String(); !strings.Contains(l, `"llm_check":"llm-max-output-tokens"`) || strings.Contains(l, "Pearl Harbor") {
		t.Errorf("log: %s", l)
	}
}

// A streamed answer's usage settles the request's token limit as it goes
// out, whether the stream is inspected event by event or not: the stream that used 5,000 tokens of a 1,000 an hour limit puts
// the key in debt, so its next request is refused.
func TestLLMStreamUsage(t *testing.T) {
	for _, streams := range []bool{false, true} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for ev := range strings.SplitAfterSeq(llmtest.StreamUsage, "\n\n") {
				_, _ = io.WriteString(w, ev)
				w.(http.Flusher).Flush()
			}
		}))
		t.Cleanup(up.Close)
		target, _ := url.Parse(up.URL)
		h, err := New(llmtest.TokenSet(t, streams), Config{Upstream: target, MaxBodyBytes: policy.MaxBodyBytes, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		post := func() (int, string) {
			t.Helper()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+llmtest.Path, strings.NewReader(llmtest.Small))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Api-Key", "k1")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		if status, body := post(); status != 200 || body != llmtest.StreamUsage {
			t.Fatalf("streams %v: the stream: %d %q", streams, status, body)
		}
		if status, _ := post(); status != 429 {
			t.Errorf("streams %v: after a stream that used 5,000 tokens: %d, want 429", streams, status)
		}
	}
}
