// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/websocket"
)

// The WebSockets of both kinds: forwarded as they are, and with their
// messages inspected.
var wsKinds = []struct {
	name     string
	messages pipeline.WebSocketMessages
}{{"uninspected", pipeline.MessagesOff}, {"inspected", pipeline.MessagesInspect}}

// TestWebSocketIdleTimeout (#368): a WebSocket with no frame in either
// direction for WebSocketIdleTimeout is closed with 1001; one in use stays
// open.
func TestWebSocketIdleTimeout(t *testing.T) {
	for _, k := range wsKinds {
		t.Run(k.name, func(t *testing.T) {
			_, addr, _, _ := newWSProxyWith(t, pipeline.ModeBlock, k.messages, pipeline.OversizeAuto, 64, nil,
				func(c *Config) { c.WebSocketIdleTimeout = 300 * time.Millisecond })
			c := dialWS(t, addr)
			// In use: a message every 100ms for twice the timeout.
			for i := range 6 {
				c.send(t, clientFrame(true, websocket.OpText, []byte(fmt.Sprint("m", i))))
				c.echoes(t, fmt.Sprint("m", i))
				time.Sleep(100 * time.Millisecond)
			}
			start := time.Now()
			c.closed(t, websocket.CloseGoingAway)
			if d := time.Since(start); d < 150*time.Millisecond || d > 3*time.Second {
				t.Errorf("closed after %v idle, want about 300ms", d)
			}
		})
	}
	// Unset: no idle limit.
	_, addr, _, _ := newWSProxyWith(t, pipeline.ModeBlock, pipeline.MessagesOff, pipeline.OversizeAuto, 64, nil, nil)
	c := dialWS(t, addr)
	time.Sleep(500 * time.Millisecond)
	c.send(t, clientFrame(true, websocket.OpText, []byte("late")))
	c.echoes(t, "late")
}

// TestCloseWebSockets (#368): on shutdown the open WebSockets get 1001,
// and CloseWebSockets returns once they are closed.
func TestCloseWebSockets(t *testing.T) {
	for _, k := range wsKinds {
		t.Run(k.name, func(t *testing.T) {
			_, addr, _, h := newWSProxyWith(t, pipeline.ModeBlock, k.messages, pipeline.OversizeAuto, 64, nil, nil)
			c1, c2 := dialWS(t, addr), dialWS(t, addr)
			for _, c := range []*wsClient{c1, c2} {
				c.send(t, clientFrame(true, websocket.OpText, []byte("hi")))
				c.echoes(t, "hi")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.CloseWebSockets(ctx) }()
			c1.closed(t, websocket.CloseGoingAway)
			c2.closed(t, websocket.CloseGoingAway)
			if err := <-done; err != nil {
				t.Fatalf("CloseWebSockets: %v", err)
			}
		})
	}
}

// TestBodyReadTimeout (#368): BodyReadTimeout bounds reading the part of
// the body the engine inspects: a client that stalls in it gets 408; once
// the prefix is read, the rest of a long upload streams to the upstream
// for as long as it takes.
func TestBodyReadTimeout(t *testing.T) {
	got := make(chan int, 4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- len(b)
	}))
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Oversize: pipeline.OversizeAllow, Timeout: 10 * time.Second}),
		Config{Upstream: upURL, MaxBodyBytes: 64, BodyReadTimeout: 300 * time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	post := func(t *testing.T, size int, chunks []string, pause time.Duration) *http.Response {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: test\r\nAccept: */*\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n", size)
		for _, c := range chunks {
			if _, err := io.WriteString(conn, c); err != nil {
				break // the proxy gave up on the request
			}
			time.Sleep(pause)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	t.Run("stalled prefix", func(t *testing.T) {
		resp := post(t, 100, []string{"0123456789", "0123456789"}, time.Second)
		if resp.StatusCode != http.StatusRequestTimeout {
			t.Fatalf("status %d, want 408", resp.StatusCode)
		}
		select {
		case n := <-got:
			t.Fatalf("the upstream got %d bytes", n)
		default:
		}
	})
	t.Run("slow upload after the prefix", func(t *testing.T) {
		// The prefix at once, then 6 chunks 150ms apart: 900ms, three
		// times the timeout.
		chunks := []string{"q=" + strings.Repeat("a", 68)}
		for range 6 {
			chunks = append(chunks, strings.Repeat("b", 10))
		}
		resp := post(t, 130, chunks, 150*time.Millisecond)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if n := <-got; n != 130 {
			t.Fatalf("the upstream got %d bytes, want 130", n)
		}
	})
}
