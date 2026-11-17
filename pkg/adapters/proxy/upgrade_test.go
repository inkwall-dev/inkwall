// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// switchingUpstream switches protocols on any Upgrade it gets, as a
// permissive server does (one that takes h2c without HTTP2-Settings), and
// serves app otherwise. Each request's Upgrade and HTTP2-Settings headers
// go to seen.
func switchingUpstream(t *testing.T, app http.Handler, seen chan<- string) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrade := strings.Join(r.Header.Values("Upgrade"), ",")
		seen <- "upgrade=" + upgrade + " settings=" + r.Header.Get("Http2-Settings")
		if upgrade == "" {
			app.ServeHTTP(w, r)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + r.Header.Get("Upgrade") + "\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(io.Discard, brw)
	}))
	t.Cleanup(up.Close)
	return up
}

func upgradeProxy(t *testing.T, up *httptest.Server, messages pipeline.WebSocketMessages) *httptest.Server {
	t.Helper()
	upURL, _ := url.Parse(up.URL)
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second}),
		Config{Upstream: upURL, MaxBodyBytes: 1 << 20, WebSocketMessages: messages})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)
	return front
}

// TestProxyRefusesNonWebSocketUpgrade: the proxy forwards an upgrade only
// to WebSocket. Any other Upgrade (h2c in particular) is removed, with
// HTTP2-Settings, and the request is proxied as a plain one: the upstream
// can't switch the connection to a protocol whose requests the engine
// doesn't see, and a client that offers h2c gets HTTP/1.1.
func TestProxyRefusesNonWebSocketUpgrade(t *testing.T) {
	for messages, name := range map[pipeline.WebSocketMessages]string{pipeline.MessagesOff: "messages off", pipeline.MessagesInspect: "messages inspected"} {
		seen := make(chan string, 16)
		app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "app: "+r.Proto)
		})
		front := upgradeProxy(t, switchingUpstream(t, app, seen), messages)

		tests := []struct{ name, headers string }{
			{"h2c", "Connection: Upgrade\r\nUpgrade: h2c\r\n"},
			{"h2c with settings", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"},
			{"websocket and h2c", "Connection: Upgrade\r\nUpgrade: websocket, h2c\r\n"},
			{"h2c and websocket", "Connection: Upgrade\r\nUpgrade: h2c, WebSocket\r\n"},
			{"two Upgrade lines", "Connection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: h2c\r\n"},
			{"versioned websocket", "Connection: Upgrade\r\nUpgrade: websocket/13\r\n"},
			{"other protocol", "Connection: Upgrade\r\nUpgrade: TLS/1.2\r\n"},
		}
		for _, tt := range tests {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"+tt.headers+"\r\n")
				res, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if got := <-seen; got != "upgrade= settings=" {
					t.Errorf("upstream got %q, want no Upgrade and no HTTP2-Settings", got)
				}
				if res.StatusCode == http.StatusSwitchingProtocols {
					// The connection would carry requests (HTTP/2 for
					// h2c) that the engine never sees.
					t.Fatalf("101 to %q, want the request proxied as a plain one", res.Header.Get("Upgrade"))
				}
				if res.StatusCode != http.StatusOK || string(body) != "app: HTTP/1.1" {
					t.Fatalf("%d %q, want 200 from the app over HTTP/1.1", res.StatusCode, body)
				}
			})
		}
	}
}

// TestProxyForwardsWebSocketUpgrade: a WebSocket upgrade still passes,
// whatever the token's case, with the Connection header's upgrade token.
func TestProxyForwardsWebSocketUpgrade(t *testing.T) {
	seen := make(chan string, 4)
	front := upgradeProxy(t, switchingUpstream(t, http.NotFoundHandler(), seen), pipeline.MessagesOff)
	for _, token := range []string{"websocket", "WebSocket"} {
		t.Run(token, func(t *testing.T) {
			c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(c, "GET /chat HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"+
				"Connection: keep-alive, Upgrade\r\nUpgrade: "+token+"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
			res, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if got := <-seen; got != "upgrade="+token+" settings=" {
				t.Errorf("upstream got %q", got)
			}
			if res.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("%s, want 101", res.Status)
			}
		})
	}
}
