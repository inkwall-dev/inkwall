// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// handshake is a WebSocket handshake with headers kv (name, value, ...).
func handshake(kv ...string) *request.Request {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return &request.Request{Method: http.MethodGet, Host: "app.example.com", RawURI: "/chat", Headers: h}
}

func TestWebSocketHandshake(t *testing.T) {
	tests := []struct {
		name string
		req  *request.Request
		want bool
	}{
		{"browser", handshake("Upgrade", "websocket", "Connection", "Upgrade", "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version", "13"), true},
		// Traefik's ForwardAuth drops Upgrade and Connection.
		{"through ForwardAuth", handshake("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version", "13"), true},
		// RFC 8441 (HTTP/2) has no Sec-WebSocket-Key.
		{"over HTTP/2", handshake("Sec-WebSocket-Version", "13"), true},
		{"upgrade only, mixed case", handshake("Upgrade", "WebSocket"), true},
		{"upgrade list", handshake("Upgrade", "foo/1, websocket"), true},
		{"key only", handshake("Sec-WebSocket-Key", "x"), true},
		{"plain GET", handshake("Accept", "text/html"), false},
		{"h2c upgrade", handshake("Upgrade", "h2c", "Connection", "Upgrade, HTTP2-Settings"), false},
		{"websocket in another header", handshake("X-Upgrade", "websocket"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WebSocketHandshake(tt.req); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompileWebSocket(t *testing.T) {
	if w, err := CompileWebSocket(WebSocketConfig{}); w != nil || err != nil {
		t.Fatalf("empty config: %v, %v, want nil, nil", w, err)
	}
	if w, err := CompileWebSocket(WebSocketConfig{AllowMissingOrigin: true}); w != nil || err != nil {
		t.Fatalf("allowMissingOrigin alone: %v, %v, want nil, nil", w, err)
	}
	valid := []string{"https://app.example.com", "http://localhost:3000", "HTTPS://App.Example.COM", "https://*.example.com", "https://[::1]:8443", "https://10.0.0.1"}
	for _, o := range valid {
		if _, err := CompileWebSocket(WebSocketConfig{AllowedOrigins: []string{o}}); err != nil {
			t.Errorf("origin %q: %v", o, err)
		}
	}
	invalid := []string{"", "app.example.com", "ws://app.example.com", "https://", "https://app.example.com/", "https://app.example.com/chat",
		"https://user@app.example.com", "https://app.example.com:", "https://app.example.com:x", "https://*", "https://*.",
		"https://a.*.example.com", "https://*example.com", "https://app.example.com?x", "null", "*"}
	for _, o := range invalid {
		if _, err := CompileWebSocket(WebSocketConfig{AllowedOrigins: []string{o}}); err == nil {
			t.Errorf("origin %q: no error", o)
		}
	}
	for _, name := range []string{"", "X Api", "X-Api:", "é"} {
		if _, err := CompileWebSocket(WebSocketConfig{RequiredHeaders: []string{name}}); err == nil {
			t.Errorf("header %q: no error", name)
		}
	}
}

func TestWebSocketViolation(t *testing.T) {
	rules, err := CompileWebSocket(WebSocketConfig{
		AllowedOrigins: []string{"https://app.example.com", "http://localhost:3000", "https://*.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		origin []string
		ok     bool
	}{
		{[]string{"https://app.example.com"}, true},
		{[]string{"https://APP.example.com"}, true},
		{[]string{"HTTPS://app.example.com"}, true},
		{[]string{"https://app.example.com:443"}, true},
		{[]string{"http://localhost:3000"}, true},
		{[]string{"https://chat.example.net"}, true},
		{[]string{"https://a.b.example.net"}, true},
		// Not the bare domain of a wildcard, not another scheme or port.
		{[]string{"https://example.net"}, false},
		{[]string{"http://chat.example.net"}, false},
		{[]string{"https://chat.example.net:8443"}, false},
		{[]string{"http://app.example.com"}, false},
		{[]string{"https://app.example.com:8443"}, false},
		{[]string{"http://localhost"}, false},
		{[]string{"https://evil.example"}, false},
		{[]string{"https://app.example.com.evil.example"}, false},
		{[]string{"https://evilexample.net"}, false},
		{[]string{"null"}, false},
		{[]string{"https://app.example.com/path"}, false},
		{nil, false},
		{[]string{"https://app.example.com", "https://app.example.com"}, false},
	}
	for _, tt := range tests {
		r := handshake("Sec-WebSocket-Version", "13")
		for _, o := range tt.origin {
			r.Headers.Add("Origin", o)
		}
		if got := rules.violation(r) == ""; got != tt.ok {
			t.Errorf("origin %q: allowed %v, want %v (%s)", tt.origin, got, tt.ok, rules.violation(r))
		}
	}

	// A missing Origin, when allowed; a present one is still checked.
	rules, _ = CompileWebSocket(WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}, AllowMissingOrigin: true})
	if v := rules.violation(handshake()); v != "" {
		t.Errorf("missing origin allowed: %s", v)
	}
	if v := rules.violation(handshake("Origin", "https://evil.example")); v == "" {
		t.Error("allowMissingOrigin let another origin through")
	}

	// Required headers, any origin.
	rules, _ = CompileWebSocket(WebSocketConfig{RequiredHeaders: []string{"authorization", "X-Tenant"}})
	for _, tt := range []struct {
		kv []string
		ok bool
	}{
		{[]string{"Authorization", "Bearer x", "X-Tenant", "a", "Origin", "https://evil.example"}, true},
		{[]string{"Authorization", "Bearer x"}, false},
		{[]string{"Authorization", " ", "X-Tenant", "a"}, false},
		{nil, false},
	} {
		if got := rules.violation(handshake(tt.kv...)) == ""; got != tt.ok {
			t.Errorf("headers %q: allowed %v, want %v", tt.kv, got, tt.ok)
		}
	}
}

// TestWebSocketRules: a handshake that breaks the policy's WebSocket rules
// is denied with 403 in block mode, before the rules run, and logged in
// detect mode; other requests, and skipped routes, aren't affected.
func TestWebSocketRules(t *testing.T) {
	ws, err := CompileWebSocket(WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := router.New([]string{"/healthz"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := handshake("Sec-WebSocket-Version", "13", "Origin", "https://app.example.com")
	bad := handshake("Sec-WebSocket-Version", "13", "Origin", "https://evil.example")
	plain := handshake("Origin", "https://evil.example") // not a handshake
	skipped := handshake("Sec-WebSocket-Version", "13", "Origin", "https://evil.example")
	skipped.RawURI = "/healthz"

	tests := []struct {
		name       string
		mode       Mode
		eval       fakeEvaluator
		req        *request.Request
		wantAction Action
		wantStatus int
		wantReason Reason
	}{
		{"allowed origin", ModeBlock, fakeEvaluator{}, good, ActionAllow, 0, ReasonNone},
		{"forbidden origin", ModeBlock, fakeEvaluator{}, bad, ActionDeny, http.StatusForbidden, ReasonWebSocket},
		// The rules don't run: a hung evaluator would time out.
		{"forbidden origin, before the rules", ModeBlock, fakeEvaluator{block: hung(t)}, bad, ActionDeny, http.StatusForbidden, ReasonWebSocket},
		{"attack from an allowed origin", ModeBlock, fakeEvaluator{res: blocked}, good, ActionDeny, http.StatusForbidden, ReasonRule},
		{"not a handshake", ModeBlock, fakeEvaluator{}, plain, ActionAllow, 0, ReasonNone},
		{"skipped route", ModeBlock, fakeEvaluator{}, skipped, ActionAllow, 0, ReasonSkipped},
		{"detect: forbidden origin", ModeDetect, fakeEvaluator{}, bad, ActionLog, 0, ReasonWebSocket},
		// Detect mode runs the rules too: a match is the reason.
		{"detect: forbidden origin and an attack", ModeDetect, fakeEvaluator{res: blocked}, bad, ActionLog, 0, ReasonRule},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.eval, Config{Mode: tt.mode, WebSocket: ws, Routes: routes})
			v := p.Check(context.Background(), tt.req)
			if v.Action != tt.wantAction || v.Status != tt.wantStatus || v.Reason != tt.wantReason {
				t.Fatalf("got action=%s status=%d reason=%s, want action=%s status=%d reason=%s",
					v.Action, v.Status, v.Reason, tt.wantAction, tt.wantStatus, tt.wantReason)
			}
		})
	}
}
