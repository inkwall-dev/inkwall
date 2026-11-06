// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// TestWebSocketMessageScope: a message is evaluated on its own (#363):
// its text as arguments, with the handshake's identity and path (for
// exclusions) but none of its query arguments or headers.
func TestWebSocketMessageScope(t *testing.T) {
	eval := &recordingEvaluator{}
	p := New(eval, Config{Mode: ModeBlock})
	hs := &request.Request{
		ID: "req-1", Proto: "HTTP/1.1", Method: http.MethodGet, Scheme: "https", Host: "app.example.com",
		RawURI: "/chat/room?token=1%27%20OR%201", ClientIP: netip.MustParseAddr("198.51.100.7"),
		PeerIP:  netip.MustParseAddr("127.0.0.1"),
		Headers: http.Header{"User-Agent": {"sqlmap/1.8"}, "Cookie": {"session=1' OR '1'='1"}, "Sec-Websocket-Key": {"x"}},
	}
	p.CheckWebSocketMessage(context.Background(), hs, []byte("hello"), false)
	got := eval.got
	if got == nil {
		t.Fatal("not evaluated")
	}
	if got.ID != "req-1" || got.ClientIP != hs.ClientIP || got.PeerIP != hs.PeerIP || got.Host != hs.Host {
		t.Errorf("identity lost: %+v", got)
	}
	if got.RawURI != "/chat/room" {
		t.Errorf("RawURI %q, want the handshake's path without its query", got.RawURI)
	}
	for _, h := range []string{"User-Agent", "Cookie", "Sec-Websocket-Key"} {
		if v := got.Headers.Get(h); v != "" && v == hs.Headers.Get(h) {
			t.Errorf("the handshake's %s (%q) is evaluated again with the message", h, v)
		}
	}
	if len(got.WebSocketText) != 1 || got.WebSocketText[0].Value != "hello" {
		t.Errorf("message arguments %+v", got.WebSocketText)
	}
	if hs.RawURI != "/chat/room?token=1%27%20OR%201" || hs.Headers.Get("User-Agent") != "sqlmap/1.8" {
		t.Error("the handshake was modified")
	}
}
