// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// A denied gRPC call gets, besides the HTTP status, the gRPC status, its
// message and the content type HAProxy answers it with (trailers-only),
// as the other adapters answer one (#303). Other requests get none.
func TestGRPCDenial(t *testing.T) {
	insp := &inspector{verdict: pipeline.Verdict{Action: pipeline.ActionDeny, Status: http.StatusForbidden, Reason: pipeline.ReasonRule}}
	a := startAgent(t, insp, Config{MaxBodyBytes: 1 << 10})
	h := a.dial(t)
	h.hello()
	for _, c := range []struct {
		name, contentType, status, ctype string
	}{
		{"grpc", "application/grpc+proto", "7", "application/grpc"},
		{"grpc-web", "application/grpc-web", "7", "application/grpc-web"},
		{"grpc-web-text", "application/grpc-web-text", "7", "application/grpc-web-text"},
		{"not grpc", "application/json", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.send(notifyFrame(1, 1,
				argString(ArgMethod, "POST"), argString(ArgPath, "/pkg.Svc/Call"), argString(ArgVersion, "2.0"),
				argBinary(ArgHeaders, hdrs("host", "a.example", "content-type", c.contentType, "x-request-id", "req-9", "content-length", "0")),
			))
			_, vars := h.ack()
			if vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 403 {
				t.Fatalf("variables %+v", vars)
			}
			st, ok := vars[VarGRPCStatus]
			if c.status == "" {
				if ok || vars[VarGRPCMessage].typ != 0 || vars[VarGRPCContentType].typ != 0 {
					t.Fatalf("gRPC variables for a plain request: %+v", vars)
				}
				return
			}
			if !ok || st.typ != typeInt32 || st.u != 7 {
				t.Errorf("grpc_status %+v, want 7", st)
			}
			if got := vars[VarGRPCMessage].String(); got != "Forbidden (request ID req-9)" {
				t.Errorf("grpc_message %q", got)
			}
			if got := vars[VarGRPCContentType].String(); got != c.ctype {
				t.Errorf("grpc_content_type %q, want %q", got, c.ctype)
			}
		})
	}

	// An allowed gRPC call gets no gRPC status.
	insp.mu.Lock()
	insp.verdict = pipeline.Verdict{}
	insp.mu.Unlock()
	h.send(notifyFrame(1, 2,
		argString(ArgMethod, "POST"), argString(ArgPath, "/pkg.Svc/Call"),
		argBinary(ArgHeaders, hdrs("host", "a.example", "content-type", "application/grpc", "content-length", "0")),
	))
	if _, vars := h.ack(); vars[VarAction].String() != ActionAllow || vars[VarGRPCStatus].typ != 0 {
		t.Errorf("variables %+v", vars)
	}
}

// The policy's WebSocket rules apply to a handshake HAProxy asks about:
// HAProxy keeps the Upgrade header, and asks before it upgrades.
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
	handshake := func(kv ...string) []byte {
		h := []string{"host", "app.example.com", "upgrade", "websocket", "connection", "Upgrade",
			"sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==", "sec-websocket-version", "13"}
		return notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/chat"),
			argString(ArgVersion, "1.1"), argBinary(ArgHeaders, hdrs(append(h, kv...)...)))
	}
	origin, proto := []string{"origin", "https://app.example.com"}, []string{"sec-websocket-protocol", "chat"}
	tests := []struct {
		name  string
		frame []byte
		deny  bool
	}{
		{"allowed", handshake(append(origin, proto...)...), false},
		{"forbidden origin", handshake("origin", "https://evil.example", "sec-websocket-protocol", "chat"), true},
		{"no origin", handshake(proto...), true},
		{"missing required header", handshake(origin...), true},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		a := startAgent(t, pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second, WebSocket: ws}), Config{MaxBodyBytes: 1 << 10})
		h := a.dial(t)
		h.hello()
		for _, tt := range tests {
			h.send(tt.frame)
			_, vars := h.ack()
			want := ActionAllow
			if tt.deny && mode == pipeline.ModeBlock {
				want = ActionDeny
			}
			if got := vars[VarAction].String(); got != want {
				t.Errorf("mode %d, %s: %s, want %s", mode, tt.name, got, want)
			}
			if want == ActionDeny && vars[VarStatus].u != 403 {
				t.Errorf("mode %d, %s: status %d", mode, tt.name, vars[VarStatus].u)
			}
		}
	}
}
