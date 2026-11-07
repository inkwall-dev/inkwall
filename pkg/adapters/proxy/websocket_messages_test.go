// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	xws "golang.org/x/net/websocket"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
	"github.com/inkwall-dev/inkwall/pkg/websocket"
)

// wsUpstream echoes every message and records what it received, and the
// handshake's Sec-WebSocket-Extensions.
type wsUpstream struct {
	mu         sync.Mutex
	got        []string
	extensions []string
}

func (u *wsUpstream) received() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.got...)
}

func newWSProxy(t *testing.T, mode pipeline.Mode, messages pipeline.WebSocketMessages, oversize pipeline.OversizeAction, maxBody int64) (*wsUpstream, string, *bytes.Buffer) {
	t.Helper()
	return newWSProxyMetrics(t, mode, messages, oversize, maxBody, nil)
}

func newWSProxyMetrics(t *testing.T, mode pipeline.Mode, messages pipeline.WebSocketMessages, oversize pipeline.OversizeAction, maxBody int64,
	m *telemetry.Metrics) (*wsUpstream, string, *bytes.Buffer) {
	t.Helper()
	u, addr, logs, _ := newWSProxyWith(t, mode, messages, oversize, maxBody, m, nil)
	return u, addr, logs
}

// newWSProxyWith is newWSProxyMetrics with the proxy's Config changed by
// with, and the Handler.
func newWSProxyWith(t *testing.T, mode pipeline.Mode, messages pipeline.WebSocketMessages, oversize pipeline.OversizeAction, maxBody int64,
	m *telemetry.Metrics, with func(*Config)) (*wsUpstream, string, *bytes.Buffer, *Handler) {
	t.Helper()
	u := &wsUpstream{}
	echo := xws.Server{
		Handshake: func(_ *xws.Config, r *http.Request) error {
			u.mu.Lock()
			u.extensions = r.Header.Values("Sec-Websocket-Extensions")
			u.mu.Unlock()
			return nil
		},
		Handler: func(c *xws.Conn) {
			for {
				var m []byte
				if err := xws.Message.Receive(c, &m); err != nil {
					return
				}
				u.mu.Lock()
				u.got = append(u.got, string(m))
				u.mu.Unlock()
				if c.PayloadType == xws.BinaryFrame {
					_ = xws.Message.Send(c, m)
				} else {
					_ = xws.Message.Send(c, string(m))
				}
			}
		},
	}
	up := httptest.NewServer(echo)
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	pcfg := pipeline.Config{Mode: mode, Oversize: oversize, Timeout: 10 * time.Second}
	if m != nil {
		pcfg.Observer = m
	}
	cfg := Config{Upstream: upURL, MaxBodyBytes: maxBody, WebSocketMessages: messages, Logger: slog.New(slog.NewJSONHandler(&syncWriter{w: &logs}, nil)), Metrics: m}
	if with != nil {
		with(&cfg)
	}
	h, err := New(pipeline.New(eval, pcfg), cfg)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)
	return u, strings.TrimPrefix(front.URL, "http://"), &logs, h
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// wsClient is a raw WebSocket client: it writes the frames it is given.
type wsClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialWS(t *testing.T, addr string) *wsClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /chat HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: http://app.example.com\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n")
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// A 101's body is the connection: nothing to read here.
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %s", resp.Status)
	}
	return &wsClient{conn: conn, r: r}
}

var testKey = [4]byte{1, 2, 3, 4}

func clientFrame(fin bool, op byte, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	f := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		f = append(f, 0x80|byte(n))
	default:
		f = append(f, 0x80|126, byte(n>>8), byte(n))
	}
	f = append(f, testKey[:]...)
	p := append([]byte(nil), payload...)
	websocket.Mask(testKey, 0, p)
	return append(f, p...)
}

func (c *wsClient) send(t *testing.T, frames ...[]byte) {
	t.Helper()
	for _, f := range frames {
		if _, err := c.conn.Write(f); err != nil {
			t.Fatal(err)
		}
	}
}

// next reads the server's next frame: opcode and payload.
func (c *wsClient) next() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var e [2]byte
		if _, err := io.ReadFull(c.r, e[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(e[:]))
	}
	p := make([]byte, n)
	_, err := io.ReadFull(c.r, p)
	return h[0] & 0x0f, p, err
}

// closed expects a close frame with code, and then the end of the
// connection.
func (c *wsClient) closed(t *testing.T, code int) {
	t.Helper()
	for {
		op, p, err := c.next()
		if err != nil {
			t.Fatalf("no close frame: %v", err)
		}
		if op != websocket.OpClose {
			continue
		}
		if len(p) < 2 || int(binary.BigEndian.Uint16(p)) != code {
			t.Fatalf("close % x, want code %d", p, code)
		}
		break
	}
	if _, _, err := c.next(); err == nil {
		t.Fatal("the connection is still open")
	}
}

func (c *wsClient) echoes(t *testing.T, want string) {
	t.Helper()
	op, p, err := c.next()
	if err != nil || op == websocket.OpClose || string(p) != want {
		t.Fatalf("got op %d %q %v, want the echo %q", op, p, err, want)
	}
}

const sqli = `{"q":"1' OR '1'='1' -- "}`

// TestWebSocketMessages: the engine's proxy inspects a client's text
// messages before the upstream gets them (#276). In block mode a denied
// message closes the connection with 1008 and never reaches the upstream.
func TestWebSocketMessages(t *testing.T) {
	t.Run("clean messages echo, an attack closes with 1008", func(t *testing.T) {
		u, addr, logs := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, []byte(`{"text":"hello"}`)))
		c.echoes(t, `{"text":"hello"}`)
		c.send(t, clientFrame(true, websocket.OpText, []byte(sqli)), clientFrame(true, websocket.OpText, []byte("after")))
		c.closed(t, websocket.ClosePolicyViolation)
		if got := u.received(); len(got) != 1 {
			t.Fatalf("upstream got %q, want only the clean message", got)
		}
		if !strings.Contains(logs.String(), `"reason":"rule"`) || !strings.Contains(logs.String(), `"action":"deny"`) {
			t.Fatalf("events: %s", logs.String())
		}
		u.mu.Lock()
		ext := u.extensions
		u.mu.Unlock()
		if len(ext) != 0 {
			t.Fatalf("upstream got Sec-WebSocket-Extensions %q: permessage-deflate must not be negotiated", ext)
		}
	})
	t.Run("fragments are held until the message is whole", func(t *testing.T) {
		u, addr, _ := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(false, websocket.OpText, []byte("Hel")), clientFrame(true, websocket.OpPing, []byte("p")),
			clientFrame(true, websocket.OpContinuation, []byte("lo")))
		// The test's upstream (x/net/websocket) takes each fragment for a
		// message, and echoes it as such.
		var echoed string
		for echoed != "Hello" {
			op, p, err := c.next()
			if err != nil || len(echoed) > 5 {
				t.Fatalf("echoed %q, %v", echoed, err)
			}
			if op != websocket.OpPong {
				echoed += string(p)
			}
		}
		// An attack split across fragments is one message.
		c.send(t, clientFrame(false, websocket.OpText, []byte(`{"q":"1' OR `)), clientFrame(true, websocket.OpContinuation, []byte(`'1'='1' -- "}`)))
		c.closed(t, websocket.ClosePolicyViolation)
		if got := u.received(); strings.Join(got, "") != "Hello" {
			t.Fatalf("upstream got %q", got)
		}
	})
	t.Run("binary passes; text-only closes with 1003", func(t *testing.T) {
		_, addr, _ := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpBinary, []byte(sqli)))
		c.echoes(t, sqli)
		_, addr, _ = newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesTextOnly, pipeline.OversizeAuto, 4096)
		c = dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpBinary, []byte{1, 2, 3}))
		c.closed(t, websocket.CloseUnsupportedData)
	})
	t.Run("invalid UTF-8 closes with 1007", func(t *testing.T) {
		_, addr, _ := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, []byte{0xff, 0xfe}))
		c.closed(t, websocket.CloseInvalidPayload)
	})
	t.Run("an unmasked frame closes with 1002", func(t *testing.T) {
		_, addr, logs := newWSProxy(t, pipeline.ModeDetect, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, []byte{0x81, 0x02, 'h', 'i'})
		c.closed(t, websocket.CloseProtocolError)
		if !strings.Contains(logs.String(), `"reason":"websocket"`) {
			t.Fatalf("events: %s", logs.String())
		}
	})
	t.Run("over the limit: 1009, or passes when oversize is allowed", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), 200)
		_, addr, _ := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 64)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, big))
		c.closed(t, websocket.CloseMessageTooBig)

		u, addr, _ := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAllow, 64)
		c = dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, big))
		c.echoes(t, string(big))
		if got := u.received(); len(got) != 1 || got[0] != string(big) {
			t.Fatalf("upstream got %d messages", len(got))
		}
		// An attack in the inspected part still closes.
		c.send(t, clientFrame(true, websocket.OpText, append([]byte(sqli), big...)))
		c.closed(t, websocket.ClosePolicyViolation)
	})
	t.Run("detect mode: an attack passes and is logged", func(t *testing.T) {
		u, addr, logs := newWSProxy(t, pipeline.ModeDetect, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, []byte(sqli)))
		c.echoes(t, sqli)
		if got := u.received(); len(got) != 1 {
			t.Fatalf("upstream got %q", got)
		}
		if !strings.Contains(logs.String(), `"action":"log"`) || !strings.Contains(logs.String(), `"reason":"rule"`) {
			t.Fatalf("events: %s", logs.String())
		}
	})
	t.Run("off: messages pass uninspected", func(t *testing.T) {
		_, addr, logs := newWSProxy(t, pipeline.ModeBlock, pipeline.MessagesOff, pipeline.OversizeAuto, 4096)
		c := dialWS(t, addr)
		c.send(t, clientFrame(true, websocket.OpText, []byte(sqli)))
		c.echoes(t, sqli)
		if logs.Len() != 0 {
			t.Fatalf("events: %s", logs.String())
		}
	})
}

// The proxy counts its open WebSockets, inspected or not, their messages
// apart from requests, and the violations that close them (#356).
func TestWebSocketMetrics(t *testing.T) {
	waitGauge := func(t *testing.T, m *telemetry.Metrics, want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			body := scrapeMetrics(t, m)
			if strings.Contains(body, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("metrics never had %q:\n%s", want, body)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Run("inspected", func(t *testing.T) {
		m := telemetry.NewMetrics("proxy")
		_, addr, logs := newWSProxyMetrics(t, pipeline.ModeBlock, pipeline.MessagesInspect, pipeline.OversizeAuto, 4096, m)
		c := dialWS(t, addr)
		waitGauge(t, m, `inkwall_websocket_connections{adapter="proxy"} 1`)
		c.send(t, clientFrame(true, websocket.OpText, []byte("hello")))
		c.echoes(t, "hello")
		c.send(t, clientFrame(true, websocket.OpText, []byte{0xff, 0xfe}))
		c.closed(t, websocket.CloseInvalidPayload)
		waitGauge(t, m, `inkwall_websocket_connections{adapter="proxy"} 0`)
		if !strings.Contains(logs.String(), `"phase":"websocket_message"`) {
			t.Errorf("the violation's event: %s", logs.String())
		}
		body := scrapeMetrics(t, m)
		for _, want := range []string{
			`inkwall_websocket_messages_total{action="allow",adapter="proxy"} 1`,
			`inkwall_websocket_violations_total{adapter="proxy",code="1007"} 1`,
			// The handshake only.
			`inkwall_requests_total{action="allow",adapter="proxy",reason="none"} 1`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("metrics missing %q", want)
			}
		}
	})
	t.Run("uninspected", func(t *testing.T) {
		m := telemetry.NewMetrics("proxy")
		_, addr, _ := newWSProxyMetrics(t, pipeline.ModeBlock, pipeline.MessagesOff, pipeline.OversizeAuto, 4096, m)
		c := dialWS(t, addr)
		waitGauge(t, m, `inkwall_websocket_connections{adapter="proxy"} 1`)
		_ = c.conn.Close()
		waitGauge(t, m, `inkwall_websocket_connections{adapter="proxy"} 0`)
	})
}

func scrapeMetrics(t *testing.T, m *telemetry.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.AdminHandler(nil).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}
