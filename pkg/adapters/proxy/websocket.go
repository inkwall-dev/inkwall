// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"unicode/utf8"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/websocket"
)

// messageInspector inspects a WebSocket's messages: the pipeline of a
// policy from flags. A bundle's policies (pkg/policy) don't, yet.
type messageInspector interface {
	CheckWebSocketMessage(ctx context.Context, handshake *request.Request, text []byte, truncated bool) pipeline.Verdict
	Mode() pipeline.Mode
}

// inspectingWriter hands ReverseProxy a connection whose client side is
// inspected, when it hijacks it for the upgrade.
type inspectingWriter struct {
	http.ResponseWriter
	h   *Handler
	ctx context.Context
	req *request.Request
	// path is the handshake's path, for events.
	path string
	mi   messageInspector
}

func (w *inspectingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack hijacks the client's connection and wraps it: what ReverseProxy
// reads from it, to copy to the upstream, is only what was inspected.
func (w *inspectingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// Bytes the server read ahead are in brw.Reader: read through it.
	c := &inspectedConn{
		Conn:   conn,
		w:      w,
		frames: websocket.NewReader(brw.Reader, w.h.maxBody),
		block:  w.mi.Mode() == pipeline.ModeBlock,
	}
	return c, brw, nil
}

// inspectedConn is the client's side of an upgraded WebSocket. Read
// returns the client's frames once inspected: in block mode, a data
// message is held until it is whole and inspected; in detect mode, frames
// pass at once and a copy is inspected. Write passes the upstream's bytes
// to the client, and follows its frames, so that a close frame of the
// proxy's own goes between two of them. Embedding net.Conn (an interface)
// hides the connection's ReadFrom and WriteTo, so io.Copy goes through
// Read and Write.
type inspectedConn struct {
	net.Conn
	w      *inspectingWriter
	frames *websocket.Reader
	block  bool

	out []byte // bytes ready for the upstream
	err error  // returned once out is empty

	held      []byte // block mode: the raw frames of the open data message
	text      []byte // its payload, up to the limit
	opcode    byte
	truncated bool // the open message went past the limit
	streaming bool // block mode: past the limit and allowed, it passes as it comes

	wmu     sync.Mutex
	tracker websocket.Tracker
	closing []byte // a close frame for the client, sent at the next boundary
	closed  bool   // the close frame was sent: the upstream's bytes are dropped
}

func (c *inspectedConn) Read(p []byte) (int, error) {
	for {
		if len(c.out) > 0 {
			n := copy(p, c.out)
			c.out = c.out[n:]
			return n, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		if c.frames.Pending() > 0 {
			// The rest of a frame past the limit, allowed (frame decided
			// at the limit): it passes as it comes.
			n, err := c.frames.ReadRest(p)
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return n, err
		}
		f, err := c.frames.Next()
		if err != nil {
			var we *websocket.Error
			if errors.As(err, &we) {
				// The upstream would fail the connection too (RFC 6455
				// §7.1.7): in either mode, it closes.
				c.violation(we.Code, we.Reason, true)
				continue
			}
			return 0, err
		}
		c.frame(f)
	}
}

// frame handles one frame of the client's.
func (c *inspectedConn) frame(f *websocket.Frame) {
	if f.Control() {
		// Control frames may come between a message's fragments: they pass
		// at once, ahead of what is held.
		c.out = append(c.out, f.Raw...)
		return
	}
	if f.Opcode != websocket.OpContinuation {
		c.held, c.text, c.opcode, c.truncated, c.streaming = c.held[:0], c.text[:0], f.Opcode, false, false
	}
	c.text = append(c.text, f.Payload...)
	if !c.block || c.streaming {
		c.out = append(c.out, f.Raw...)
	} else {
		c.held = append(c.held, f.Raw...)
	}
	if f.Truncated && !c.truncated {
		c.truncated = true
		// Past the limit: decided on what came, as an oversized body.
		switch {
		case c.opcode == websocket.OpText:
			if !c.inspect(true) {
				return
			}
		case c.w.h.messages == pipeline.MessagesTextOnly:
			if !c.violation(websocket.CloseUnsupportedData, "binary message", c.block) {
				return
			}
		}
		if c.block {
			// Allowed: what is held passes, and the rest as it comes.
			c.out = append(c.out, c.held...)
			c.held = c.held[:0]
			c.streaming = true
		}
	}
	if !f.Fin || c.truncated {
		return
	}
	switch {
	case c.opcode == websocket.OpBinary && c.w.h.messages == pipeline.MessagesTextOnly:
		if !c.violation(websocket.CloseUnsupportedData, "binary message", c.block) {
			return
		}
	case c.opcode == websocket.OpText && !utf8.Valid(c.text):
		if !c.violation(websocket.CloseInvalidPayload, "text message not UTF-8", c.block) {
			return
		}
	case c.opcode == websocket.OpText:
		if !c.inspect(false) {
			return
		}
	}
	if c.block {
		c.out = append(c.out, c.held...)
		c.held = c.held[:0]
	}
}

// inspect inspects the open text message, and reports whether it passes.
// A denied one closes the connection.
func (c *inspectedConn) inspect(truncated bool) bool {
	w := c.w
	v := w.mi.CheckWebSocketMessage(w.ctx, w.req, c.text, truncated)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(w.ctx, w.h.logger, w.h.events, w.req, w.path, v)
	}
	if v.Action != pipeline.ActionDeny {
		return true
	}
	code := websocket.ClosePolicyViolation
	if v.Reason == pipeline.ReasonOversize {
		code = websocket.CloseMessageTooBig
	}
	c.close(code, "denied by policy")
	return false
}

// violation reports a message the policy can't inspect, or a frame that
// breaks the protocol, as a security event with reason websocket. With
// closing, the connection closes with code; it reports whether the message
// passes.
func (c *inspectedConn) violation(code int, reason string, closing bool) bool {
	w := c.w
	v := pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonWebSocket}
	if closing {
		v.Action = pipeline.ActionDeny
	}
	httpadapter.LogEvent(w.ctx, w.h.logger, w.h.events, w.req, w.path, v)
	if !closing {
		return true
	}
	c.close(code, reason)
	return false
}

// close ends the connection with code: a close frame to the upstream, as
// if the client sent it, and one to the client, at the next boundary
// between the upstream's frames. Nothing more of the client's passes.
func (c *inspectedConn) close(code int, reason string) {
	var key [4]byte
	_, _ = rand.Read(key[:])
	c.held, c.text = nil, nil
	c.out = append(c.out, websocket.CloseFrame(code, reason, &key)...)
	c.err = io.EOF

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing != nil || c.closed {
		return
	}
	c.closing = websocket.CloseFrame(code, reason, nil)
	if c.tracker.AtBoundary() {
		c.sendClose()
	}
}

// sendClose sends the close frame to the client; wmu is held.
func (c *inspectedConn) sendClose() {
	_, _ = c.Conn.Write(c.closing)
	c.closed = true
}

// Write passes the upstream's bytes to the client, up to the close frame
// of the proxy's own once there is one.
func (c *inspectedConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return len(p), nil
	}
	b := p
	for len(b) > 0 {
		n := c.tracker.Split(b)
		if _, err := c.Conn.Write(b[:n]); err != nil {
			return len(p) - len(b), err
		}
		b = b[n:]
		if c.closing != nil && c.tracker.AtBoundary() {
			c.sendClose()
			return len(p), nil
		}
	}
	return len(p), nil
}
