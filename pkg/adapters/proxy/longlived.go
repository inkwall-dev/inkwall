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
	"sync/atomic"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/websocket"
)

// Long-lived connections (#368). Once ReverseProxy hijacks a WebSocket's
// connection, the server's deadlines and its Shutdown no longer apply to
// it: liveConn closes it when it idles past WebSocketIdleTimeout, and
// CloseWebSockets on shutdown, with 1001 (going away) both ways.

// liveWriter wraps the connection ReverseProxy hijacks for a WebSocket in
// a liveConn.
type liveWriter struct {
	http.ResponseWriter
	h *Handler
}

func (w *liveWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *liveWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return w.h.track(conn), brw, nil
}

// liveConns are the open WebSockets of a Handler.
type liveConns struct {
	mu    sync.Mutex
	conns map[*liveConn]struct{}
	empty chan struct{} // closed when conns becomes empty; nil while it is
}

func (l *liveConns) add(c *liveConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns == nil {
		l.conns = map[*liveConn]struct{}{}
	}
	if len(l.conns) == 0 {
		l.empty = make(chan struct{})
	}
	l.conns[c] = struct{}{}
}

func (l *liveConns) remove(c *liveConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.conns[c]; !ok {
		return
	}
	delete(l.conns, c)
	if len(l.conns) == 0 {
		close(l.empty)
		l.empty = nil
	}
}

// CloseWebSockets sends 1001 (going away) to the open WebSockets, both
// ways, and waits until they are closed or ctx ends: the http.Server's
// Shutdown doesn't see them once hijacked.
func (h *Handler) CloseWebSockets(ctx context.Context) error {
	h.live.mu.Lock()
	conns := make([]*liveConn, 0, len(h.live.conns))
	for c := range h.live.conns {
		conns = append(conns, c)
	}
	empty := h.live.empty
	h.live.mu.Unlock()
	if empty == nil {
		return nil
	}
	for _, c := range conns {
		c.goAway()
	}
	select {
	case <-empty:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// live wraps a hijacked WebSocket connection: what ReverseProxy reads from
// it goes to the upstream, what it writes goes to the client.
func (h *Handler) track(conn net.Conn) net.Conn {
	c := &liveConn{Conn: conn, set: &h.live, idle: h.wsIdle}
	c.touch()
	h.live.add(c)
	if c.idle > 0 {
		c.timer.Store(time.AfterFunc(c.idle, c.checkIdle))
	}
	return c
}

// liveConn is a WebSocket's client connection, as ReverseProxy relays it.
type liveConn struct {
	net.Conn
	set   *liveConns
	idle  time.Duration
	timer atomic.Pointer[time.Timer]
	last  atomic.Int64 // UnixNano of the last bytes either way

	away atomic.Bool // going away: Read ends the client's side

	// The client's side, read by ReverseProxy's one copier.
	in     websocket.Tracker // the bytes passed to the upstream
	ended  bool              // the client's side is over
	ending []byte            // what is left of the close frame for the upstream

	wmu     sync.Mutex
	out     websocket.Tracker // the bytes passed to the client
	pending bool              // a close frame for the client, at the next boundary
	closed  bool              // our close frame went to the client: drop the rest

	closeOnce sync.Once
}

func (c *liveConn) touch() { c.last.Store(time.Now().UnixNano()) }

// checkIdle closes the connection once it is idle for c.idle, or checks
// again when it would be.
func (c *liveConn) checkIdle() {
	if c.away.Load() {
		return
	}
	idle := time.Since(time.Unix(0, c.last.Load()))
	if idle < c.idle {
		c.timer.Load().Reset(c.idle - idle)
		return
	}
	c.goAway()
}

// goAway closes the WebSocket with 1001: a close frame to the client
// between two of the upstream's frames (at once, or after the frame being
// written), and one to the upstream, as if the client sent it, then the
// end of the client's side, which ends ReverseProxy's relay.
func (c *liveConn) goAway() {
	if c.away.Swap(true) {
		return
	}
	c.wmu.Lock()
	if !c.closed {
		c.pending = true
		if c.out.AtBoundary() {
			c.sendClose()
		}
	}
	c.wmu.Unlock()
	// Wake the Read blocked on the client.
	_ = c.SetReadDeadline(time.Unix(1, 0))
}

func (c *liveConn) Read(p []byte) (int, error) {
	if c.away.Load() {
		return c.end(p)
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
		for b := p[:n]; len(b) > 0; {
			b = b[c.in.Split(b):]
		}
	}
	if err != nil && c.away.Load() {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if n > 0 {
				return n, nil
			}
			return c.end(p)
		}
	}
	return n, err
}

// end returns the close frame for the upstream, if the client's side is
// between two frames, and then io.EOF.
func (c *liveConn) end(p []byte) (int, error) {
	if !c.ended {
		c.ended = true
		if c.in.AtBoundary() {
			var key [4]byte
			_, _ = rand.Read(key[:])
			c.ending = websocket.CloseFrame(websocket.CloseGoingAway, "", &key)
		}
	}
	if len(c.ending) > 0 {
		n := copy(p, c.ending)
		c.ending = c.ending[n:]
		return n, nil
	}
	return 0, io.EOF
}

func (c *liveConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return len(p), nil
	}
	c.touch()
	for b := p; len(b) > 0; {
		n := c.out.Split(b)
		if _, err := c.Conn.Write(b[:n]); err != nil {
			return len(p) - len(b), err
		}
		b = b[n:]
		if c.pending && c.out.AtBoundary() {
			c.sendClose()
			break
		}
	}
	return len(p), nil
}

// sendClose sends the client 1001; wmu is held.
func (c *liveConn) sendClose() {
	_, _ = c.Conn.Write(websocket.CloseFrame(websocket.CloseGoingAway, "", nil))
	c.closed = true
}

func (c *liveConn) Close() error {
	c.closeOnce.Do(func() {
		if t := c.timer.Load(); t != nil {
			t.Stop()
		}
		c.set.remove(c)
	})
	return c.Conn.Close()
}
