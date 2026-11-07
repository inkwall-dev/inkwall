// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"sync"

	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// limitListener accepts at most max connections at a time (--max-connections,
// #368): past it, Accept waits until one closes, so the next client waits in
// the kernel's backlog; each wait is counted in
// inkwall_connection_limit_waits_total. A WebSocket's connection counts until
// it closes.
func limitListener(l net.Listener, max int, m *telemetry.Metrics) net.Listener {
	return &limited{Listener: l, slots: make(chan struct{}, max), metrics: m, done: make(chan struct{})}
}

type limited struct {
	net.Listener
	slots   chan struct{}
	metrics *telemetry.Metrics
	once    sync.Once
	done    chan struct{}
}

func (l *limited) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	default:
		l.metrics.ConnectionLimitWait()
		select {
		case l.slots <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.slots }, closed: l.metrics.ConnectionOpened()}, nil
}

func (l *limited) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
	closed  func()
}

func (c *limitedConn) Close() error {
	c.once.Do(func() {
		c.release()
		c.closed()
	})
	return c.Conn.Close()
}
