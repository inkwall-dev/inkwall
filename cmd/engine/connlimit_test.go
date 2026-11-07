// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// TestLimitListener (#368): past --max-connections, a connection waits
// until one closes; reaching the limit is counted.
func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := telemetry.NewMetrics("proxy")
	ln := limitListener(inner, 2, m)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 3 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	first := <-accepted
	<-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection accepted past the limit of 2")
	case <-time.After(200 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close() // a second Close frees nothing more
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the third connection waits after one closed")
	}
	// The limit was reached twice: with the first two open, and again
	// once the third took the freed slot (the next Accept waits).
	time.Sleep(50 * time.Millisecond)
	got := scrape(t, m)
	if !strings.Contains(got, `inkwall_connection_limit_waits_total{adapter="proxy"} 2`) ||
		!strings.Contains(got, `inkwall_connections{adapter="proxy"} 2`) {
		t.Errorf("metrics:\n%s", got)
	}
}

func scrape(t *testing.T, m *telemetry.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.AdminHandler(nil).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

func TestLongLivedFlags(t *testing.T) {
	cfg, err := parseFlags(cmdProxy, []string{"--upstream", "http://app", "--max-connections", "100",
		"--websocket-idle-timeout", "5m", "--body-read-timeout", "10s"}, io.Discard)
	if err != nil || cfg.maxConnections != 100 || cfg.webSocketIdle != 5*time.Minute || cfg.bodyReadTimeout != 10*time.Second {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := parseFlags(cmdProxy, []string{"--upstream", "http://app", "--max-connections", "-1"}, io.Discard); err == nil {
		t.Error("a negative --max-connections accepted")
	}
	// Proxy only.
	if _, err := parseFlags(cmdForwardAuth, []string{"--max-connections", "10"}, io.Discard); err == nil {
		t.Error("--max-connections accepted by forward-auth")
	}
}
