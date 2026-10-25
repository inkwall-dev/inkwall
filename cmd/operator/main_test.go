// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The manager itself is tested in operator/manager.

func TestFlags(t *testing.T) {
	var stderr strings.Builder
	if code := run([]string{"--help"}, &stderr); code != 0 {
		t.Errorf("--help: exit %d", code)
	}
	if !strings.Contains(stderr.String(), "-webhook-certs") {
		t.Errorf("--help does not list the flags:\n%s", stderr.String())
	}
	for _, args := range [][]string{{"--no-such-flag"}, {"extra"}, {"--webhook-certs", "cert-manager"}} {
		if code := run(args, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	t.Setenv("POD_NAMESPACE", "security")
	if o, err := parseFlags(nil, io.Discard); err != nil || o.Namespace != "security" {
		t.Errorf("namespace from POD_NAMESPACE: got %q, %v", o.Namespace, err)
	}
}

func TestDrain(t *testing.T) {
	signal, stop := context.WithCancel(context.Background())
	var draining atomic.Bool
	ctx := drain(signal, 200*time.Millisecond, &draining, slog.New(slog.DiscardHandler))
	if draining.Load() || ctx.Err() != nil {
		t.Fatal("draining before the signal")
	}
	stop()
	time.Sleep(50 * time.Millisecond)
	// Not ready, still serving.
	if !draining.Load() || ctx.Err() != nil {
		t.Fatalf("right after the signal: draining=%v, stopped=%v", draining.Load(), ctx.Err() != nil)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("not stopped after the delay")
	}
	if o, err := parseFlags(nil, io.Discard); err != nil || o.shutdownDelay != 5*time.Second {
		t.Errorf("default shutdown delay %v, %v", o.shutdownDelay, err)
	}
}
