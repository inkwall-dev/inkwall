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
	for _, args := range [][]string{{"--no-such-flag"}, {"extra"}, {"--webhook-certs", "cert-manager"},
		{"--signing-key-grace", "0s"}, {"--selector-restart-max-delay", "-1s"}} {
		if code := run(args, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	t.Setenv("POD_NAMESPACE", "security")
	if o, err := parseFlags(nil, io.Discard); err != nil || o.Namespace != "security" {
		t.Errorf("namespace from POD_NAMESPACE: got %q, %v", o.Namespace, err)
	}
	// The defaults are the production ones; e2e on kind shortens them.
	if o, err := parseFlags(nil, io.Discard); err != nil || o.SigningKeyGrace != time.Minute || o.SelectorRestartMaxDelay != 30*time.Second {
		t.Errorf("defaults: signing key grace %v, selector restart delay %v, %v", o.SigningKeyGrace, o.SelectorRestartMaxDelay, err)
	}
	o, err := parseFlags([]string{"--signing-key-grace=15s", "--selector-restart-max-delay=2s"}, io.Discard)
	if err != nil || o.SigningKeyGrace != 15*time.Second || o.SelectorRestartMaxDelay != 2*time.Second {
		t.Errorf("set: signing key grace %v, selector restart delay %v, %v", o.SigningKeyGrace, o.SelectorRestartMaxDelay, err)
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

// GOMEMLIMIT follows the container's memory limit (#213).
func TestMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want int64
	}{
		{map[string]string{MemoryLimitEnv: "536870912"}, 483183819},
		// Set by hand: the runtime applied it.
		{map[string]string{MemoryLimitEnv: "536870912", "GOMEMLIMIT": "300MiB"}, 0},
		{map[string]string{}, 0},
		{map[string]string{MemoryLimitEnv: "512Mi"}, 0},
		{map[string]string{MemoryLimitEnv: "0"}, 0},
	} {
		if got := memoryLimit(func(k string) string { return tc.env[k] }); got != tc.want {
			t.Errorf("%v: %d, want %d", tc.env, got, tc.want)
		}
	}
}
