// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitForBootstrap: /readyz waits for the first bundle and the country
// table it names, within --bootstrap-timeout, then turns ready either way.
func TestWaitForBootstrap(t *testing.T) {
	cfg := engineConfig{bootstrapTimeout: 100 * time.Millisecond}
	log := slog.New(slog.DiscardHandler)
	wait := func(applied, geo chan struct{}) (*atomic.Bool, chan struct{}) {
		var ready atomic.Bool
		done := make(chan struct{})
		go func() { waitForBootstrap(context.Background(), applied, geo, cfg, &ready, log); close(done) }()
		return &ready, done
	}
	closed := func() chan struct{} { c := make(chan struct{}); close(c); return c }

	// Bundle and table: ready at once.
	ready, done := wait(closed(), closed())
	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("not ready with the bundle and its table")
	}
	if !ready.Load() {
		t.Fatal("not ready")
	}

	// The bundle, not its table: unready until the timeout, then ready.
	geo := make(chan struct{})
	ready, done = wait(closed(), geo)
	time.Sleep(50 * time.Millisecond)
	if ready.Load() {
		t.Fatal("ready before the table or the timeout")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("still unready after the timeout")
	}
	if !ready.Load() {
		t.Fatal("not ready after the timeout")
	}
	// Ready stays: nothing turns it back for the table.
	close(geo)
	time.Sleep(10 * time.Millisecond)
	if !ready.Load() {
		t.Fatal("unready after the table came")
	}

	// No bundle at all: ready after the timeout too.
	ready, done = wait(make(chan struct{}), make(chan struct{}))
	<-done
	if !ready.Load() {
		t.Fatal("not ready after the timeout without a bundle")
	}
}
