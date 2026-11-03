// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// Shutdown while connections go idle between frames (#338): it must
// return, whatever the interleaving. Shutdown once held the server's lock
// while taking each connection's, and a connection going idle held its own
// while taking the server's: a deadlock, with every later frame and accept
// blocked too.
func TestShutdownWhileConnectionsGoIdle(t *testing.T) {
	for i := range 200 {
		srv, err := New(&inspector{verdict: pipeline.Verdict{}}, Config{Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(t.TempDir(), "spoe.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()

		// A few connections answer frames as fast as they come: each frame
		// takes the connection out of idle and back.
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			h := (&agent{sock: sock}).dial(t)
			h.hello()
			wg.Add(1)
			go func() {
				defer wg.Done()
				frame := notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/"), argBinary(ArgHeaders, hdrs("host", "a")))
				buf := make([]byte, 4096)
				for {
					select {
					case <-stop:
						return
					default:
					}
					_ = h.nc.SetDeadline(time.Now().Add(time.Second))
					if _, err := h.nc.Write(frame); err != nil {
						return
					}
					if _, err := h.nc.Read(buf); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(time.Duration(i%5) * time.Millisecond)

		shut := make(chan error, 1)
		go func() { shut <- srv.Shutdown(context.Background()) }()
		select {
		case <-shut:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: Shutdown deadlocked", i)
		}
		close(stop)
		wg.Wait()
		<-served
	}
}
