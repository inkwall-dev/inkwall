// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var cfg *rest.Config

func TestMain(m *testing.M) {
	var (
		stop func()
		err  error
	)
	cfg, stop, err = testenv.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func TestFlags(t *testing.T) {
	var stderr strings.Builder
	if code := run([]string{"--help"}, &stderr); code != 0 {
		t.Errorf("--help: exit %d", code)
	}
	if !strings.Contains(stderr.String(), "-leader-elect") {
		t.Errorf("--help does not list the flags:\n%s", stderr.String())
	}
	if code := run([]string{"--no-such-flag"}, io.Discard); code != 2 {
		t.Errorf("unknown flag: exit %d, want 2", code)
	}
	if code := run([]string{"extra"}, io.Discard); code != 2 {
		t.Errorf("extra argument: exit %d, want 2", code)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestManagerStarts(t *testing.T) {
	testenv.Skip(t, cfg)
	probe := freeAddr(t)
	mgr, err := newManager(cfg, options{metricsAddr: "0", probeAddr: probe, leaderElect: true, leaderNS: "default"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()

	// Ready, and leading: with one replica the election is won at once.
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get("http://" + probe + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ready after 20s (last error: %v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-mgr.Elected():
	case <-time.After(20 * time.Second):
		t.Fatal("not elected leader after 20s")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("manager stopped with %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("manager did not stop after 20s")
	}
}
