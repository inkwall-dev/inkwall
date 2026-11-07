// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

func attack(q string) *request.Request {
	return &request.Request{Method: http.MethodGet, Proto: "HTTP/1.1", Host: "app", RawURI: "/?q=" + q,
		Headers: http.Header{"User-Agent": {"Mozilla/5.0"}, "Accept": {"*/*"}}}
}

// TestRulesReload (#359): a SIGHUP recompiles --rules and swaps them in;
// requests under load during the swap all get a verdict from one set or
// the other; an invalid file keeps the old rules; --watch-rules reloads
// once on a ConfigMap-style symlink swap.
func TestRulesReload(t *testing.T) {
	dir := t.TempDir()
	// A ConfigMap volume: rules.conf -> ..data/rules.conf, ..data -> a
	// timestamped directory, swapped atomically on an update.
	write := func(name, rules string) {
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "rules.conf"), []byte(rules), 0o600); err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(dir, "..data_tmp")
		_ = os.Remove(tmp)
		if err := os.Symlink(name, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	rule := func(word string, id string) string {
		return `SecRule ARGS "@contains ` + word + `" "id:` + id + `,phase:2,deny,status:403,log"`
	}
	write("v1", rule("alpha", "100001"))
	if err := os.Symlink("..data/rules.conf", filepath.Join(dir, "rules.conf")); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseFlags(cmdProxy, []string{"--upstream", "http://app", "--rules", filepath.Join(dir, "rules.conf"), "--mode", "block", "--watch-rules"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics("proxy")
	p, reloader, err := flagMode(cfg, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	verdict := func(q string) pipeline.Verdict { return p.Check(ctx, attack(q)) }
	if verdict("alpha").Action != pipeline.ActionDeny || verdict("beta").Action != pipeline.ActionAllow {
		t.Fatal("v1 rules not in force")
	}

	// Under load: every request gets a rule verdict, none an error.
	var stop atomic.Bool
	var failed atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				if v := verdict("alpha"); v.Reason != pipeline.ReasonRule && v.Reason != pipeline.ReasonNone {
					failed.Add(1)
				}
			}
		})
	}
	write("v2", rule("beta", "100002"))
	if err := reloader.reload("SIGHUP"); err != nil {
		t.Fatal(err)
	}
	stop.Store(true)
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Errorf("%d requests without a verdict during the reload", n)
	}
	if verdict("beta").Action != pipeline.ActionDeny || verdict("alpha").Action != pipeline.ActionAllow {
		t.Fatal("v2 rules not in force after the reload")
	}

	// An invalid file: the v2 rules stay.
	write("v3", `SecRule ARGS "@nosuchoperator x" "id:1,deny"`)
	if err := reloader.reload("SIGHUP"); err == nil {
		t.Fatal("invalid rules reloaded")
	}
	if verdict("beta").Action != pipeline.ActionDeny {
		t.Fatal("the old rules aren't in force after a failed reload")
	}

	// --watch-rules: the run loop reloads once on a change, and SIGHUP
	// reloads too.
	write("v4", rule("gamma", "100004"))
	hup := make(chan os.Signal, 1)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	before := reloader.reloads.Load()
	go func() { reloader.run(runCtx, hup, 50*time.Millisecond); close(done) }()
	waitFor(t, func() bool { return verdict("gamma").Action == pipeline.ActionDeny })
	time.Sleep(300 * time.Millisecond)
	if n := reloader.reloads.Load() - before; n != 1 {
		t.Errorf("%d reloads on one change, want 1", n)
	}
	hup <- syscall.SIGHUP
	waitFor(t, func() bool { return reloader.reloads.Load()-before == 2 })
	cancel()
	<-done
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for range 200 {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out")
}
