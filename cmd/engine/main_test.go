// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

func TestParseProxyFlags(t *testing.T) {
	cfg, err := parseFlags(cmdProxy, []string{
		"--upstream", "http://app:8080", "--mode", "block", "--failure-mode", "closed",
		"--trusted-proxies", "10.0.0.0/8,192.0.2.1", "--oversize-body", "deny", "--max-args", "255",
		"--skip-paths", "/healthz,/static/*", "--skip-body-paths", "/upload/*",
		"--disable-rule-groups", "php, java",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.upstream.Host != "app:8080" || cfg.mode != pipeline.ModeBlock || cfg.failureMode != pipeline.FailClosed {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.oversize != pipeline.OversizeDeny || cfg.maxArgs != 255 {
		t.Fatalf("oversize/max-args not parsed: %+v", cfg)
	}
	if len(cfg.skipPaths) != 2 || len(cfg.skipBodyPaths) != 1 {
		t.Fatalf("skip paths not parsed: %v %v", cfg.skipPaths, cfg.skipBodyPaths)
	}
	if len(cfg.ruleGroupsOff) != 2 {
		t.Fatalf("rule groups not parsed: %v", cfg.ruleGroupsOff)
	}
	if len(cfg.trustedProxies) != 2 {
		t.Fatalf("trusted proxies = %v", cfg.trustedProxies)
	}
}

func TestParseProxyFlagsDefaults(t *testing.T) {
	cfg, err := parseFlags(cmdProxy, []string{"--upstream", "http://app"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode != pipeline.ModeDetect || cfg.failureMode != pipeline.FailAuto {
		t.Fatalf("defaults must be detect mode and the auto failure mode, got %+v", cfg)
	}
	if cfg.listen != ":8480" || cfg.adminListen != ":9480" {
		t.Fatalf("default ports = %s / %s, want :8480 / :9480", cfg.listen, cfg.adminListen)
	}
}

func TestParseProxyFlagsErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--upstream", "http://app", "--mode", "enforce"},
		{"--upstream", "http://app", "--failure-mode", "maybe"},
		{"--upstream", "http://app", "--oversize-body", "truncate"},
		{"--upstream", "http://app", "--skip-paths", "static/*"},
		{"--upstream", "http://app", "--disable-rule-groups", "php,cobol"},
	} {
		if _, err := parseFlags(cmdProxy, args, io.Discard); err == nil {
			t.Errorf("parseFlags(proxy, %v) succeeded, want error", args)
		}
	}
}

func TestRunUsage(t *testing.T) {
	if code := run(nil, io.Discard); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
}

func TestParseForwardAuthFlags(t *testing.T) {
	cfg, err := parseFlags(cmdForwardAuth, []string{"--mode", "block", "--trusted-proxies", "127.0.0.1/32"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != "127.0.0.1:9001" || cfg.adminListen != ":9480" {
		t.Fatalf("default ports = %s / %s, want 127.0.0.1:9001 / :9480", cfg.listen, cfg.adminListen)
	}
	if cfg.upstream != nil || cfg.mode != pipeline.ModeBlock {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, err := parseFlags(cmdForwardAuth, []string{"--upstream", "http://app"}, io.Discard); err == nil {
		t.Fatal("forward-auth accepted --upstream")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := run([]string{"serve"}, io.Discard); code != 2 {
		t.Fatalf("run(serve) = %d, want 2", code)
	}
}

func TestParseCheckFlags(t *testing.T) {
	cfg, err := parseFlags(cmdCheck, []string{"--listen", "unix:/run/inkwall/engine.sock", "--mode", "block"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != "unix:/run/inkwall/engine.sock" || cfg.mode != pipeline.ModeBlock {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg, _ := parseFlags(cmdCheck, nil, io.Discard); cfg.listen != "127.0.0.1:9002" {
		t.Fatalf("default listen = %s, want 127.0.0.1:9002", cfg.listen)
	}
	// The caller sends the resolved client address; there is no
	// X-Forwarded-For to trust.
	for _, args := range [][]string{{"--upstream", "http://app"}, {"--trusted-proxies", "10.0.0.0/8"}} {
		if _, err := parseFlags(cmdCheck, args, io.Discard); err == nil {
			t.Fatalf("check accepted %v", args)
		}
	}
}

func TestListenUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.sock")
	ln, err := listen("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if ln.Addr().Network() != "unix" {
		t.Fatalf("network %s, want unix", ln.Addr().Network())
	}

	// A socket left by a crashed run is replaced.
	stale, err := net.Listen("unix", filepath.Join(t.TempDir(), "stale.sock"))
	if err != nil {
		t.Fatal(err)
	}
	stalePath := stale.Addr().String()
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	again, err := listen("unix:" + stalePath)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = again.Close()

	// Anything else at the path is left alone.
	_ = ln.Close()
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen("unix:" + path); err == nil {
		t.Fatal("listen replaced a regular file")
	}
	if _, err := listen("unix:"); err == nil {
		t.Fatal("empty socket path accepted")
	}
	if _, err := listen("unix:/" + strings.Repeat("a", 103)); err == nil || !strings.Contains(err.Error(), "103") {
		t.Fatalf("over-long socket path: %v", err)
	}
}

func TestPprofHandler(t *testing.T) {
	admin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := withPprof(admin)
	for path, want := range map[string]int{
		"/debug/pprof/":        http.StatusOK,
		"/debug/pprof/heap":    http.StatusOK,
		"/debug/pprof/cmdline": http.StatusOK,
		"/metrics":             http.StatusTeapot,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("GET %s: %d, want %d", path, w.Code, want)
		}
	}
	if cfg, _ := parseFlags(cmdProxy, []string{"--upstream", "http://app"}, io.Discard); cfg.pprof {
		t.Error("pprof on by default")
	}
}

func TestParseBundleModeFlags(t *testing.T) {
	cfg, err := parseFlags(cmdForwardAuth, []string{
		"--operator", "inkwall-operator.inkwall-system.svc:9445",
		"--bundle-cache", "/var/run/inkwall/bundle.pb",
		"--max-body-bytes", "131072",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.operator != "inkwall-operator.inkwall-system.svc:9445" || cfg.bundleCache != "/var/run/inkwall/bundle.pb" ||
		cfg.operatorToken != "/var/run/secrets/inkwall/token" || cfg.bundleKey != "/var/run/secrets/inkwall/ed25519.pub" {
		t.Errorf("got %+v", cfg)
	}

	// Flags that define a policy come from the bundle in bundle mode.
	for _, args := range [][]string{
		{"--mode", "block"},
		{"--rules", "rules.conf"},
		{"--skip-paths", "/healthz"},
		{"--paranoia-level", "2"},
	} {
		_, err := parseFlags(cmdForwardAuth, append([]string{"--operator", "op:9445"}, args...), io.Discard)
		if err == nil || !strings.Contains(err.Error(), args[0]) || !strings.Contains(err.Error(), "bundle") {
			t.Errorf("%v with --operator: got %v", args, err)
		}
	}
}

func TestParseBootstrapFlags(t *testing.T) {
	cfg, err := parseFlags(cmdForwardAuth, []string{"--operator", "op:9445"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.bundleSecret != "" || cfg.bootstrapDeny || cfg.bootstrapTimeout != 10*time.Second ||
		cfg.kubeToken != "/var/run/secrets/inkwall/kube-token" || cfg.kubeCA != "/var/run/secrets/inkwall/kube-ca.crt" {
		t.Errorf("defaults: %+v", cfg)
	}
	cfg, err = parseFlags(cmdForwardAuth, []string{
		"--operator", "op:9445", "--bundle-secret", "inkwall-system/inkwall-bundle", "--bootstrap", "deny", "--bootstrap-timeout", "0",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.bundleSecret != "inkwall-system/inkwall-bundle" || !cfg.bootstrapDeny || cfg.bootstrapTimeout != 0 {
		t.Errorf("got %+v", cfg)
	}
	for _, args := range [][]string{
		{"--operator", "op:9445", "--bootstrap", "maybe"},
		{"--operator", "op:9445", "--bundle-secret", "inkwall-bundle"},
		{"--operator", "op:9445", "--bundle-secret", "a/b/c"},
		{"--bundle-secret", "inkwall-system/inkwall-bundle"},
	} {
		if _, err := parseFlags(cmdForwardAuth, args, io.Discard); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestBundleModeNeedsItsFiles(t *testing.T) {
	cfg, err := parseFlags(cmdCheck, []string{"--operator", "op:9445", "--bundle-key", "/nonexistent/ed25519.pub"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundleMode(cfg, telemetry.NewMetrics("httpcheck"), slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("got %v, want an error about the public key", err)
	}
}
