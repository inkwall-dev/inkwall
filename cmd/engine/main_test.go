// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
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

func TestParseExtProcFlags(t *testing.T) {
	cfg, err := parseFlags(cmdExtProc, []string{"--trusted-proxies", "127.0.0.1/32"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != "127.0.0.1:9003" || len(cfg.trustedProxies) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, err := parseFlags(cmdExtProc, []string{"--upstream", "http://app"}, io.Discard); err == nil {
		t.Fatal("ext-proc accepted --upstream")
	}
}

// TestServeExtProc runs the ext-proc engine on a Unix socket: an attack
// gets an immediate 403, counted with the adapter label extproc.
func TestServeExtProc(t *testing.T) {
	dir := t.TempDir()
	sock, adminSock := filepath.Join(dir, "extproc.sock"), filepath.Join(dir, "admin.sock")
	cfg, err := parseFlags(cmdExtProc, []string{"--listen", "unix:" + sock, "--admin-listen", "unix:" + adminSock, "--mode", "block", "--timeout", "10s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	dial := func(ctx context.Context, path string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}
	conn, err := grpc.NewClient("passthrough:///engine", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dial(ctx, sock) }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	var resp *extprocv3.ProcessingResponse
	for deadline := time.Now().Add(10 * time.Second); ; {
		if resp, err = processOnce(conn); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the engine never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := resp.GetImmediateResponse().GetStatus().GetCode(); code != 403 {
		t.Fatalf("attack answered %v, want 403", resp)
	}

	admin := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dial(ctx, adminSock)
	}}}
	r, err := admin.Get("http://engine/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	metrics, _ := io.ReadAll(r.Body)
	if want := `inkwall_requests_total{action="deny",adapter="extproc",reason="rule"} 1`; !strings.Contains(string(metrics), want) {
		t.Errorf("metrics lack %s", want)
	}
}

// processOnce sends Envoy's request headers for an attack and returns the
// answer.
func processOnce(conn *grpc.ClientConn) (*extprocv3.ProcessingResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		return nil, err
	}
	h := func(k, v string) *corev3.HeaderValue { return &corev3.HeaderValue{Key: k, RawValue: []byte(v)} }
	err = stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true, Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			h(":method", "GET"), h(":path", "/?q=<script>alert(1)</script>"), h(":authority", "shop.example.com"),
			h(":scheme", "http"), h("user-agent", "Mozilla/5.0"), h("accept", "text/html"),
		}}},
	}})
	if err != nil {
		return nil, err
	}
	return stream.Recv()
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
	if _, _, _, err := bundleMode(cfg, telemetry.NewMetrics("httpcheck"), slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("got %v, want an error about the public key", err)
	}
}

// serve applies a valid cached bundle before it listens: the first request
// a restarted engine answers is inspected with it, and before that the
// proxy's requests are refused, never let through. An unusable cache is not
// an error: the engine serves, waiting for the operator.
func TestServeAppliesTheCacheBeforeListening(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	b := &bundlev1.Bundle{
		Version:     7,
		CreatedAt:   timestamppb.Now(),
		ContentHash: []byte("block"),
		Policies: []*bundlev1.Policy{{
			Id:       "shop/shop",
			Mode:     bundlev1.Mode_MODE_BLOCK,
			Routes:   []*bundlev1.RouteMatch{{Host: "shop.example.com", Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}}},
			RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "WAFRuleSet/shop/rules"}},
		}},
		RuleSets: []*bundlev1.RuleSet{{Id: "WAFRuleSet/shop/rules", Source: &bundlev1.RuleSet_Seclang{
			Seclang: `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`,
		}}},
	}
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.Marshal(&bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(priv, raw), KeyId: bundlekey.ID(pub)})
	if err != nil {
		t.Fatal(err)
	}
	key := write("ed25519.pub", pub)

	// firstAnswer starts the engine with cache and returns the status of
	// the first attack it answers, sent again at once while it refuses, as
	// Traefik's requests are.
	firstAnswer := func(cache []byte) int {
		t.Helper()
		sock := filepath.Join(dir, "engine.sock")
		cfg, err := parseFlags(cmdForwardAuth, []string{
			"--listen", "unix:" + sock,
			"--admin-listen", "unix:" + filepath.Join(dir, "admin.sock"),
			// Nothing listens there: only the cache can supply the bundle.
			"--operator", "127.0.0.1:1",
			"--operator-ca", filepath.Join(dir, "ca.crt"),
			"--operator-token", filepath.Join(dir, "token"),
			"--bundle-key", key,
			"--bundle-cache", write("bundle.pb", cache),
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- serve(ctx, cfg, slog.New(slog.DiscardHandler)) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("serve: %v", err)
			}
		}()
		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		}}
		for deadline := time.Now().Add(10 * time.Second); ; {
			req, _ := http.NewRequest(http.MethodGet, "http://engine/v1/forward-auth", nil)
			req.Header.Set("X-Forwarded-Method", "GET")
			req.Header.Set("X-Forwarded-Proto", "http")
			req.Header.Set("X-Forwarded-Host", "shop.example.com")
			req.Header.Set("X-Forwarded-Uri", "/?q=attack")
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			if time.Now().After(deadline) {
				t.Fatalf("the engine never answered: %v", err)
			}
		}
	}

	if code := firstAnswer(signed); code != http.StatusForbidden {
		t.Errorf("first answer to an attack %d, want 403 from the cached bundle", code)
	}
	if code := firstAnswer([]byte("garbage")); code != http.StatusOK {
		t.Errorf("first answer with a corrupt cache %d, want 200 (no policy, bootstrap allow)", code)
	}
}
