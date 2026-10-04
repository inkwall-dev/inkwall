// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-engine runs the Inkwall inspection engine.
//
// Usage:
//
//	inkwall-engine proxy --upstream http://app:8080 [flags]
//
// The proxy subcommand runs the standalone reverse proxy: it inspects each
// request with the OWASP Core Rule Set and forwards allowed requests to the
// upstream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "proxy" {
		fmt.Fprintln(stderr, "usage: inkwall-engine proxy --upstream URL [flags]")
		fmt.Fprintln(stderr, "run 'inkwall-engine proxy -h' for flags")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := parseProxyFlags(args[1:], stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := serveProxy(cfg, logger); err != nil {
		logger.Error("engine stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

type proxyConfig struct {
	listen         string
	adminListen    string
	readTimeout    time.Duration
	upstream       *url.URL
	mode           pipeline.Mode
	failureMode    pipeline.FailureMode
	timeout        time.Duration
	maxConcurrent  int
	maxBodyBytes   int64
	oversize       pipeline.OversizeAction
	maxArgs        int
	paranoiaLevel  int
	threshold      int
	rulesFile      string
	rulesBeforeCRS string
	trustedProxies []string
	skipPaths      []string
	routes         *router.Table
	skipBodyPaths  []string
	ruleGroupsOff  []string
}

func parseProxyFlags(args []string, stderr io.Writer) (proxyConfig, error) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8480", "address to listen on")
	adminListen := fs.String("admin-listen", ":9480", "address for /metrics, /healthz and /readyz (empty disables)")
	readTimeout := fs.Duration("read-timeout", 60*time.Second, "maximum time to read a whole request, including the body (0 = no limit)")
	upstream := fs.String("upstream", "", "upstream URL that allowed requests are forwarded to (required)")
	mode := fs.String("mode", "detect", "enforcement mode: detect or block")
	failure := fs.String("failure-mode", "auto", "when a request cannot be inspected (timeout, error, overload): open (allow), closed (deny with 503), or auto (closed in block mode, open in detect mode)")
	timeout := fs.Duration("timeout", pipeline.DefaultTimeout, "per-request inspection deadline")
	maxConcurrent := fs.Int("max-concurrent", 0, "maximum concurrent evaluations; extra requests get the failure mode (0 = 2 * CPUs)")
	maxBody := fs.Int64("max-body-bytes", 64<<10, "request body bytes to inspect (0 disables body inspection)")
	oversize := fs.String("oversize-body", "auto", "bodies over --max-body-bytes: deny (413 in block mode), allow (forward with the body uninspected, logged), or auto (deny in block mode, allow in detect mode)")
	maxArgs := fs.Int("max-args", 0, "maximum arguments per source (query, body); more is rejected with 400 before CRS runs (0 = 1000)")
	paranoia := fs.Int("paranoia-level", coraza.DefaultParanoiaLevel, "OWASP CRS paranoia level (1-4)")
	threshold := fs.Int("anomaly-threshold", coraza.DefaultInboundAnomalyThreshold, "OWASP CRS inbound anomaly score threshold")
	rulesFile := fs.String("rules", "", "file with SecLang rules and configure-time exclusions (SecRuleRemoveById, SecRuleUpdateTargetById), loaded after CRS")
	rulesBeforeCRS := fs.String("rules-before-crs", "", "file with SecLang runtime exclusions (rules using ctl:ruleRemoveById and similar) and settings, loaded before CRS")
	trusted := fs.String("trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is trusted")
	skipPaths := fs.String("skip-paths", "", "comma-separated paths never inspected, exact (/healthz) or prefix (/static/*); ambiguous paths are always inspected")
	disableGroups := fs.String("disable-rule-groups", "", "comma-separated CRS attack families to remove when the application cannot be vulnerable to them: "+strings.Join(coraza.RuleGroupNames(), ", "))
	skipBodyPaths := fs.String("skip-body-paths", "", "comma-separated paths whose body is not inspected (headers and URI still are), same syntax as --skip-paths")
	if err := fs.Parse(args); err != nil {
		return proxyConfig{}, err
	}

	cfg := proxyConfig{
		listen:         *listen,
		adminListen:    *adminListen,
		readTimeout:    *readTimeout,
		timeout:        *timeout,
		maxConcurrent:  *maxConcurrent,
		maxBodyBytes:   *maxBody,
		maxArgs:        *maxArgs,
		paranoiaLevel:  *paranoia,
		threshold:      *threshold,
		rulesFile:      *rulesFile,
		rulesBeforeCRS: *rulesBeforeCRS,
	}
	if *upstream == "" {
		return cfg, errors.New("--upstream is required")
	}
	u, err := url.Parse(*upstream)
	if err != nil {
		return cfg, fmt.Errorf("--upstream: %w", err)
	}
	cfg.upstream = u

	switch *mode {
	case "detect":
		cfg.mode = pipeline.ModeDetect
	case "block":
		cfg.mode = pipeline.ModeBlock
	default:
		return cfg, fmt.Errorf("--mode must be detect or block, got %q", *mode)
	}
	switch *failure {
	case "auto":
		cfg.failureMode = pipeline.FailAuto
	case "open":
		cfg.failureMode = pipeline.FailOpen
	case "closed":
		cfg.failureMode = pipeline.FailClosed
	default:
		return cfg, fmt.Errorf("--failure-mode must be auto, open or closed, got %q", *failure)
	}
	switch *oversize {
	case "auto":
		cfg.oversize = pipeline.OversizeAuto
	case "allow":
		cfg.oversize = pipeline.OversizeAllow
	case "deny":
		cfg.oversize = pipeline.OversizeDeny
	default:
		return cfg, fmt.Errorf("--oversize-body must be auto, allow or deny, got %q", *oversize)
	}
	cfg.trustedProxies = splitList(*trusted)
	cfg.skipPaths = splitList(*skipPaths)
	cfg.skipBodyPaths = splitList(*skipBodyPaths)
	cfg.ruleGroupsOff = splitList(*disableGroups)
	for _, g := range cfg.ruleGroupsOff {
		if _, ok := coraza.RuleGroups[g]; !ok {
			return cfg, fmt.Errorf("--disable-rule-groups: unknown group %q (known: %s)", g, strings.Join(coraza.RuleGroupNames(), ", "))
		}
	}
	routes, err := router.New(cfg.skipPaths, cfg.skipBodyPaths)
	if err != nil {
		return cfg, err
	}
	cfg.routes = routes
	return cfg, nil
}

func readOptional(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	// The path comes from the operator's own command line.
	b, err := os.ReadFile(filepath.Clean(path))
	return string(b), err
}

// splitList splits a comma-separated flag value, trimming spaces and
// dropping empty entries, so "php, java" works like "php,java".
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func serveProxy(cfg proxyConfig, logger *slog.Logger) error {
	directives, err := readOptional(cfg.rulesFile)
	if err != nil {
		return fmt.Errorf("read --rules: %w", err)
	}
	directivesBeforeCRS, err := readOptional(cfg.rulesBeforeCRS)
	if err != nil {
		return fmt.Errorf("read --rules-before-crs: %w", err)
	}
	eval, err := coraza.New(coraza.Config{
		ParanoiaLevel:           cfg.paranoiaLevel,
		InboundAnomalyThreshold: cfg.threshold,
		MaxArgs:                 cfg.maxArgs,
		BodyLimit:               int(cfg.maxBodyBytes),
		DisabledRuleGroups:      cfg.ruleGroupsOff,
		DirectivesBeforeCRS:     directivesBeforeCRS,
		Directives:              directives,
	})
	if err != nil {
		return err
	}
	resolver, err := clientip.NewResolver(cfg.trustedProxies)
	if err != nil {
		return err
	}
	metrics := telemetry.NewMetrics("proxy")
	p := pipeline.New(eval, pipeline.Config{
		Mode:          cfg.mode,
		FailureMode:   cfg.failureMode,
		Timeout:       cfg.timeout,
		MaxConcurrent: cfg.maxConcurrent,
		Oversize:      cfg.oversize,
		Observer:      metrics,
		Routes:        cfg.routes,
	})
	metrics.WatchPipeline(p)
	handler, err := proxy.New(p,
		proxy.Config{Upstream: cfg.upstream, MaxBodyBytes: cfg.maxBodyBytes, ClientIP: resolver, Logger: logger},
	)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds slow uploads that would otherwise hold a connection and a
		// goroutine open indefinitely.
		ReadTimeout: cfg.readTimeout,
		IdleTimeout: 120 * time.Second,
	}

	// Bind before announcing, so "started" means the ports are really open.
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	var adminLn net.Listener
	if cfg.adminListen != "" {
		if adminLn, err = net.Listen("tcp", cfg.adminListen); err != nil {
			_ = ln.Close()
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()

	// Rules are compiled before anything listens, so the engine is ready as
	// soon as it serves; readiness turns off again during shutdown.
	var ready atomic.Bool
	ready.Store(true)
	var admin *http.Server
	if adminLn != nil {
		admin = &http.Server{
			Handler:           metrics.AdminHandler(ready.Load),
			ReadHeaderTimeout: 5 * time.Second,
			// Admin requests are tiny; without these, idle keep-alive
			// connections are never closed and can exhaust fds and memory.
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
		go func() { errc <- admin.Serve(adminLn) }()
	}

	logger.Info("inkwall-engine proxy started",
		slog.String("listen", ln.Addr().String()),
		slog.String("admin_listen", cfg.adminListen),
		slog.String("upstream", cfg.upstream.String()),
		slog.String("mode", modeName(cfg.mode)),
		slog.String("failure_mode", failureModeName(cfg.failureMode.Resolve(cfg.mode))),
		slog.Int("paranoia_level", cfg.paranoiaLevel),
		slog.Any("disabled_rule_groups", cfg.ruleGroupsOff))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	ready.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	logger.Info("shutting down")
	err = srv.Shutdown(shutdownCtx)
	if admin != nil {
		err = errors.Join(err, admin.Shutdown(shutdownCtx))
	}
	return err
}

func failureModeName(f pipeline.FailureMode) string {
	if f == pipeline.FailClosed {
		return "closed"
	}
	return "open"
}

func modeName(m pipeline.Mode) string {
	if m == pipeline.ModeBlock {
		return "block"
	}
	return "detect"
}
