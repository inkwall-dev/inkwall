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
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
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
	upstream       *url.URL
	mode           pipeline.Mode
	failureMode    pipeline.FailureMode
	timeout        time.Duration
	maxBodyBytes   int64
	paranoiaLevel  int
	threshold      int
	rulesFile      string
	trustedProxies []string
}

func parseProxyFlags(args []string, stderr io.Writer) (proxyConfig, error) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8080", "address to listen on")
	upstream := fs.String("upstream", "", "upstream URL that allowed requests are forwarded to (required)")
	mode := fs.String("mode", "detect", "enforcement mode: detect or block")
	failure := fs.String("failure-mode", "open", "on inspection error or timeout: open (allow) or closed (deny with 503)")
	timeout := fs.Duration("timeout", pipeline.DefaultTimeout, "per-request inspection deadline")
	maxBody := fs.Int64("max-body-bytes", 64<<10, "request body bytes to inspect (0 disables body inspection)")
	paranoia := fs.Int("paranoia-level", coraza.DefaultParanoiaLevel, "OWASP CRS paranoia level (1-4)")
	threshold := fs.Int("anomaly-threshold", coraza.DefaultInboundAnomalyThreshold, "OWASP CRS inbound anomaly score threshold")
	rulesFile := fs.String("rules", "", "file with extra SecLang rules or exclusions, loaded after CRS")
	trusted := fs.String("trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is trusted")
	if err := fs.Parse(args); err != nil {
		return proxyConfig{}, err
	}

	cfg := proxyConfig{
		listen:        *listen,
		timeout:       *timeout,
		maxBodyBytes:  *maxBody,
		paranoiaLevel: *paranoia,
		threshold:     *threshold,
		rulesFile:     *rulesFile,
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
	case "open":
		cfg.failureMode = pipeline.FailOpen
	case "closed":
		cfg.failureMode = pipeline.FailClosed
	default:
		return cfg, fmt.Errorf("--failure-mode must be open or closed, got %q", *failure)
	}
	if *trusted != "" {
		cfg.trustedProxies = strings.Split(*trusted, ",")
	}
	return cfg, nil
}

func serveProxy(cfg proxyConfig, logger *slog.Logger) error {
	var directives string
	if cfg.rulesFile != "" {
		b, err := os.ReadFile(cfg.rulesFile)
		if err != nil {
			return fmt.Errorf("read rules: %w", err)
		}
		directives = string(b)
	}
	eval, err := coraza.New(coraza.Config{
		ParanoiaLevel:           cfg.paranoiaLevel,
		InboundAnomalyThreshold: cfg.threshold,
		Directives:              directives,
	})
	if err != nil {
		return err
	}
	resolver, err := clientip.NewResolver(cfg.trustedProxies)
	if err != nil {
		return err
	}
	handler, err := proxy.New(
		pipeline.New(eval, pipeline.Config{Mode: cfg.mode, FailureMode: cfg.failureMode, Timeout: cfg.timeout}),
		proxy.Config{Upstream: cfg.upstream, MaxBodyBytes: cfg.maxBodyBytes, ClientIP: resolver, Logger: logger},
	)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	logger.Info("inkwall-engine proxy started",
		slog.String("listen", cfg.listen),
		slog.String("upstream", cfg.upstream.String()),
		slog.String("mode", modeName(cfg.mode)),
		slog.Int("paranoia_level", cfg.paranoiaLevel))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	logger.Info("shutting down")
	return srv.Shutdown(shutdownCtx)
}

func modeName(m pipeline.Mode) string {
	if m == pipeline.ModeBlock {
		return "block"
	}
	return "detect"
}
