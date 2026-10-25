// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-engine runs the Inkwall inspection engine.
//
// Usage:
//
//	inkwall-engine proxy --upstream http://app:8080 [flags]
//	inkwall-engine forward-auth [flags]
//	inkwall-engine check [flags]
//
// The proxy subcommand runs the standalone reverse proxy: it inspects each
// request with the OWASP Core Rule Set and forwards allowed requests to the
// upstream.
//
// The forward-auth subcommand answers forward-auth subrequests from a proxy
// such as Traefik (ForwardAuth middleware) on /v1/forward-auth: 200 allows
// the request, any other status is returned to the client.
//
// The check subcommand serves the engine's own check API (api/engine/v1) on
// POST /v1/check, for proxies without a native protocol and for inkwallctl.
//
// --listen and --admin-listen take a TCP address (127.0.0.1:9001) or a Unix
// socket (unix:/run/inkwall/engine.sock).
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/forwardauth"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != cmdProxy && args[0] != cmdForwardAuth && args[0] != cmdCheck) {
		fmt.Fprintln(stderr, "usage: inkwall-engine proxy --upstream URL [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine forward-auth [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine check [flags]")
		fmt.Fprintln(stderr, "run 'inkwall-engine <command> -h' for flags")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := parseFlags(args[0], args[1:], stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := serve(cfg, logger); err != nil {
		logger.Error("engine stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

// Subcommands. All run the same engine and differ only in how requests
// arrive and how the verdict is returned.
const (
	cmdProxy       = "proxy"
	cmdForwardAuth = "forward-auth"
	cmdCheck       = "check"
)

type engineConfig struct {
	command        string
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
	pprof          bool
	ruleGroupsOff  []string

	// Bundle mode: policies come from the operator.
	operator           string
	operatorCA         string
	operatorServerName string
	operatorToken      string
	bundleKey          string
	bundleCache        string
}

// policyFlags define a policy: in bundle mode the operator's bundle does, so
// they can't be set.
var policyFlags = []string{
	"mode", "failure-mode", "timeout", "oversize-body", "paranoia-level", "anomaly-threshold",
	"rules", "rules-before-crs", "skip-paths", "skip-body-paths", "disable-rule-groups",
}

func parseFlags(command string, args []string, stderr io.Writer) (engineConfig, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	// forward-auth and check run next to the proxy that calls them, so by
	// default they are reachable only from inside the pod.
	defaultListen := ":8480"
	switch command {
	case cmdForwardAuth:
		defaultListen = "127.0.0.1:9001"
	case cmdCheck:
		defaultListen = "127.0.0.1:9002"
	}
	listen := fs.String("listen", defaultListen, "address to listen on: host:port or unix:/path/to/socket")
	adminListen := fs.String("admin-listen", ":9480", "address for /metrics, /healthz and /readyz (empty disables)")
	readTimeout := fs.Duration("read-timeout", 60*time.Second, "maximum time to read a whole request, including the body (0 = no limit)")
	var upstream *string
	if command == cmdProxy {
		upstream = fs.String("upstream", "", "upstream URL that allowed requests are forwarded to (required)")
	}
	mode := fs.String("mode", "detect", "enforcement mode: detect or block")
	failure := fs.String("failure-mode", "auto", "when a request cannot be inspected (timeout, error, overload): open (allow), closed (deny with 503), or auto (closed in block mode, open in detect mode)")
	timeout := fs.Duration("timeout", pipeline.DefaultTimeout, "per-request inspection deadline")
	maxConcurrent := fs.Int("max-concurrent", 0, "maximum concurrent evaluations; extra requests get the failure mode (0 = 2 * CPUs)")
	maxBody := fs.Int64("max-body-bytes", 64<<10, "request body bytes to inspect (0 disables body inspection); in bundle mode, for policies that don't set body.maxBytes")
	oversize := fs.String("oversize-body", "auto", "bodies over --max-body-bytes: deny (413 in block mode), allow (forward with the body uninspected, logged), or auto (deny in block mode, allow in detect mode)")
	maxArgs := fs.Int("max-args", 0, "maximum arguments per source (query, body); more is rejected with 400 before CRS runs (0 = 1000)")
	paranoia := fs.Int("paranoia-level", coraza.DefaultParanoiaLevel, "OWASP CRS paranoia level (1-4)")
	threshold := fs.Int("anomaly-threshold", coraza.DefaultInboundAnomalyThreshold, "OWASP CRS inbound anomaly score threshold")
	rulesFile := fs.String("rules", "", "file with SecLang rules and configure-time exclusions (SecRuleRemoveById, SecRuleUpdateTargetById), loaded after CRS")
	rulesBeforeCRS := fs.String("rules-before-crs", "", "file with SecLang runtime exclusions (rules using ctl:ruleRemoveById and similar) and settings, loaded before CRS")
	// The check API carries the client address resolved by the proxy.
	trusted := new(string)
	if command != cmdCheck {
		trusted = fs.String("trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is trusted")
	}
	skipPaths := fs.String("skip-paths", "", "comma-separated paths never inspected, exact (/healthz) or prefix (/static/*); ambiguous paths are always inspected")
	disableGroups := fs.String("disable-rule-groups", "", "comma-separated CRS attack families to remove when the application cannot be vulnerable to them: "+strings.Join(coraza.RuleGroupNames(), ", "))
	pprof := fs.Bool("pprof", false, "serve /debug/pprof on the admin listener (exposes internals: keep that listener private)")
	skipBodyPaths := fs.String("skip-body-paths", "", "comma-separated paths whose body is not inspected (headers and URI still are), same syntax as --skip-paths")
	operator := fs.String("operator", "", "bundle mode: the operator's distribution server, host:port; policies come from its bundles, per route, instead of the flags that define a policy")
	operatorCA := fs.String("operator-ca", "/var/run/secrets/inkwall/ca.crt", "bundle mode: CA certificate (PEM) of the operator's server")
	operatorServerName := fs.String("operator-server-name", "", "bundle mode: name the operator's certificate must have (default: the host of --operator)")
	operatorToken := fs.String("operator-token", "/var/run/secrets/inkwall/token", "bundle mode: ServiceAccount token for the audience inkwall-operator, re-read on every connection")
	bundleKey := fs.String("bundle-key", "/var/run/secrets/inkwall/ed25519.pub", "bundle mode: the cluster's ed25519 public key (raw 32 bytes) that bundles are signed with")
	bundleCache := fs.String("bundle-cache", "", "bundle mode: file that keeps the last applied bundle, enforced at startup before the operator is reachable (empty: no cache)")
	if err := fs.Parse(args); err != nil {
		return engineConfig{}, err
	}
	if *operator != "" {
		var conflicts []string
		fs.Visit(func(f *flag.Flag) {
			if slices.Contains(policyFlags, f.Name) {
				conflicts = append(conflicts, "--"+f.Name)
			}
		})
		if len(conflicts) > 0 {
			return engineConfig{}, fmt.Errorf("%s: set by the operator's bundle with --operator", strings.Join(conflicts, ", "))
		}
	}

	cfg := engineConfig{
		command:        command,
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

		operator:           *operator,
		operatorCA:         *operatorCA,
		operatorServerName: *operatorServerName,
		operatorToken:      *operatorToken,
		bundleKey:          *bundleKey,
		bundleCache:        *bundleCache,
	}
	if command == cmdProxy {
		if *upstream == "" {
			return cfg, errors.New("--upstream is required")
		}
		u, err := url.Parse(*upstream)
		if err != nil {
			return cfg, fmt.Errorf("--upstream: %w", err)
		}
		cfg.upstream = u
	}

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
	cfg.pprof = *pprof
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

func serve(cfg engineConfig, logger *slog.Logger) error {
	resolver, err := clientip.NewResolver(cfg.trustedProxies)
	if err != nil {
		return err
	}
	adapter := "proxy"
	switch cfg.command {
	case cmdForwardAuth:
		adapter = "forwardauth"
	case cmdCheck:
		adapter = "httpcheck"
	}
	metrics := telemetry.NewMetrics(adapter)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		p  pipeline.Inspector
		ag *agent.Agent
	)
	if cfg.operator != "" {
		ag, p, err = bundleMode(cfg, metrics, logger)
	} else {
		p, err = flagMode(cfg, metrics)
	}
	if err != nil {
		return err
	}
	// In bundle mode each policy sets its body limit, up to the CRD's
	// maximum; the adapters must accept bodies that large.
	maxBody := cfg.maxBodyBytes
	if ag != nil {
		maxBody = max(maxBody, policy.MaxBodyBytes)
	}
	var handler http.Handler
	switch cfg.command {
	case cmdForwardAuth:
		handler, err = forwardauth.New(p,
			forwardauth.Config{MaxBodyBytes: maxBody, ClientIP: resolver, Logger: logger},
		)
	case cmdCheck:
		handler, err = httpcheck.New(p, httpcheck.Config{MaxBodyBytes: maxBody, Logger: logger})
	default:
		handler, err = proxy.New(p,
			proxy.Config{Upstream: cfg.upstream, MaxBodyBytes: maxBody, ClientIP: resolver, Logger: logger},
		)
	}
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
	ln, err := listen(cfg.listen)
	if err != nil {
		return err
	}
	var adminLn net.Listener
	if cfg.adminListen != "" {
		if adminLn, err = listen(cfg.adminListen); err != nil {
			_ = ln.Close()
			return err
		}
	}

	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()
	if ag != nil {
		go func() { _ = ag.Run(ctx) }()
	}

	// Rules are compiled before anything listens, so the engine is ready as
	// soon as it serves; readiness turns off again during shutdown.
	var ready atomic.Bool
	ready.Store(true)
	var admin *http.Server
	if adminLn != nil {
		adminHandler := metrics.AdminHandler(ready.Load)
		// A CPU or trace profile streams for its whole duration (30s by
		// default), longer than any other admin response.
		writeTimeout := 10 * time.Second
		if cfg.pprof {
			adminHandler = withPprof(adminHandler)
			writeTimeout = 2 * time.Minute
		}
		admin = &http.Server{
			Handler:           adminHandler,
			ReadHeaderTimeout: 5 * time.Second,
			// Admin requests are tiny; without these, idle keep-alive
			// connections are never closed and can exhaust fds and memory.
			ReadTimeout:  10 * time.Second,
			WriteTimeout: writeTimeout,
			IdleTimeout:  30 * time.Second,
		}
		go func() { errc <- admin.Serve(adminLn) }()
	}

	attrs := []any{
		slog.String("listen", ln.Addr().String()),
		slog.String("admin_listen", cfg.adminListen),
	}
	if cfg.upstream != nil {
		attrs = append(attrs, slog.String("upstream", cfg.upstream.String()))
	}
	if ag != nil {
		attrs = append(attrs, slog.String("operator", cfg.operator), slog.String("bundle_cache", cfg.bundleCache))
	} else {
		attrs = append(attrs,
			slog.String("mode", modeName(cfg.mode)),
			slog.String("failure_mode", failureModeName(cfg.failureMode.Resolve(cfg.mode))),
			slog.Int("paranoia_level", cfg.paranoiaLevel),
			slog.Any("disabled_rule_groups", cfg.ruleGroupsOff))
	}
	logger.Info("inkwall-engine "+cfg.command+" started", attrs...)

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

// flagMode builds the one pipeline the flags define.
func flagMode(cfg engineConfig, metrics *telemetry.Metrics) (pipeline.Inspector, error) {
	directives, err := readOptional(cfg.rulesFile)
	if err != nil {
		return nil, fmt.Errorf("read --rules: %w", err)
	}
	directivesBeforeCRS, err := readOptional(cfg.rulesBeforeCRS)
	if err != nil {
		return nil, fmt.Errorf("read --rules-before-crs: %w", err)
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
		return nil, err
	}
	p := pipeline.New(eval, pipeline.Config{
		Mode:          cfg.mode,
		FailureMode:   cfg.failureMode,
		Timeout:       cfg.timeout,
		MaxConcurrent: cfg.maxConcurrent,
		Oversize:      cfg.oversize,
		Observer:      metrics,
		Routes:        cfg.routes,
	})
	metrics.WatchAdmission(p.Admission())
	return p, nil
}

// bundleMode inspects with the policies of the operator's bundles, per
// route. Until the first bundle (or the cached one) is applied, requests
// are allowed and reported with reason no-policy.
func bundleMode(cfg engineConfig, metrics *telemetry.Metrics, logger *slog.Logger) (*agent.Agent, pipeline.Inspector, error) {
	adm := pipeline.NewAdmission(cfg.maxConcurrent)
	metrics.WatchAdmission(adm)
	opts := policy.Options{
		Admission:  adm,
		Observer:   metrics,
		MaxArgs:    cfg.maxArgs,
		BodyLimit:  cfg.maxBodyBytes,
		Evaluators: policy.NewEvaluators(),
	}
	holder := &policy.Holder{}
	host, _ := os.Hostname()
	podName := cmp.Or(os.Getenv("POD_NAME"), host)
	ag, err := agent.New(agent.Config{
		Addr:          cfg.operator,
		CAFile:        cfg.operatorCA,
		ServerName:    cfg.operatorServerName,
		TokenFile:     cfg.operatorToken,
		PublicKeyFile: cfg.bundleKey,
		CacheFile:     cfg.bundleCache,
		// One engine per pod; the operator replaces a restarted engine's
		// record.
		EngineID:      podName,
		PodNamespace:  os.Getenv("POD_NAMESPACE"),
		PodName:       podName,
		NodeName:      os.Getenv("NODE_NAME"),
		EngineVersion: engineVersion(),
		Compile:       func(b *bundlev1.Bundle) (*policy.Set, error) { return policy.Compile(b, opts) },
		Holder:        holder,
		Admission:     adm,
		Logger:        logger,
	})
	if err != nil {
		return nil, nil, err
	}
	metrics.Register(ag.Collectors()...)
	return ag, holder, nil
}

// engineVersion is the module version the binary was built from.
func engineVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "unknown"
}

// withPprof adds the net/http/pprof handlers under /debug/pprof/.
func withPprof(admin http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/", admin)
	return mux
}

// listen opens a TCP address or, with a "unix:" prefix, a Unix socket. A
// socket file left behind by a previous run is removed first; the listener
// removes its socket when it is closed.
func listen(addr string) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return net.Listen("tcp", addr)
	}
	if path == "" {
		return nil, errors.New("unix: listen address without a socket path")
	}
	// sun_path is 108 bytes on Linux and 104 on macOS, including the NUL;
	// the kernel reports a longer path only as "invalid argument".
	if len(path) > 103 {
		return nil, fmt.Errorf("unix socket path %q is %d bytes, longer than the 103 the OS allows", path, len(path))
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	return net.Listen("unix", path)
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
