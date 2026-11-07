// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-engine runs the Inkwall inspection engine.
//
// Usage:
//
//	inkwall-engine proxy --upstream http://app:8080 [flags]
//	inkwall-engine forward-auth [flags]
//	inkwall-engine check [flags]
//	inkwall-engine ext-proc [flags]
//	inkwall-engine spoe [flags]
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
// The ext-proc subcommand serves Envoy's external processing API
// (envoy.service.ext_proc.v3) over gRPC: Envoy and Envoy Gateway call it.
//
// The spoe subcommand is an SPOE agent: HAProxy's Stream Processing Offload
// Engine calls it over SPOP, and acts on the variables it sets.
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

	"google.golang.org/grpc"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/internal/buildinfo"
	"github.com/inkwall-dev/inkwall/internal/memlimit"
	"github.com/inkwall-dev/inkwall/pkg/adapters/extproc"
	"github.com/inkwall-dev/inkwall/pkg/adapters/forwardauth"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/adapters/spoe"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && slices.Contains([]string{"version", "--version", "-version"}, args[0]) {
		if len(args) > 1 {
			fmt.Fprintln(stderr, "usage: inkwall-engine version")
			return 2
		}
		fmt.Fprint(stdout, buildinfo.Get(version, commit).String("inkwall-engine"))
		return 0
	}
	if len(args) == 0 || !slices.Contains([]string{cmdProxy, cmdForwardAuth, cmdCheck, cmdExtProc, cmdSPOE}, args[0]) {
		fmt.Fprintln(stderr, "usage: inkwall-engine proxy --upstream URL [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine forward-auth [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine check [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine ext-proc [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine spoe [flags]")
		fmt.Fprintln(stderr, "       inkwall-engine version")
		fmt.Fprintln(stderr, "run 'inkwall-engine <command> -h' for flags")
		return 2
	}

	cfg, err := parseFlags(args[0], args[1:], stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	logger := newLogger(os.Stdout, cfg.logLevel)
	// The engine buffers request bodies: without a soft limit the heap
	// goal is twice the live heap, and a burst of large bodies reaches the
	// container's memory limit before the GC runs.
	if limit := memlimit.Set(os.Getenv); limit > 0 {
		logger.Info("Go memory limit set", slog.Int64("bytes", limit), slog.String("from", memlimit.Env))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfg, logger); err != nil {
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
	cmdExtProc     = "ext-proc"
	cmdSPOE        = "spoe"
)

// rulesWatchInterval is how often --watch-rules checks the rule files.
const rulesWatchInterval = 2 * time.Second

// newLogger returns the engine's JSON logger, writing lines of level and
// above to w.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

type engineConfig struct {
	command      string
	logLevel     slog.Level
	eventLogRate int
	// policyMetrics adds requests by policy, for at most policyMetricsMax
	// policies.
	policyMetrics    bool
	policyMetricsMax int
	// jsonDenials: JSON denial bodies for clients that accept JSON.
	jsonDenials   bool
	listen        string
	adminListen   string
	readTimeout   time.Duration
	upstream      *url.URL
	mode          pipeline.Mode
	failureMode   pipeline.FailureMode
	timeout       time.Duration
	maxConcurrent int
	maxBodyBytes  int64
	oversize      pipeline.OversizeAction
	grpcMessages  bool
	// responses: ext-proc only, the one adapter that sees responses.
	responses      pipeline.ResponseConfig
	maxArgs        int
	paranoiaLevel  int
	threshold      int
	rulesFile      string
	rulesBeforeCRS string
	// watchRules reloads the rule files when their content changes.
	watchRules    bool
	clientIP      clientip.Options
	skipPaths     []string
	routes        *router.Table
	skipBodyPaths []string
	pprof         bool
	ruleGroupsOff []string
	// webSocket is what a WebSocket handshake must meet; nil: nothing more
	// than any request.
	webSocket *pipeline.WebSocketRules
	// webSocketMessages: what the proxy does with a WebSocket's messages.
	webSocketMessages pipeline.WebSocketMessages

	// Bundle mode: policies come from the operator.
	operator           string
	operatorCA         string
	operatorServerName string
	operatorToken      string
	bundleKey          string
	bundleCache        string
	// bundleSecret is namespace/name of the bundle Secret, read through the
	// API server when the engine has no bundle.
	bundleSecret     string
	kubeToken        string
	kubeCA           string
	bootstrapDeny    bool
	bootstrapTimeout time.Duration
}

// policyFlags define a policy: in bundle mode the operator's bundle does, so
// they can't be set.
var policyFlags = []string{
	"mode", "failure-mode", "timeout", "oversize-body", "grpc-messages", "paranoia-level", "anomaly-threshold",
	"rules", "rules-before-crs", "watch-rules", "skip-paths", "skip-body-paths", "disable-rule-groups",
	"websocket-origins", "websocket-allow-missing-origin", "websocket-required-headers", "websocket-messages",
	"inspect-responses", "max-response-bytes", "oversize-response",
}

func parseFlags(command string, args []string, stderr io.Writer) (engineConfig, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	// forward-auth, check, ext-proc and spoe run next to the proxy that calls them, so by
	// default they are reachable only from inside the pod.
	defaultListen := ":8480"
	switch command {
	case cmdForwardAuth:
		defaultListen = "127.0.0.1:9001"
	case cmdCheck:
		defaultListen = "127.0.0.1:9002"
	case cmdExtProc:
		defaultListen = "127.0.0.1:9003"
	case cmdSPOE:
		defaultListen = "127.0.0.1:9004"
	}
	listen := fs.String("listen", defaultListen, "address to listen on: host:port or unix:/path/to/socket")
	adminListen := fs.String("admin-listen", ":9480", "address for /metrics, /healthz and /readyz (empty disables)")
	readTimeout := fs.Duration("read-timeout", 60*time.Second, "maximum time to read a whole request, including the body (0 = no limit; not ext-proc; spoe: time to read one frame once it has begun)")
	var upstream *string
	wsMessages := new(string)
	if command == cmdProxy {
		upstream = fs.String("upstream", "", "upstream URL that allowed requests are forwarded to (required)")
		// Only the proxy sees a WebSocket's messages: the other adapters
		// see its handshake alone.
		wsMessages = fs.String("websocket-messages", "off", "WebSocket messages: off (forwarded uninspected), inspect (text messages inspected, each up to --max-body-bytes; binary ones pass), or text-only (text inspected, binary refused); a denied message closes the connection with 1008")
	}
	mode := fs.String("mode", "detect", "enforcement mode: detect or block")
	failure := fs.String("failure-mode", "auto", "when a request cannot be inspected (timeout, error, overload): open (allow), closed (deny with 503), or auto (closed in block mode, open in detect mode)")
	timeout := fs.Duration("timeout", pipeline.DefaultTimeout, "per-request inspection deadline")
	maxConcurrent := fs.Int("max-concurrent", 0, "maximum concurrent evaluations; extra requests get the failure mode (0 = 2 * CPUs)")
	maxBody := fs.Int64("max-body-bytes", 64<<10, "request body bytes to inspect (0 disables body inspection); in bundle mode, for policies that don't set body.maxBytes")
	oversize := fs.String("oversize-body", "auto", "bodies over --max-body-bytes: deny (413 in block mode), allow (forward with the body uninspected, logged), or auto (deny in block mode, allow in detect mode)")
	grpcMessages := fs.String("grpc-messages", "skip", "gRPC calls' messages: inspect (the text in them, read without a schema; a message that can't be read is handled as an oversized body) or skip (path and metadata only)")
	// Only ext-proc sees responses: the other adapters don't take the
	// flags, so none claims to inspect them.
	inspectResponses, maxResponse, oversizeResponse := new(bool), new(int64), new(string)
	if command == cmdExtProc {
		inspectResponses = fs.Bool("inspect-responses", false, "inspect the upstream's responses too (CRS RESPONSE-95x data leakage rules and your phase 3 and 4 rules); Envoy must send them (processing_mode)")
		maxResponse = fs.Int64("max-response-bytes", policy.DefaultResponseBytes, "with --inspect-responses: response body bytes inspected (0: status and headers only); a longer body has its prefix inspected and gets --oversize-response")
		oversizeResponse = fs.String("oversize-response", "auto", "with --inspect-responses: responses over --max-response-bytes, or with a body that can't be inspected: deny (502 in block mode), allow, or auto (deny in block mode, allow in detect mode)")
	}
	maxArgs := fs.Int("max-args", 0, "maximum arguments per source (query, body); more is rejected with 400 before CRS runs (0 = 1000)")
	paranoia := fs.Int("paranoia-level", coraza.DefaultParanoiaLevel, "OWASP CRS paranoia level (1-4)")
	threshold := fs.Int("anomaly-threshold", coraza.DefaultInboundAnomalyThreshold, "OWASP CRS inbound anomaly score threshold")
	rulesFile := fs.String("rules", "", "file with SecLang rules and configure-time exclusions (SecRuleRemoveById, SecRuleUpdateTargetById), loaded after CRS")
	rulesBeforeCRS := fs.String("rules-before-crs", "", "file with SecLang runtime exclusions (rules using ctl:ruleRemoveById and similar) and settings, loaded before CRS")
	watchRules := fs.Bool("watch-rules", false, "reload --rules and --rules-before-crs when their content changes, checked every 2s (a mounted ConfigMap); they are reloaded on SIGHUP in any case")
	// The check API carries the client address resolved by the proxy.
	trusted := new(string)
	trustedHops := new(int)
	clientIPHeader := new(string)
	if command != cmdCheck {
		trusted = fs.String("trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For (or Forwarded) is trusted")
		trustedHops = fs.Int("trusted-hops", 0, fmt.Sprintf("forwarding header entries, from the right, that are proxies whatever their address (0-%d), for load balancers without fixed addresses; only behind a trusted peer", clientip.MaxTrustedHops))
		clientIPHeader = fs.String("client-ip-header", "x-forwarded-for", "forwarding header the client IP is read from: x-forwarded-for or forwarded (RFC 7239); only for a peer that sets or replaces it, as clients can send either")
	}
	skipPaths := fs.String("skip-paths", "", "comma-separated paths never inspected, exact (/healthz) or prefix (/static/*); ambiguous paths are always inspected")
	disableGroups := fs.String("disable-rule-groups", "", "comma-separated CRS attack families to remove when the application cannot be vulnerable to them: "+strings.Join(coraza.RuleGroupNames(), ", "))
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error (security events are logged at warn)")
	eventLogRate := fs.Int("event-log-rate", 10, "security event log lines per second for each policy and rule, in bursts of as many; the rest are counted in inkwall_security_event_logs_suppressed_total, and still go to the operator (0 = no limit)")
	jsonDenials := fs.Bool("json-denials", false, "answer a denied client that accepts application/json with a JSON body ({\"error\",\"status\",\"request_id\"}) instead of text (not spoe: HAProxy writes its denials)")
	policyMetrics := fs.Bool("policy-metrics", false, "add inkwall_policy_requests_total, requests by policy (bundle mode); off by default for its cardinality")
	policyMetricsMax := fs.Int("policy-metrics-max", telemetry.DefaultMaxPolicies, "with --policy-metrics: distinct policies counted; past them, requests count under policy=\"other\"")
	pprof := fs.Bool("pprof", false, "serve /debug/pprof on the admin listener (exposes internals: keep that listener private)")
	skipBodyPaths := fs.String("skip-body-paths", "", "comma-separated paths whose body is not inspected (headers and URI still are), same syntax as --skip-paths")
	wsOrigins := fs.String("websocket-origins", "", "comma-separated origins a WebSocket handshake may come from, scheme://host[:port] (http or https; the host may start with *. for subdomains); others are denied with 403 (empty: any origin)")
	wsMissingOrigin := fs.Bool("websocket-allow-missing-origin", false, "let a WebSocket handshake without an Origin header pass --websocket-origins")
	wsHeaders := fs.String("websocket-required-headers", "", "comma-separated headers a WebSocket handshake must have, not empty; one without them is denied with 403")
	operator := fs.String("operator", "", "bundle mode: the operator's distribution server, host:port; policies come from its bundles, per route, instead of the flags that define a policy")
	operatorCA := fs.String("operator-ca", "/var/run/secrets/inkwall/ca.crt", "bundle mode: CA certificate (PEM) of the operator's server")
	operatorServerName := fs.String("operator-server-name", "", "bundle mode: name the operator's certificate must have (default: the host of --operator)")
	operatorToken := fs.String("operator-token", "/var/run/secrets/inkwall/token", "bundle mode: ServiceAccount token for the audience inkwall-operator, re-read on every connection")
	bundleKey := fs.String("bundle-key", "/var/run/secrets/inkwall/ed25519.pub", "bundle mode: the ed25519 public keys bundles may be signed with: one or more raw 32-byte keys, concatenated (the trust ConfigMap's trusted-keys.pub), re-read when the file changes, so the operator can rotate its signing key")
	bundleCache := fs.String("bundle-cache", "", "bundle mode: file that keeps the last applied bundle, enforced at startup before the operator is reachable (empty: no cache)")
	bundleSecret := fs.String("bundle-secret", "", "bundle mode: namespace/name of the operator's bundle Secret, read through the Kubernetes API when the engine has no bundle (a new pod while the operator is unreachable); empty: not read")
	kubeToken := fs.String("kube-token", "/var/run/secrets/inkwall/kube-token", "bundle mode: ServiceAccount token for the Kubernetes API, to read --bundle-secret")
	kubeCA := fs.String("kube-ca", "/var/run/secrets/inkwall/kube-ca.crt", "bundle mode: CA certificate (PEM) of the Kubernetes API server, to read --bundle-secret")
	bootstrap := fs.String("bootstrap", "allow", "bundle mode: requests before the first bundle (no cache, no Secret, no operator): allow (uninspected) or deny (503)")
	bootstrapTimeout := fs.Duration("bootstrap-timeout", 10*time.Second, "bundle mode: how long the engine stays unready waiting for its first bundle, so the proxy doesn't take traffic before it (0: ready at once)")
	if err := fs.Parse(args); err != nil {
		return engineConfig{}, err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil || !slices.Contains([]string{"debug", "info", "warn", "error"}, strings.ToLower(*logLevel)) {
		return engineConfig{}, fmt.Errorf("--log-level: %q, want debug, info, warn or error", *logLevel)
	}
	if *policyMetricsMax < 1 {
		return engineConfig{}, fmt.Errorf("--policy-metrics-max: %d, want 1 or more", *policyMetricsMax)
	}
	if *eventLogRate < 0 {
		return engineConfig{}, fmt.Errorf("--event-log-rate: %d, want 0 or more", *eventLogRate)
	}
	if *bootstrap != "allow" && *bootstrap != "deny" {
		return engineConfig{}, fmt.Errorf("--bootstrap: %q, want allow or deny", *bootstrap)
	}
	if *bundleSecret != "" {
		if *operator == "" {
			return engineConfig{}, errors.New("--bundle-secret: only with --operator")
		}
		if ns, name, ok := strings.Cut(*bundleSecret, "/"); !ok || ns == "" || name == "" || strings.Contains(name, "/") {
			return engineConfig{}, fmt.Errorf("--bundle-secret: %q, want namespace/name", *bundleSecret)
		}
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
		command:          command,
		logLevel:         level,
		eventLogRate:     *eventLogRate,
		policyMetrics:    *policyMetrics,
		jsonDenials:      *jsonDenials,
		policyMetricsMax: *policyMetricsMax,
		listen:           *listen,
		adminListen:      *adminListen,
		readTimeout:      *readTimeout,
		timeout:          *timeout,
		maxConcurrent:    *maxConcurrent,
		maxBodyBytes:     *maxBody,
		maxArgs:          *maxArgs,
		paranoiaLevel:    *paranoia,
		threshold:        *threshold,
		rulesFile:        *rulesFile,
		rulesBeforeCRS:   *rulesBeforeCRS,
		watchRules:       *watchRules,

		operator:           *operator,
		operatorCA:         *operatorCA,
		operatorServerName: *operatorServerName,
		operatorToken:      *operatorToken,
		bundleKey:          *bundleKey,
		bundleCache:        *bundleCache,
		bundleSecret:       *bundleSecret,
		kubeToken:          *kubeToken,
		kubeCA:             *kubeCA,
		bootstrapDeny:      *bootstrap == "deny",
		bootstrapTimeout:   *bootstrapTimeout,
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
		switch *wsMessages {
		case "off":
		case "inspect":
			cfg.webSocketMessages = pipeline.MessagesInspect
		case "text-only":
			cfg.webSocketMessages = pipeline.MessagesTextOnly
		default:
			return cfg, fmt.Errorf("--websocket-messages must be off, inspect or text-only, got %q", *wsMessages)
		}
		if cfg.webSocketMessages != pipeline.MessagesOff && cfg.maxBodyBytes <= 0 {
			return cfg, errors.New("--websocket-messages needs --max-body-bytes, the limit of a message")
		}
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
	switch *grpcMessages {
	case "inspect":
		cfg.grpcMessages = true
	case "skip":
	default:
		return cfg, fmt.Errorf("--grpc-messages must be inspect or skip, got %q", *grpcMessages)
	}
	if !*inspectResponses {
		var stray []string
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "max-response-bytes" || f.Name == "oversize-response" {
				stray = append(stray, "--"+f.Name)
			}
		})
		if len(stray) > 0 {
			return cfg, fmt.Errorf("%s: only with --inspect-responses", strings.Join(stray, ", "))
		}
	}
	if *inspectResponses {
		if *maxResponse < 0 || *maxResponse > policy.MaxBodyBytes {
			return cfg, fmt.Errorf("--max-response-bytes must be 0 to %d, got %d", policy.MaxBodyBytes, *maxResponse)
		}
		cfg.responses = pipeline.ResponseConfig{Inspect: true, MaxBytes: *maxResponse}
		switch *oversizeResponse {
		case "auto":
			cfg.responses.Oversize = pipeline.OversizeAuto
		case "allow":
			cfg.responses.Oversize = pipeline.OversizeAllow
		case "deny":
			cfg.responses.Oversize = pipeline.OversizeDeny
		default:
			return cfg, fmt.Errorf("--oversize-response must be auto, allow or deny, got %q", *oversizeResponse)
		}
	}
	cfg.clientIP = clientip.Options{TrustedProxies: splitList(*trusted), TrustedHops: *trustedHops, Header: *clientIPHeader}
	if _, err := clientip.New(cfg.clientIP); err != nil {
		return cfg, err
	}
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
	origins := splitList(*wsOrigins)
	if *wsMissingOrigin && len(origins) == 0 {
		return cfg, errors.New("--websocket-allow-missing-origin needs --websocket-origins")
	}
	cfg.webSocket, err = pipeline.CompileWebSocket(pipeline.WebSocketConfig{
		AllowedOrigins:     origins,
		AllowMissingOrigin: *wsMissingOrigin,
		RequiredHeaders:    splitList(*wsHeaders),
	})
	if err != nil {
		return cfg, fmt.Errorf("--websocket-origins, --websocket-required-headers: %w", err)
	}
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

func serve(ctx context.Context, cfg engineConfig, logger *slog.Logger) error {
	resolver, err := clientip.New(cfg.clientIP)
	if err != nil {
		return err
	}
	adapter := "proxy"
	switch cfg.command {
	case cmdForwardAuth:
		adapter = "forwardauth"
	case cmdCheck:
		adapter = "httpcheck"
	case cmdExtProc:
		adapter = "extproc"
	case cmdSPOE:
		adapter = "spoe"
	}
	metrics := telemetry.NewMetrics(adapter)
	if cfg.policyMetrics {
		metrics.EnablePolicyMetrics(cfg.policyMetricsMax)
	}

	var (
		p  pipeline.Inspector
		ag *agent.Agent
		// Without an operator, events are only logged: the recorder only
		// rate-limits their lines.
		rec = &events.Recorder{}
	)
	if cfg.operator != "" {
		ag, p, rec, err = bundleMode(cfg, metrics, logger)
	} else {
		var reloader *rulesReloader
		if p, reloader, err = flagMode(cfg, metrics, logger); err == nil {
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			var watch time.Duration
			if cfg.watchRules {
				watch = rulesWatchInterval
			}
			go reloader.run(ctx, hup, watch)
		}
	}
	if err != nil {
		return err
	}
	rec.Log = events.NewLogLimiter(cfg.eventLogRate)
	metrics.Register(rec.Log.Collectors()...)
	// In bundle mode each policy sets its body limit, up to the CRD's
	// maximum; the adapters must accept bodies that large.
	maxBody := cfg.maxBodyBytes
	if ag != nil {
		maxBody = max(maxBody, policy.MaxBodyBytes)
	}
	var (
		handler  http.Handler
		ep       *extproc.Server
		agentSrv *spoe.Server
	)
	switch cfg.command {
	case cmdExtProc:
		ep, err = extproc.New(p, extproc.Config{MaxBodyBytes: maxBody, ClientIP: resolver, Logger: logger, Events: rec, Metrics: metrics, JSONDenials: cfg.jsonDenials})
	case cmdSPOE:
		sc := spoe.Config{MaxBodyBytes: maxBody, ClientIP: resolver, ReadTimeout: cfg.readTimeout, Logger: logger, Events: rec, Metrics: metrics}
		if h, ok := p.(*policy.Holder); ok {
			// Bundle mode: the operator's HAProxy probe is answered with
			// the bundle's key.
			sc.ProbeKey = h.ProbeKey
		}
		agentSrv, err = spoe.New(p, sc)
	case cmdForwardAuth:
		handler, err = forwardauth.New(p,
			forwardauth.Config{MaxBodyBytes: maxBody, ClientIP: resolver, Logger: logger, Events: rec, Metrics: metrics, JSONDenials: cfg.jsonDenials},
		)
	case cmdCheck:
		handler, err = httpcheck.New(p, httpcheck.Config{MaxBodyBytes: maxBody, Logger: logger, Events: rec, Metrics: metrics})
	default:
		handler, err = proxy.New(p,
			proxy.Config{Upstream: cfg.upstream, MaxBodyBytes: maxBody, ClientIP: resolver, Logger: logger, Events: rec, Metrics: metrics, JSONDenials: cfg.jsonDenials,
				WebSocketMessages: cfg.webSocketMessages},
		)
	}
	if err != nil {
		return err
	}

	var srv server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds slow uploads that would otherwise hold a connection and a
		// goroutine open indefinitely.
		ReadTimeout: cfg.readTimeout,
		IdleTimeout: 120 * time.Second,
	}
	if ep != nil {
		srv = grpcServer{ep.NewGRPCServer()}
	}
	if agentSrv != nil {
		srv = agentSrv
	}

	// Bind before announcing, so "started" means the ports are really open.
	// The admin listener comes first, so /healthz answers while a cached
	// bundle is compiled; /readyz waits for it.
	var adminLn net.Listener
	if cfg.adminListen != "" {
		if adminLn, err = listen(cfg.adminListen); err != nil {
			return err
		}
	}

	// Rules are compiled before the engine listens, so it is ready as soon
	// as it serves; readiness turns off again during shutdown. In bundle
	// mode it waits for the first bundle (ready at once with a cached one),
	// for a while: the proxy takes no traffic before the policy is in place.
	var ready atomic.Bool
	if ag != nil {
		go waitForBundle(ctx, ag, cfg, &ready, logger)
	} else {
		ready.Store(true)
	}
	errc := make(chan error, 2)
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

	// A restarted engine (its pod's cache survives) enforces the cached
	// bundle from its first request: until it listens, the proxy's requests
	// fail rather than pass uninspected. An unusable cache is logged, and
	// the engine waits for the Secret or the operator.
	if ag != nil {
		ag.LoadCache()
	}
	ln, err := listen(cfg.listen)
	if err != nil {
		if admin != nil {
			_ = admin.Close()
		}
		return err
	}
	go func() { errc <- srv.Serve(ln) }()
	if ag != nil {
		go func() { _ = ag.Run(ctx) }()
	}

	attrs := []any{
		slog.String("listen", ln.Addr().String()),
		slog.String("admin_listen", cfg.adminListen),
	}
	if cfg.upstream != nil {
		attrs = append(attrs, slog.String("upstream", cfg.upstream.String()))
	}
	if ag != nil {
		attrs = append(attrs, slog.String("operator", cfg.operator), slog.String("bundle_cache", cfg.bundleCache),
			slog.String("bundle_secret", cfg.bundleSecret), slog.Bool("bootstrap_deny", cfg.bootstrapDeny))
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

// server is the request listener: an http.Server, a gRPC one, or the SPOE
// agent.
type server interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

// grpcServer gives a gRPC server http.Server's Shutdown.
type grpcServer struct{ *grpc.Server }

// Shutdown waits for in-flight streams, each one request, until ctx ends,
// then closes them.
func (g grpcServer) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		g.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		g.Stop()
		return ctx.Err()
	}
}

// flagMode builds the one pipeline the flags define.
func flagMode(cfg engineConfig, metrics *telemetry.Metrics, logger *slog.Logger) (pipeline.Inspector, *rulesReloader, error) {
	after, before, sum, err := ruleFiles(cfg)
	if err != nil {
		return nil, nil, err
	}
	eval, err := compileRules(cfg, after, before)
	if err != nil {
		return nil, nil, err
	}
	// The rules can be reloaded (SIGHUP, --watch-rules): the pipeline
	// evaluates with whichever is in force when a request starts.
	reloader := &rulesReloader{cfg: cfg, swap: rules.NewSwap(eval), logger: logger, metrics: metrics, sum: sum}
	p := pipeline.New(reloader.swap, pipeline.Config{
		Mode:          cfg.mode,
		FailureMode:   cfg.failureMode,
		Timeout:       cfg.timeout,
		MaxConcurrent: cfg.maxConcurrent,
		Oversize:      cfg.oversize,
		Observer:      metrics,
		Routes:        cfg.routes,
		GRPCMessages:  cfg.grpcMessages,
		WebSocket:     cfg.webSocket,
		Responses:     cfg.responses,
	})
	metrics.WatchAdmission(p.Admission())
	metrics.WatchRuleSets(func() int { return 1 })
	return p, reloader, nil
}

// bundleMode inspects with the policies of the operator's bundles, per
// route. Until the first bundle (or the cached one) is applied, requests
// are allowed and reported with reason no-policy. Security events and each
// policy's request counts go to the operator through the agent.
func bundleMode(cfg engineConfig, metrics *telemetry.Metrics, logger *slog.Logger) (*agent.Agent, pipeline.Inspector, *events.Recorder, error) {
	adm := pipeline.NewAdmission(cfg.maxConcurrent)
	metrics.WatchAdmission(adm)
	evaluators := policy.NewEvaluators()
	metrics.WatchRuleSets(evaluators.Len)
	stats := events.NewStats()
	opts := policy.Options{
		Admission:  adm,
		Observer:   metrics,
		MaxArgs:    cfg.maxArgs,
		BodyLimit:  cfg.maxBodyBytes,
		Evaluators: evaluators,
		Stats:      stats,
	}
	holder := &policy.Holder{DenyBeforeFirst: cfg.bootstrapDeny}
	var secret *agent.SecretSource
	if ns, name, ok := strings.Cut(cfg.bundleSecret, "/"); ok {
		secret = &agent.SecretSource{Namespace: ns, Name: name, CAFile: cfg.kubeCA, TokenFile: cfg.kubeToken}
	}
	host, _ := os.Hostname()
	podName := cmp.Or(os.Getenv("POD_NAME"), host)
	buf := events.NewBuffer(events.DefaultCapacity)
	ag, err := agent.New(agent.Config{
		Addr:          cfg.operator,
		CAFile:        cfg.operatorCA,
		ServerName:    cfg.operatorServerName,
		TokenFile:     cfg.operatorToken,
		PublicKeyFile: cfg.bundleKey,
		CacheFile:     cfg.bundleCache,
		Secret:        secret,
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
		Events:        buf,
		Stats:         stats,
		Logger:        logger,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	metrics.Register(ag.Collectors()...)
	metrics.Register(buf.Collectors()...)
	rec := &events.Recorder{Buffer: buf, Source: events.Source{
		EngineID: podName, PodNamespace: os.Getenv("POD_NAMESPACE"), PodName: podName, BundleVersion: ag.Version,
		Redaction: holder.Redaction,
	}}
	return ag, holder, rec, nil
}

// waitForBundle marks the engine ready once the first bundle is applied,
// or after cfg.bootstrapTimeout without one.
func waitForBundle(ctx context.Context, ag *agent.Agent, cfg engineConfig, ready *atomic.Bool, logger *slog.Logger) {
	timeout := time.NewTimer(cfg.bootstrapTimeout)
	defer timeout.Stop()
	select {
	case <-ag.Applied():
	case <-timeout.C:
		action := "allowing requests uninspected"
		if cfg.bootstrapDeny {
			action = "denying requests with 503"
		}
		logger.Warn("no policy bundle yet (no cache, bundle Secret and operator unavailable); ready, "+action+" until one is applied",
			slog.Duration("waited", cfg.bootstrapTimeout))
	case <-ctx.Done():
		return
	}
	ready.Store(true)
}

// version and commit are set at release builds (-ldflags "-X
// main.version=... -X main.commit=..."); otherwise the build info has the
// commit.
var version, commit string

// engineVersion is the release version, else the module version the binary
// was built from.
func engineVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
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
// removes its socket when it is closed. The socket is open to every user:
// the proxy may run as another one (Istio's Envoy runs as 1337), and the
// directory it is in, an emptyDir shared with the proxy's container, is
// what keeps it to the pod.
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
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// Connecting takes write permission, which the umask leaves to the
	// owner only.
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- a socket, in a directory only the pod mounts
		_ = l.Close()
		return nil, err
	}
	return l, nil
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
