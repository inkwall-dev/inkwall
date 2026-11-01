// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-operator is Inkwall's Kubernetes operator: it turns
// WAFPolicy and the other waf.inkwall.dev objects into policy bundles for
// the engines, and wires the cluster's proxies to them (docs/design/0004).
// It is never on the request path.
//
// It runs the bundle builder on the elected leader, and serves the
// validating webhook, health probes and metrics on every replica
// (operator/manager).
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/manager"
)

// version is set at release builds (-ldflags "-X main.version=...").
var version string

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// options are the operator's: the manager's, and how it shuts down.
type options struct {
	manager.Options
	// shutdownDelay keeps serving after SIGTERM, not ready, while
	// Kubernetes stops routing to the pod.
	shutdownDelay time.Duration
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("inkwall-operator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// The downward API sets these in a cluster.
	o := options{Options: manager.Options{
		Namespace:  os.Getenv("POD_NAMESPACE"),
		Replica:    os.Getenv("POD_NAME"),
		ReplicaUID: types.UID(os.Getenv("POD_UID")),
	}}
	if o.Namespace == "" {
		o.Namespace = "inkwall-system"
	}
	fs.StringVar(&o.MetricsAddr, "metrics-bind-address", ":8080", "address for /metrics (0 disables)")
	fs.StringVar(&o.ProbeAddr, "health-probe-bind-address", ":8081", "address for /healthz and /readyz (0 disables)")
	fs.BoolVar(&o.LeaderElect, "leader-elect", false, "elect a leader through a Lease, so several replicas can run")
	fs.StringVar(&o.Namespace, "namespace", o.Namespace, "the operator's namespace, for its Lease and Secrets (default: $POD_NAMESPACE, else inkwall-system)")
	fs.BoolVar(&o.Webhooks, "webhooks", true, "serve the validating webhook")
	fs.IntVar(&o.WebhookPort, "webhook-port", 9443, "port of the webhook server")
	fs.StringVar(&o.WebhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "directory of the webhook's tls.crt and tls.key")
	fs.StringVar(&o.WebhookCerts, "webhook-certs", manager.CertsRotate, "where the webhook certificate comes from: rotate (the operator creates and renews it, and injects its CA) or external (files in --webhook-cert-dir, e.g. from cert-manager)")
	fs.StringVar(&o.WebhookService, "webhook-service", "inkwall-operator-webhook", "Service the API server reaches the webhook through, named in the certificate")
	fs.StringVar(&o.WebhookSecret, "webhook-cert-secret", "inkwall-operator-webhook-tls", "Secret, in --namespace, that holds the rotated certificate (shared with the distribution server)")
	fs.DurationVar(&o.shutdownDelay, "shutdown-delay", 5*time.Second, "on SIGTERM, keep serving the webhook and the bundles this long, not ready, so Kubernetes stops routing to the pod before it stops; keep it below the pod's termination grace period")
	fs.BoolVar(&o.Inject, "inject", true, "inject the engine into proxy pods (Traefik) as a sidecar; needs the webhooks and the distribution server. Off, the routes wired before are unwired")
	fs.DurationVar(&o.SelectorRestartMaxDelay, "selector-restart-max-delay", manager.DefaultSelectorRestartMaxDelay, "when the InkwallConfig's integration selectors change, each replica restarts after a random delay up to this, so they don't all restart at once")
	fs.StringVar(&o.EngineImage, "engine-image", "ghcr.io/inkwall-dev/inkwall-engine:latest", "engine image injected into proxy pods, unless InkwallConfig.spec.engine.image sets one")
	proxyNamespaces := fs.String("proxy-namespaces", integrations.DefaultNamespaces.String(), "the namespaces the proxies' pods run in, comma-separated, or * for every namespace: only pods there that an integration selects get the engine and read access to the policy bundle (their labels can be set by whoever may create a pod)")
	pullPolicy := fs.String("engine-image-pull-policy", "IfNotPresent", "pull policy of the injected engine: Always, IfNotPresent or Never")
	fs.StringVar(&o.EventsDir, "events-dir", "", "directory of this replica's buffer of security events for the optional control plane, kept across restarts (empty: in memory)")
	fs.Int64Var(&o.EventsBufferBytes, "events-buffer-bytes", manager.DefaultEventsBufferBytes, "bound of the events buffer; when full, the oldest events are dropped and counted")
	fs.DurationVar(&o.SigningKeyGrace, "signing-key-grace", manager.DefaultSigningKeyGrace, "least time each phase of a signing key rotation lasts; keep it above the kubelet's delay to update a mounted ConfigMap (about a minute by default)")
	fs.StringVar(&o.ControlPlaneCAFile, "control-plane-ca", "", "CA certificate (PEM) trusted for the optional control plane's server certificate, in GitOps and Managed mode (empty: the system roots)")
	fs.IntVar(&o.DistributionPort, "distribution-port", 9445, "port of the gRPC server that sends bundles to the engines, over TLS with the webhook's certificate (0 disables)")
	fs.StringVar(&o.DistributionService, "distribution-service", "inkwall-operator", "Service engines reach the distribution server through, named in the certificate")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	switch p := corev1.PullPolicy(*pullPolicy); p {
	case corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
		o.EnginePullPolicy = p
	default:
		return o, fmt.Errorf("--engine-image-pull-policy must be Always, IfNotPresent or Never, not %q", *pullPolicy)
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	ns, err := integrations.ParseNamespaces(*proxyNamespaces)
	if err != nil {
		return o, fmt.Errorf("--proxy-namespaces: %w", err)
	}
	o.ProxyNamespaces = ns
	if o.SigningKeyGrace <= 0 || o.SelectorRestartMaxDelay <= 0 {
		return o, errors.New("--signing-key-grace and --selector-restart-max-delay must be positive")
	}
	if o.WebhookCerts != manager.CertsRotate && o.WebhookCerts != manager.CertsExternal {
		return o, fmt.Errorf("--webhook-certs must be %s or %s, not %q", manager.CertsRotate, manager.CertsExternal, o.WebhookCerts)
	}
	return o, nil
}

func run(args []string, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "unwire" {
		return unwire(args[1:], stderr, slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	}
	o, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))

	cfg, err := ctrl.GetConfig()
	if err != nil {
		logger.Error("no Kubernetes API configuration", slog.Any("error", err))
		return 1
	}
	o.Version = cmp.Or(version, "unknown")
	mgr, err := manager.New(cfg, o.Options)
	if err != nil {
		logger.Error("cannot create the manager", slog.Any("error", err))
		return 1
	}
	var draining atomic.Bool
	if err := mgr.AddReadyzCheck("shutdown", func(*http.Request) error {
		if draining.Load() {
			return errors.New("shutting down")
		}
		return nil
	}); err != nil {
		logger.Error("cannot create the manager", slog.Any("error", err))
		return 1
	}
	logger.Info("operator starting", slog.String("version", cmp.Or(version, "unknown")), slog.String("namespace", o.Namespace),
		slog.Bool("leader_elect", o.LeaderElect), slog.Bool("webhooks", o.Webhooks))
	ctx := drain(ctrl.SetupSignalHandler(), o.shutdownDelay, &draining, logger)
	if err := mgr.Start(ctx); err != nil {
		logger.Error("operator stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

// drain returns a context that ends shutdownDelay after signal does. In
// between, draining is set (the replica reports not ready) and the servers
// keep answering: Kubernetes removes a terminating pod from its Services
// asynchronously, and the webhook fails closed, so stopping at once would
// refuse the API server's calls still routed here.
func drain(signal context.Context, delay time.Duration, draining *atomic.Bool, logger *slog.Logger) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signal.Done()
		draining.Store(true)
		logger.Info("shutting down", slog.Duration("drain", delay))
		time.Sleep(delay)
		cancel()
	}()
	return ctx
}
