// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-operator is Inkwall's Kubernetes operator: it turns
// WAFPolicy and the other waf.inkwall.dev objects into policy bundles for
// the engines, and wires the cluster's proxies to them (docs/design/0004).
// It is never on the request path.
//
// This is the manager the controllers run in. It serves the validating
// webhook, health probes and metrics, and elects a leader when more than one
// replica runs.
package main

import (
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// leaderElectionID names the Lease the replicas compete for.
const leaderElectionID = "inkwall-operator.waf.inkwall.dev"

// Leader election uses a Lease and records Events in the operator's
// namespace.
//
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=inkwall-system,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="";events.k8s.io,namespace=inkwall-system,resources=events,verbs=create;patch

// Certificate sources for the webhook (--webhook-certs).
const (
	certsRotate   = "rotate"
	certsExternal = "external"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

type options struct {
	metricsAddr string
	probeAddr   string
	leaderElect bool
	namespace   string

	webhooks       bool
	webhookPort    int
	webhookCertDir string
	webhookCerts   string
	webhookService string
	webhookSecret  string
	// webhookDNSNames replaces the webhook Service's names in the serving
	// certificate; for tests, where the API server calls localhost.
	webhookDNSNames []string
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("inkwall-operator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := options{namespace: os.Getenv("POD_NAMESPACE")}
	if o.namespace == "" {
		o.namespace = "inkwall-system"
	}
	fs.StringVar(&o.metricsAddr, "metrics-bind-address", ":8080", "address for /metrics (0 disables)")
	fs.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "address for /healthz and /readyz (0 disables)")
	fs.BoolVar(&o.leaderElect, "leader-elect", false, "elect a leader through a Lease, so several replicas can run")
	fs.StringVar(&o.namespace, "namespace", o.namespace, "the operator's namespace, for its Lease and Secrets (default: $POD_NAMESPACE, else inkwall-system)")
	fs.BoolVar(&o.webhooks, "webhooks", true, "serve the validating webhook")
	fs.IntVar(&o.webhookPort, "webhook-port", 9443, "port of the webhook server")
	fs.StringVar(&o.webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "directory of the webhook's tls.crt and tls.key")
	fs.StringVar(&o.webhookCerts, "webhook-certs", certsRotate, "where the webhook certificate comes from: rotate (the operator creates and renews it, and injects its CA) or external (files in --webhook-cert-dir, e.g. from cert-manager)")
	fs.StringVar(&o.webhookService, "webhook-service", "inkwall-operator-webhook", "Service the API server reaches the webhook through, named in the certificate")
	fs.StringVar(&o.webhookSecret, "webhook-cert-secret", "inkwall-operator-webhook-tls", "Secret, in --namespace, that holds the rotated certificate")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if o.webhookCerts != certsRotate && o.webhookCerts != certsExternal {
		return o, fmt.Errorf("--webhook-certs must be %s or %s, not %q", certsRotate, certsExternal, o.webhookCerts)
	}
	return o, nil
}

func run(args []string, stderr io.Writer) int {
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
	mgr, err := newManager(cfg, o)
	if err != nil {
		logger.Error("cannot create the manager", slog.Any("error", err))
		return 1
	}
	logger.Info("operator starting", slog.String("namespace", o.namespace),
		slog.Bool("leader_elect", o.leaderElect), slog.Bool("webhooks", o.webhooks))
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("operator stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

// newScheme returns the types the operator reads and writes.
func newScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := wafv1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

func newManager(cfg *rest.Config, o options) (manager.Manager, error) {
	s, err := newScheme()
	if err != nil {
		return nil, err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                  s,
		Metrics:                 metricsserver.Options{BindAddress: o.metricsAddr},
		HealthProbeBindAddress:  o.probeAddr,
		LeaderElection:          o.leaderElect,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: o.namespace,
		// The new leader starts at once instead of waiting out the lease,
		// as the old one steps down cleanly on shutdown.
		LeaderElectionReleaseOnCancel: true,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:    o.webhookPort,
			CertDir: o.webhookCertDir,
		}),
	})
	if err != nil {
		return nil, err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if o.webhooks {
		if err := addWebhooks(mgr, o); err != nil {
			return nil, err
		}
	} else if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	return mgr, nil
}

// addWebhooks starts the webhook server once its certificate is in place.
// The server reads the certificate files when it starts, so registering the
// webhooks (which adds the server to the manager) waits for the rotator.
// The replica reports ready only once it serves the webhook.
func addWebhooks(mgr manager.Manager, o options) error {
	ready := make(chan struct{})
	switch o.webhookCerts {
	case certsRotate:
		dns := o.webhookDNSNames
		if len(dns) == 0 {
			dns = webhook.ServiceDNSNames(o.webhookService, o.namespace)
		}
		secret := types.NamespacedName{Namespace: o.namespace, Name: o.webhookSecret}
		c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := webhook.EnsureCertSecret(ctx, c, secret); err != nil {
			return err
		}
		err = webhook.AddCertRotator(mgr, webhook.CertOptions{
			Secret:   secret,
			CertDir:  o.webhookCertDir,
			DNSNames: dns,
		}, ready)
		if err != nil {
			return err
		}
	case certsExternal:
		close(ready)
	}
	starter := &webhookStarter{mgr: mgr, ready: ready}
	if err := mgr.Add(starter); err != nil {
		return err
	}
	return mgr.AddReadyzCheck("webhook", starter.check)
}

// webhookStarter registers the webhooks once the certificate is ready. It
// runs on every replica, leader or not: all of them serve the webhook.
type webhookStarter struct {
	mgr        manager.Manager
	ready      <-chan struct{}
	registered atomic.Bool
}

func (w *webhookStarter) Start(ctx context.Context) error {
	select {
	case <-w.ready:
	case <-ctx.Done():
		return nil
	}
	if err := webhook.Setup(w.mgr); err != nil {
		return fmt.Errorf("register webhooks: %w", err)
	}
	w.registered.Store(true)
	return nil
}

func (*webhookStarter) NeedLeaderElection() bool { return false }

func (w *webhookStarter) check(req *http.Request) error {
	if !w.registered.Load() {
		return errors.New("webhook certificate not ready")
	}
	return w.mgr.GetWebhookServer().StartedChecker()(req)
}
