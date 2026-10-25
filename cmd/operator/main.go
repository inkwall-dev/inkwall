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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/inkwall-dev/inkwall/operator/manager"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func parseFlags(args []string, stderr io.Writer) (manager.Options, error) {
	fs := flag.NewFlagSet("inkwall-operator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// The downward API sets these in a cluster.
	o := manager.Options{
		Namespace:  os.Getenv("POD_NAMESPACE"),
		Replica:    os.Getenv("POD_NAME"),
		ReplicaUID: types.UID(os.Getenv("POD_UID")),
	}
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
	fs.IntVar(&o.DistributionPort, "distribution-port", 9445, "port of the gRPC server that sends bundles to the engines, over TLS with the webhook's certificate (0 disables)")
	fs.StringVar(&o.DistributionService, "distribution-service", "inkwall-operator", "Service engines reach the distribution server through, named in the certificate")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if o.WebhookCerts != manager.CertsRotate && o.WebhookCerts != manager.CertsExternal {
		return o, fmt.Errorf("--webhook-certs must be %s or %s, not %q", manager.CertsRotate, manager.CertsExternal, o.WebhookCerts)
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
	mgr, err := manager.New(cfg, o)
	if err != nil {
		logger.Error("cannot create the manager", slog.Any("error", err))
		return 1
	}
	logger.Info("operator starting", slog.String("namespace", o.Namespace),
		slog.Bool("leader_elect", o.LeaderElect), slog.Bool("webhooks", o.Webhooks))
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("operator stopped", slog.Any("error", err))
		return 1
	}
	return 0
}
