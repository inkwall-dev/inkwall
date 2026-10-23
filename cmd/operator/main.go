// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwall-operator is Inkwall's Kubernetes operator: it turns
// WAFPolicy and the other waf.inkwall.dev objects into policy bundles for
// the engines, and wires the cluster's proxies to them (docs/design/0004).
// It is never on the request path.
//
// This is the manager the controllers run in. It serves health probes and
// metrics, and elects a leader when more than one replica runs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// leaderElectionID names the Lease the replicas compete for.
const leaderElectionID = "inkwall-operator.waf.inkwall.dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

type options struct {
	metricsAddr string
	probeAddr   string
	leaderElect bool
	leaderNS    string
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("inkwall-operator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.metricsAddr, "metrics-bind-address", ":8080", "address for /metrics (0 disables)")
	fs.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "address for /healthz and /readyz (0 disables)")
	fs.BoolVar(&o.leaderElect, "leader-elect", false, "elect a leader through a Lease, so several replicas can run")
	fs.StringVar(&o.leaderNS, "leader-election-namespace", "", "namespace of the leader election Lease (empty: the operator's own namespace, when running in a cluster)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
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
	logger.Info("operator starting", slog.Bool("leader_elect", o.leaderElect))
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
		LeaderElectionNamespace: o.leaderNS,
		// The new leader starts at once instead of waiting out the lease,
		// as the old one steps down cleanly on shutdown.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return nil, err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	return mgr, nil
}
