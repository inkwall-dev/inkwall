// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package manager assembles the operator: the controllers and webhooks, in
// one controller-runtime manager. cmd/operator parses flags into Options.
package manager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/controller"
	"github.com/inkwall-dev/inkwall/operator/internal/resolver"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// leaderElectionID names the Lease the replicas compete for.
const leaderElectionID = "inkwall-operator.waf.inkwall.dev"

// Leader election uses a Lease and records Events in the operator's
// namespace.
//
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=inkwall-system,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="";events.k8s.io,namespace=inkwall-system,resources=events,verbs=create;patch

// Certificate sources for the webhook (Options.WebhookCerts).
const (
	// CertsRotate: the operator creates and renews the certificate, and
	// injects its CA.
	CertsRotate = "rotate"
	// CertsExternal: the certificate files are provided in WebhookCertDir,
	// e.g. by cert-manager.
	CertsExternal = "external"
)

// Options configures the operator.
type Options struct {
	MetricsAddr string
	ProbeAddr   string
	LeaderElect bool
	// Namespace is the operator's, for its Lease and Secrets.
	Namespace string
	// Debounce batches changes before a bundle is built; 0: the default.
	Debounce time.Duration

	Webhooks       bool
	WebhookPort    int
	WebhookCertDir string
	// WebhookCerts is CertsRotate or CertsExternal.
	WebhookCerts   string
	WebhookService string
	WebhookSecret  string
	// WebhookDNSNames replaces the webhook Service's names in the serving
	// certificate; for tests, where the API server calls localhost.
	WebhookDNSNames []string
}

// NewScheme returns the types the operator reads and writes.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := wafv1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

// New creates the operator's manager: the bundle builder (leader only),
// the validating webhook (every replica), health probes and metrics.
func New(cfg *rest.Config, o Options) (manager.Manager, error) {
	s, err := NewScheme()
	if err != nil {
		return nil, err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: s,
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			// Only the operator's own Secrets, and only ConfigMaps that hold
			// rules: neither is read cluster-wide.
			&corev1.Secret{}:    {Namespaces: map[string]cache.Config{o.Namespace: {}}},
			&corev1.ConfigMap{}: {Label: labels.SelectorFromSet(labels.Set{resolver.RulesLabel: "true"})},
		}},
		Metrics:                 metricsserver.Options{BindAddress: o.MetricsAddr},
		HealthProbeBindAddress:  o.ProbeAddr,
		LeaderElection:          o.LeaderElect,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: o.Namespace,
		// The new leader starts at once instead of waiting out the lease,
		// as the old one steps down cleanly on shutdown.
		LeaderElectionReleaseOnCancel: true,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:    o.WebhookPort,
			CertDir: o.WebhookCertDir,
		}),
	})
	if err != nil {
		return nil, err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if err := (&controller.BundleReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Namespace: o.Namespace,
		Debounce:  o.Debounce,
	}).SetupWithManager(mgr); err != nil {
		return nil, err
	}
	if o.Webhooks {
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
func addWebhooks(mgr manager.Manager, o Options) error {
	ready := make(chan struct{})
	switch o.WebhookCerts {
	case CertsRotate:
		dns := o.WebhookDNSNames
		if len(dns) == 0 {
			dns = webhook.ServiceDNSNames(o.WebhookService, o.Namespace)
		}
		secret := types.NamespacedName{Namespace: o.Namespace, Name: o.WebhookSecret}
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
			CertDir:  o.WebhookCertDir,
			DNSNames: dns,
		}, ready)
		if err != nil {
			return err
		}
	case CertsExternal:
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
