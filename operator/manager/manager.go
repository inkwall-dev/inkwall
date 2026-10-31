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
	"os"
	"sync"
	"sync/atomic"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/controller"
	"github.com/inkwall-dev/inkwall/operator/internal/controlplane"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	proxydiscovery "github.com/inkwall-dev/inkwall/operator/internal/discovery"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/resolver"
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
	// WebhookDNSNames replaces the Services' names in the serving
	// certificate; for tests, where everything calls localhost.
	WebhookDNSNames []string

	// DistributionPort serves bundles to the engines (gRPC over TLS, with
	// the webhook's certificate); 0 disables.
	DistributionPort int
	// DistributionService is the Service engines reach it through, named in
	// the certificate.
	DistributionService string
	// Replica names this replica (its Pod; default: the host name), and
	// ReplicaUID, if set, makes its engine report go with the Pod.
	Replica    string
	ReplicaUID types.UID
	// EngineReportInterval is how often replicas publish their engines and
	// the leader updates Enforced; 0: 2s.
	EngineReportInterval time.Duration
	// SigningKeyGrace is the least time each phase of a signing key
	// rotation lasts; 0: DefaultSigningKeyGrace.
	SigningKeyGrace time.Duration

	// Inject adds the engine to proxy pods (needs Webhooks and
	// DistributionPort), with EngineImage unless InkwallConfig sets one.
	// Without it, the routes the operator wired are unwired.
	Inject           bool
	EngineImage      string
	EnginePullPolicy corev1.PullPolicy
	// Integrations select the proxy pods; nil: read from the InkwallConfig
	// when the manager is created. The operator restarts when they change
	// (its cache of proxy pods is built from them), after a random delay
	// up to SelectorRestartMaxDelay (0: DefaultSelectorRestartMaxDelay).
	Integrations            *integrations.Selectors
	SelectorRestartMaxDelay time.Duration

	// Version is the operator's, sent to the optional control plane.
	Version string
	// ControlPlaneCAFile trusts the control plane's server certificate;
	// empty: the system roots.
	ControlPlaneCAFile string
	// CRDInterval is how often the leader looks for Traefik's IngressRoute
	// CRD, and the Gateway API's GatewayClass and HTTPRoute CRDs, until they
	// are installed; 0: 30s.
	CRDInterval time.Duration

	// EventsDir holds the replica's buffer of security events for the
	// control plane ("": in memory); EventsBufferBytes bounds it.
	EventsDir         string
	EventsBufferBytes int64
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
	if err := gatewayv1.Install(s); err != nil {
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
	selectors := o.Integrations
	if selectors == nil {
		if selectors, err = readSelectors(cfg, s); err != nil {
			return nil, err
		}
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: s,
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			// Only the operator's own Secrets, and only ConfigMaps that hold
			// rules: neither is read cluster-wide.
			&corev1.Secret{}:    {Namespaces: map[string]cache.Config{o.Namespace: {}}},
			&corev1.ConfigMap{}: {Label: labels.SelectorFromSet(labels.Set{resolver.RulesLabel: "true"})},
			// Only proxy pods, and RBAC in the operator's namespace.
			&corev1.Pod{}:         {Label: selectors.PodSelector()},
			&rbacv1.Role{}:        {Namespaces: map[string]cache.Config{o.Namespace: {}}},
			&rbacv1.RoleBinding{}: {Namespaces: map[string]cache.Config{o.Namespace: {}}},
			// Only the Pod webhook's configuration.
			&admissionregistrationv1.MutatingWebhookConfiguration{}: {Field: fields.OneTermEqualSelector("metadata.name", webhook.MutatingConfigName)},
		}},
		// Unstructured objects (Traefik's IngressRoutes) are read from the
		// cache too: the wiring and the bundle read them all at every change.
		Client:                  client.Options{Cache: &client.CacheOptions{Unstructured: true}},
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
	// Traefik's IngressRoute CRD may be installed after the operator.
	ingressRoutes := &crdwatch.Kind{GVK: wiring.IngressRouteGVK, Mapper: mgr.GetRESTMapper(), Cache: mgr.GetCache(), Interval: o.CRDInterval}
	// So may Gateway API's.
	httpRoutes := &crdwatch.Kind{GVK: controller.HTTPRouteGVK, Object: &gatewayv1.HTTPRoute{}, Mapper: mgr.GetRESTMapper(), Cache: mgr.GetCache(), Interval: o.CRDInterval}
	if err := (&controller.BundleReconciler{
		Client:        mgr.GetClient(),
		APIReader:     mgr.GetAPIReader(),
		Namespace:     o.Namespace,
		Debounce:      o.Debounce,
		EngineStale:   engineStale(o),
		RotationGrace: o.SigningKeyGrace,
		IngressRoutes: ingressRoutes,
		HTTPRoutes:    httpRoutes,
	}).SetupWithManager(mgr); err != nil {
		return nil, err
	}
	ready, err := addCerts(mgr, o)
	if err != nil {
		return nil, err
	}
	inject := o.Inject && o.Webhooks && o.DistributionPort != 0
	var injector *webhook.PodInjector
	if inject {
		injector = &webhook.PodInjector{
			Client:       mgr.GetClient(),
			Decoder:      admission.NewDecoder(mgr.GetScheme()),
			Image:        o.EngineImage,
			PullPolicy:   o.EnginePullPolicy,
			OperatorAddr: fmt.Sprintf("%s.%s.svc:%d", o.DistributionService, o.Namespace, o.DistributionPort),
			BundleSecret: o.Namespace + "/" + bundle.BundleSecret,
			Integrations: selectors,
		}
		if err := (&injection.PodWebhookReconciler{
			Client: mgr.GetClient(), ConfigName: webhook.MutatingConfigName, WebhookName: webhook.PodWebhookName,
			Pods: selectors.LabelSelector(integrations.Traefik.Name),
		}).SetupWithManager(mgr); err != nil {
			return nil, err
		}
		if err := mgr.Add(&selectorWatch{client: mgr.GetClient(), current: selectors, maxDelay: o.SelectorRestartMaxDelay}); err != nil {
			return nil, err
		}
		if err := (&injection.Reconciler{
			Client:     mgr.GetClient(),
			APIReader:  mgr.GetAPIReader(),
			Namespace:  o.Namespace,
			CertSecret: o.WebhookSecret,
			Pods:       selectors.PodSelector(),
		}).SetupWithManager(mgr); err != nil {
			return nil, err
		}
	}
	// Without injection, the wiring controller unwires what was wired: new
	// proxy pods won't have the engine.
	wirings := wiring.Integrations(mgr.GetClient(), mgr.GetAPIReader(), selectors, ingressRoutes)
	if err := (&wiring.Reconciler{
		Client: mgr.GetClient(), PodWebhook: webhook.MutatingConfigName, Integrations: wirings, Disabled: !inject,
	}).SetupWithManager(mgr); err != nil {
		return nil, err
	}
	// The Gateway API's CRDs may be installed after the operator, or never.
	gatewayClasses := &crdwatch.Kind{GVK: proxydiscovery.GatewayClassGVK, Mapper: mgr.GetRESTMapper(), Cache: mgr.GetCache(), Interval: o.CRDInterval}
	kinds := map[string][]schema.GroupKind{}
	for _, in := range wirings {
		kinds[in.Name()] = in.Kinds()
	}
	if err := (&proxydiscovery.Reconciler{Client: mgr.GetClient(), GatewayClasses: gatewayClasses, Kinds: kinds}).SetupWithManager(mgr); err != nil {
		return nil, err
	}
	for _, k := range []*crdwatch.Kind{ingressRoutes, httpRoutes, gatewayClasses} {
		if err := mgr.Add(k); err != nil {
			return nil, err
		}
	}
	if o.Webhooks {
		starter := &webhookStarter{mgr: mgr, ready: ready, inject: injector}
		if err := mgr.Add(starter); err != nil {
			return nil, err
		}
		if err := mgr.AddReadyzCheck("webhook", starter.check); err != nil {
			return nil, err
		}
	}
	// Every replica forwards its engines' events and request counts, when
	// the control plane accepts them.
	forwarder := &controlplane.Forwarder{
		Client: mgr.GetClient(), Namespace: o.Namespace, Replica: replicaName(o), OperatorVersion: o.Version,
		CAFile: o.ControlPlaneCAFile, Dir: o.EventsDir, MaxBytes: o.EventsBufferBytes,
	}
	if err := mgr.Add(forwarder); err != nil {
		return nil, err
	}
	if o.DistributionPort != 0 {
		if err := addDistribution(mgr, o, ready, forwarder); err != nil {
			return nil, err
		}
	}
	// The optional control plane: idle in Standalone mode (the default).
	if err := mgr.Add(&controlplane.Connector{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(),
		Namespace: o.Namespace, Replica: replicaName(o), OperatorVersion: o.Version,
		KubernetesVersion: kubernetesVersion(cfg),
		CAFile:            o.ControlPlaneCAFile,
		ProxyPods:         selectors.Selector(integrations.Traefik.Name),
		EngineStale:       engineStale(o),
	}); err != nil {
		return nil, err
	}
	if !o.Webhooks && o.DistributionPort == 0 {
		if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

// addCerts sets up the serving certificate the webhook and the
// distribution server share, and returns a channel closed once it is in
// place: the servers read it when they start.
func addCerts(mgr manager.Manager, o Options) (<-chan struct{}, error) {
	ready := make(chan struct{})
	if !o.Webhooks && o.DistributionPort == 0 {
		return ready, nil
	}
	if o.WebhookCerts == CertsExternal {
		close(ready)
		return ready, nil
	}
	dns := o.WebhookDNSNames
	if len(dns) == 0 {
		if o.Webhooks {
			dns = append(dns, webhook.ServiceDNSNames(o.WebhookService, o.Namespace)...)
		}
		if o.DistributionPort != 0 {
			dns = append(dns, webhook.ServiceDNSNames(o.DistributionService, o.Namespace)...)
		}
	}
	secret := types.NamespacedName{Namespace: o.Namespace, Name: o.WebhookSecret}
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := webhook.EnsureCertSecret(ctx, c, secret); err != nil {
		return nil, err
	}
	err = webhook.AddCertRotator(mgr, webhook.CertOptions{
		Secret:           secret,
		CertDir:          o.WebhookCertDir,
		DNSNames:         dns,
		InjectWebhooks:   o.Webhooks,
		InjectPodWebhook: o.Inject && o.DistributionPort != 0,
	}, ready)
	return ready, err
}

// addDistribution serves bundles to the engines on every replica, and
// reports Enforced from the leader.
func addDistribution(mgr manager.Manager, o Options, ready <-chan struct{}, forwarder *controlplane.Forwarder) error {
	replica := o.Replica
	if replica == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		replica = h
	}
	interval := engineReportInterval(o)
	store, table := distribution.NewStore(), distribution.NewTable()
	if err := (&distribution.BundleSource{Client: mgr.GetClient(), Namespace: o.Namespace, Store: store}).SetupWithManager(mgr); err != nil {
		return err
	}
	auth := &distribution.KubeAuthenticator{Client: mgr.GetClient(), Namespace: o.Namespace, TTL: time.Minute}
	service := distribution.NewServer(store, table, auth, replica, ctrl.Log.WithName("distribution"))
	service.Events, service.Stats = forwarder.Add, forwarder.AddStats
	forwarder.HasPolicy = store.HasPolicy
	srv := &distribution.GRPCServer{
		Port:    o.DistributionPort,
		CertDir: o.WebhookCertDir,
		Ready:   ready,
		Service: service,
	}
	if err := mgr.Add(srv); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("distribution", srv.Check); err != nil {
		return err
	}
	pub := &distribution.Publisher{
		Client:    mgr.GetClient(),
		Reader:    mgr.GetAPIReader(),
		Namespace: o.Namespace,
		Replica:   replica,
		Engines:   table,
		Interval:  interval,
		// The leader ignores a report older than three refreshes.
		Refresh: 5 * interval,
	}
	if o.ReplicaUID != "" {
		pub.Owner = &metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: replica, UID: o.ReplicaUID}
	}
	if err := mgr.Add(pub); err != nil {
		return err
	}
	return mgr.Add(&distribution.Reporter{
		Client:    mgr.GetClient(),
		Reader:    mgr.GetAPIReader(),
		Namespace: o.Namespace,
		Interval:  interval,
		Stale:     engineStale(o),
		Store:     store,
	})
}

// webhookStarter registers the webhooks once the certificate is ready. It
// runs on every replica, leader or not: all of them serve the webhook.
type webhookStarter struct {
	mgr        manager.Manager
	inject     *webhook.PodInjector
	ready      <-chan struct{}
	registered atomic.Bool
}

func (w *webhookStarter) Start(ctx context.Context) error {
	select {
	case <-w.ready:
	case <-ctx.Done():
		return nil
	}
	user, err := webhook.OperatorUser(ctx, w.mgr.GetClient())
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return err
	}
	// The guard reads the mode from the cache: start its informer now, not
	// in the first request, which has 2 s.
	var cfg wafv1alpha1.InkwallConfig
	if err := w.mgr.GetClient().Get(ctx, types.NamespacedName{Name: "default"}, &cfg); client.IgnoreNotFound(err) != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("read the InkwallConfig: %w", err)
	}
	guard := &webhook.SourceGuard{Operator: user, Reader: w.mgr.GetClient()}
	if err := webhook.Setup(w.mgr, w.inject, guard); err != nil {
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

// replicaName is this replica's name: its pod, else the host name.
func replicaName(o Options) string {
	if o.Replica != "" {
		return o.Replica
	}
	host, _ := os.Hostname()
	return host
}

// kubernetesVersion returns a function that asks the API server its
// version once.
func kubernetesVersion(cfg *rest.Config) func() string {
	var (
		once sync.Once
		v    string
	)
	return func() string {
		once.Do(func() {
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			if err != nil {
				return
			}
			if info, err := dc.ServerVersion(); err == nil {
				v = info.GitVersion
			}
		})
		return v
	}
}

// DefaultEventsBufferBytes bounds each replica's events buffer by default.
const DefaultEventsBufferBytes = controlplane.DefaultEventsBufferBytes

// DefaultSigningKeyGrace is the least time each phase of a signing key
// rotation lasts by default: the kubelet's delay to update a mounted
// ConfigMap.
const DefaultSigningKeyGrace = controller.DefaultRotationGrace

// engineStale is how old a replica's engine report may be before the
// leader ignores it: three of the replicas' refreshes (Publisher.Refresh).
func engineStale(o Options) time.Duration { return 15 * engineReportInterval(o) }

// engineReportInterval is how often replicas publish their engines.
func engineReportInterval(o Options) time.Duration {
	if o.EngineReportInterval == 0 {
		return 2 * time.Second
	}
	return o.EngineReportInterval
}
