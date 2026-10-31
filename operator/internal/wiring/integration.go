// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// Integration is the wiring of one proxy (0004 §4.2): the target kinds it
// wires, how, and what it reports on each target. integrations.Integration
// describes the same proxy to discovery and injection. The wiring
// controller runs every integration at each reconcile; several may share a
// kind (Ingress, HTTPRoute), each wiring the targets its proxy serves.
type Integration interface {
	// Name is integrations.Integration.Name, e.g. "traefik", and the
	// integration label of the wiring metrics.
	Name() string
	// Kinds are the target kinds it wires.
	Kinds() []schema.GroupKind
	// Watch has c reconcile when what the wiring reads, besides the
	// policies, changes: routes, classes, the proxy's pods, its own
	// objects.
	Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error
	// Wire wires the targets (those of the live policies, of its kinds)
	// that its proxy serves, and unwires every other route it wired; with
	// off, it unwires them all. It reports on each target, and on what it
	// couldn't do with an error; a nil Result means it did nothing.
	Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error)
	// Wired reports whether a target is still wired, read from the API
	// server: a policy being deleted is released once none of its targets
	// is. A target that doesn't exist isn't.
	Wired(ctx context.Context, t Target) (bool, error)
	// Unwire removes all of its wiring, at uninstall. It counts what it
	// changed, by kind.
	Unwire(ctx context.Context, c client.Client) (map[string]int, error)
}

// Target is a route a policy protects.
type Target struct {
	Kind schema.GroupKind
	Key  types.NamespacedName
	// Section is an HTTPRoute's rule (sectionName), or "" for the route.
	Section string
}

// targetOf is the target of a policy's TargetRef.
func targetOf(namespace string, ref wafv1alpha1.TargetRef) Target {
	group := ref.Group
	if group == "" && ref.Kind == "Ingress" {
		group = networkingv1.GroupName
	}
	return Target{Kind: schema.GroupKind{Group: group, Kind: ref.Kind}, Key: types.NamespacedName{Namespace: namespace, Name: ref.Name}, Section: ref.SectionName}
}

// Result is what an integration did, for Programmed.
type Result struct {
	// Proxy names the proxy in conditions, e.g. "Traefik".
	Proxy string
	// Targets has each target that exists, or that it can't tell about.
	// One that doesn't exist is left out (Accepted reports it).
	Targets map[Target]TargetState
	// Pods are the proxy's pods, whose engine the wired routes go to.
	Pods []corev1.Pod
	// Rolling: the proxy's own controller replaces its pods without the
	// engine (Envoy Gateway, once its EnvoyProxy has it), rather than the
	// Pod webhook injecting new ones; they are PendingRestart.
	Rolling bool
}

// TargetState is a target as an integration sees it.
type TargetState struct {
	// Unsupported: its proxy doesn't serve the target, and why (another
	// proxy does, or none). Another integration may.
	Unsupported string
	// Failed: why it couldn't be wired.
	Failed string
	// Wired: the integration keeps the target wired.
	Wired bool
	// Pending: wired, but not in force yet, and why (the proxy hasn't
	// accepted its configuration yet).
	Pending string
	// Partly: it is wired, but some of its traffic goes through proxies
	// Inkwall doesn't wire, and which.
	Partly string
}

// Config is what the integrations need besides the clients.
type Config struct {
	// Pods select the proxies' pods; nil: the defaults.
	Pods *integrations.Selectors
	// Watches of kinds whose CRD may be missing, once it is installed;
	// nil: only read at each reconcile.
	IngressRoutes, HTTPRoutes, Gateways, GatewayClasses, EnvoyProxies, ExtensionPolicies, TrafficPolicies *crdwatch.Kind
	// Sidecar is the engine Envoy Gateway's pods get, before the
	// InkwallConfig's settings.
	Sidecar injection.Sidecar
}

// Integrations are the wiring of every proxy Inkwall integrates: Traefik
// and Envoy Gateway.
func Integrations(c client.Client, reader client.Reader, cfg Config) []Integration {
	return []Integration{
		&Traefik{
			Client: c, APIReader: reader, Pods: cfg.Pods.Selector(integrations.Traefik.Name),
			IngressRoutes: cfg.IngressRoutes, HTTPRoutes: cfg.HTTPRoutes, Gateways: cfg.Gateways, GatewayClasses: cfg.GatewayClasses,
		},
		&EnvoyGateway{
			Client: c, APIReader: reader, Pods: cfg.Pods.Selector(integrations.EnvoyGateway.Name), Sidecar: cfg.Sidecar,
			HTTPRoutes: cfg.HTTPRoutes, Gateways: cfg.Gateways, GatewayClasses: cfg.GatewayClasses,
			EnvoyProxies: cfg.EnvoyProxies, ExtensionPolicies: cfg.ExtensionPolicies, TrafficPolicies: cfg.TrafficPolicies,
		},
	}
}

var (
	wiredTargets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_wired_targets",
		Help: "Policy targets wired to the engine, by integration. Reported by the leader.",
	}, []string{"integration"})
	wiringFailures = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_wiring_failures",
		Help: "Policy targets that couldn't be wired (Programmed: WiringFailed), by integration. Reported by the leader.",
	}, []string{"integration"})
)

func init() {
	metrics.Registry.MustRegister(wiredTargets, wiringFailures)
}

// record sets an integration's metrics from its result.
func record(name string, res *Result) {
	wired, failed := 0, 0
	for _, s := range res.Targets {
		switch {
		case s.Failed != "":
			failed++
		case s.Wired:
			wired++
		}
	}
	wiredTargets.WithLabelValues(name).Set(float64(wired))
	wiringFailures.WithLabelValues(name).Set(float64(failed))
}

// kindList names kinds for a message: "Ingress and IngressRoute".
func kindList(kinds []schema.GroupKind) string {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = k.Kind
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// count is "2 Ingress(es)", "1 IngressRoute(s)".
func count(n int, kind string) string {
	if strings.HasSuffix(kind, "s") {
		return fmt.Sprintf("%d %s(es)", n, kind)
	}
	return fmt.Sprintf("%d %s(s)", n, kind)
}
