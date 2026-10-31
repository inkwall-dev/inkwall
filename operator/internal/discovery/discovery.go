// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package discovery finds the cluster's proxies (0004 §4.1): the
// controllers its IngressClasses and GatewayClasses name, and how far
// Inkwall wires each, in InkwallConfig.status.proxies.
package discovery

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
)

// The discovery controller reads the classes and writes the InkwallConfig's
// status.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=inkwallconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=inkwallconfigs/status,verbs=get;update;patch

// GatewayClassGVK is the Gateway API's GatewayClass, whose CRD may be
// missing.
var GatewayClassGVK = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GatewayClass"}

// The route kinds of each class: what an integration must wire for its
// classes to be supported.
var (
	ingressKind   = schema.GroupKind{Group: networkingv1.GroupName, Kind: "Ingress"}
	httpRouteKind = schema.GroupKind{Group: GatewayClassGVK.Group, Kind: "HTTPRoute"}
)

// Class is an IngressClass or a GatewayClass.
type Class struct {
	Name, Controller string
}

// Reconciler writes the discovered proxies into the InkwallConfig, when
// there is one. It runs on the leader.
type Reconciler struct {
	Client client.Client
	// GatewayClasses watches the GatewayClasses once their CRD is
	// installed; nil: they are only read at each reconcile.
	GatewayClasses *crdwatch.Kind
	// Kinds are the target kinds each integration wires, by name.
	Kinds map[string][]schema.GroupKind
	// Disabled are the integrations the operator may not wire, by name,
	// and why: their proxies are Unsupported.
	Disabled map[string]string
}

var request = reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}}

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{request}
	})
	c, err := ctrl.NewControllerManagedBy(mgr).
		Named("discovery").
		// Created, or its spec changed: not its status, which this writes.
		Watches(&wafv1alpha1.InkwallConfig{}, enqueue, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&networkingv1.IngressClass{}, enqueue).
		Build(r)
	if err != nil {
		return err
	}
	if r.GatewayClasses != nil {
		r.GatewayClasses.Add(c, enqueue)
	}
	return nil
}

// Reconcile lists the classes and records their controllers.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	var ingressClasses networkingv1.IngressClassList
	if err := r.Client.List(ctx, &ingressClasses); err != nil {
		return reconcile.Result{}, err
	}
	var ics, gcs []Class
	for _, ic := range ingressClasses.Items {
		ics = append(ics, Class{Name: ic.Name, Controller: ic.Spec.Controller})
	}
	switch installed, err := crdwatch.Installed(r.Client.RESTMapper(), GatewayClassGVK); {
	case err != nil:
		return reconcile.Result{}, err
	case installed:
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(GatewayClassGVK.GroupVersion().WithKind("GatewayClassList"))
		if err := r.Client.List(ctx, list); err != nil {
			return reconcile.Result{}, err
		}
		for _, gc := range list.Items {
			controller, _, _ := unstructured.NestedString(gc.Object, "spec", "controllerName")
			gcs = append(gcs, Class{Name: gc.GetName(), Controller: controller})
		}
	}
	proxies := Disable(Proxies(ics, gcs, r.Kinds), r.Disabled)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cfg wafv1alpha1.InkwallConfig
		if err := r.Client.Get(ctx, request.NamespacedName, &cfg); err != nil {
			return client.IgnoreNotFound(err)
		}
		if apiequality.Semantic.DeepEqual(cfg.Status.Proxies, proxies) {
			return nil
		}
		cfg.Status.Proxies = proxies
		return r.Client.Status().Update(ctx, &cfg)
	})
	return reconcile.Result{}, err
}

// Disable reports the proxies of the disabled integrations (name -> why)
// Unsupported, with why.
func Disable(proxies []wafv1alpha1.ProxyStatus, disabled map[string]string) []wafv1alpha1.ProxyStatus {
	for i := range proxies {
		if why := disabled[proxies[i].Integration]; why != "" {
			proxies[i].Support, proxies[i].Message = wafv1alpha1.SupportUnsupported, why
		}
	}
	return proxies
}

// Proxies groups the classes by controller, and says how far Inkwall wires
// each: an IngressClass's routes are wired when its integration wires
// Ingresses, a GatewayClass's when it wires HTTPRoutes. kinds are the
// target kinds each integration wires, by name.
func Proxies(ingressClasses, gatewayClasses []Class, kinds map[string][]schema.GroupKind) []wafv1alpha1.ProxyStatus {
	byController := map[string]*wafv1alpha1.ProxyStatus{}
	get := func(controller string) *wafv1alpha1.ProxyStatus {
		p := byController[controller]
		if p == nil {
			p = &wafv1alpha1.ProxyStatus{ControllerName: controller}
			if in := integrations.ForController(controller); in != nil {
				p.Integration = in.Name
			}
			byController[controller] = p
		}
		return p
	}
	for _, c := range ingressClasses {
		p := get(c.Controller)
		p.IngressClasses = append(p.IngressClasses, c.Name)
	}
	for _, c := range gatewayClasses {
		p := get(c.Controller)
		p.GatewayClasses = append(p.GatewayClasses, c.Name)
	}

	var out []wafv1alpha1.ProxyStatus
	for _, controller := range slices.Sorted(maps.Keys(byController)) {
		p := byController[controller]
		slices.Sort(p.IngressClasses)
		slices.Sort(p.GatewayClasses)
		if p.Integration == "" {
			p.Support = wafv1alpha1.SupportUnsupported
			p.Message = "Inkwall has no integration for this controller: its routes can't be protected"
			out = append(out, *p)
			continue
		}
		wired, missing := 0, []string{}
		for _, c := range []struct {
			classes []string
			kind    schema.GroupKind
			what    string
		}{
			{p.IngressClasses, ingressKind, "Ingresses"},
			{p.GatewayClasses, httpRouteKind, "HTTPRoutes (GatewayClasses)"},
		} {
			switch {
			case len(c.classes) == 0:
			case slices.Contains(kinds[p.Integration], c.kind):
				wired++
			default:
				missing = append(missing, c.what)
			}
		}
		switch {
		case len(missing) == 0:
			p.Support = wafv1alpha1.SupportFull
		case wired > 0:
			p.Support = wafv1alpha1.SupportPartial
		default:
			p.Support = wafv1alpha1.SupportUnsupported
		}
		if len(missing) > 0 {
			p.Message = fmt.Sprintf("Inkwall doesn't wire %s's %s yet", p.Integration, strings.Join(missing, " or "))
		}
		out = append(out, *p)
	}
	return out
}
