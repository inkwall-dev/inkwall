// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
)

// Disable wraps an integration the operator may not wire, and why (its
// ClusterRole isn't granted, 0004 §7). The wrapper neither watches nor
// touches the proxy's objects, which it may not read; it reads only the
// routes and classes, which every integration may, to report the targets
// its proxy serves as IntegrationDisabled. It can't unwire them: what it
// wired before stays wired, and a deleted policy isn't held for it. cfg
// has the watches of the routes and classes.
func Disable(in Integration, why string, c client.Client, cfg Config) Integration {
	d := &disabledIntegration{Integration: in, why: why, client: c, cfg: cfg}
	for _, p := range integrations.All {
		if p.Name == in.Name() {
			d.proxy = p
		}
	}
	return d
}

type disabledIntegration struct {
	Integration
	why    string
	proxy  integrations.Integration
	client client.Client
	cfg    Config
}

// Watch implements Integration: the routes and classes of its kinds.
func (d *disabledIntegration) Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error {
	for _, k := range d.Kinds() {
		switch k {
		case ingressKind:
			for _, obj := range []client.Object{&networkingv1.Ingress{}, &networkingv1.IngressClass{}} {
				if err := c.Watch(source.Kind(cache, obj, h)); err != nil {
					return err
				}
			}
		case routeKind:
			addWatches(c, h, d.cfg.IngressRoutes)
		case httpRouteKind:
			addWatches(c, h, d.cfg.HTTPRoutes, d.cfg.Gateways, d.cfg.GatewayClasses)
		}
	}
	return nil
}

func addWatches(c controller.Controller, h handler.EventHandler, kinds ...*crdwatch.Kind) {
	for _, k := range kinds {
		if k != nil {
			k.Add(c, h)
		}
	}
}

// Wire implements Integration: it wires nothing, and reports the targets
// its proxy serves.
func (d *disabledIntegration) Wire(ctx context.Context, targets map[Target]bool, _ bool) (*Result, error) {
	res := &Result{Proxy: d.Name(), Targets: map[Target]TargetState{}, Disabled: d.why}
	for t := range targets {
		switch served, err := d.serves(ctx, t); {
		case err != nil:
			return nil, err
		case served:
			res.Targets[t] = TargetState{}
		}
	}
	return res, nil
}

// Wired implements Integration: none is, as far as the policies go.
func (*disabledIntegration) Wired(context.Context, Target) (bool, error) { return false, nil }

// serves reports whether its proxy serves a target that exists: an Ingress
// of its IngressClass, an HTTPRoute with a Gateway of its GatewayClass, or
// a route of its own kind (IngressRoute).
func (d *disabledIntegration) serves(ctx context.Context, t Target) (bool, error) {
	switch t.Kind {
	case ingressKind:
		var ing networkingv1.Ingress
		if err := d.client.Get(ctx, t.Key, &ing); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		var list networkingv1.IngressClassList
		if err := d.client.List(ctx, &list); err != nil {
			return false, err
		}
		classes, defaultClass := map[string]string{}, ""
		for i := range list.Items {
			ic := &list.Items[i]
			classes[ic.Name] = ic.Spec.Controller
			if IsDefaultClass(ic) {
				defaultClass = ic.Name
			}
		}
		c := Controller(&ing, classes, defaultClass)
		return c != "" && c == d.proxy.Controller, nil
	case httpRouteKind:
		var hr gatewayv1.HTTPRoute
		if ok, err := d.get(ctx, t.Key, &hr); !ok {
			return false, err
		}
		for _, p := range hr.Spec.ParentRefs {
			if p.Group != nil && *p.Group != gatewayv1.GroupName || p.Kind != nil && *p.Kind != "Gateway" {
				continue
			}
			key := types.NamespacedName{Namespace: hr.Namespace, Name: string(p.Name)}
			if p.Namespace != nil {
				key.Namespace = string(*p.Namespace)
			}
			var gw gatewayv1.Gateway
			if ok, err := d.get(ctx, key, &gw); !ok {
				if err != nil {
					return false, err
				}
				continue
			}
			gc := &unstructured.Unstructured{}
			gc.SetGroupVersionKind(GatewayClassGVK)
			if ok, err := d.get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, gc); !ok {
				if err != nil {
					return false, err
				}
				continue
			}
			if c, _, _ := unstructured.NestedString(gc.Object, "spec", "controllerName"); c != "" && c == d.proxy.GatewayController {
				return true, nil
			}
		}
		return false, nil
	}
	m, err := d.client.RESTMapper().RESTMapping(t.Kind)
	if err != nil {
		if meta.IsNoMatchError(err) {
			err = nil
		}
		return false, err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(m.GroupVersionKind)
	return d.get(ctx, t.Key, u)
}

// get reads obj from the cache: false, with no error, if it or its CRD
// doesn't exist.
func (d *disabledIntegration) get(ctx context.Context, key types.NamespacedName, obj client.Object) (bool, error) {
	gvk, err := apiutil.GVKForObject(obj, d.client.Scheme())
	if err != nil {
		return false, err
	}
	if ok, err := crdwatch.Installed(d.client.RESTMapper(), gvk); !ok {
		return false, err
	}
	switch err := d.client.Get(ctx, key, obj); {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}
