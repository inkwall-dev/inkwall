// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Unwired counts what Unwire changed.
type Unwired struct {
	Ingresses, IngressRoutes, Middlewares, Policies int
}

// Unwire undoes the wiring at uninstall: it removes the operator's
// Middleware from every Ingress and IngressRoute it wired, keeping the
// user's own, deletes the Middlewares it created, and then removes the
// finalizer from every WAFPolicy, which no operator will remove any more.
// Traefik then stops sending those routes to the engine, which a proxy pod
// started after the uninstall doesn't have. Run it with the operator
// stopped, or it wires them again.
func Unwire(ctx context.Context, c client.Client) (Unwired, error) {
	var n Unwired
	var list networkingv1.IngressList
	if err := c.List(ctx, &list); err != nil {
		return n, fmt.Errorf("list Ingresses: %w", err)
	}
	r := &Reconciler{Client: c}
	for i := range list.Items {
		ing := &list.Items[i]
		if ing.Annotations[WiredAnnotation] == "" {
			continue
		}
		if err := r.annotate(ctx, ing, false); err != nil {
			return n, fmt.Errorf("unwire Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		n.Ingresses++
	}

	routes := &unstructured.UnstructuredList{}
	routes.SetGroupVersionKind(IngressRouteGVK.GroupVersion().WithKind("IngressRouteList"))
	switch err := c.List(ctx, routes); {
	case meta.IsNoMatchError(err): // Traefik's CRDs are gone
	case err != nil:
		return n, fmt.Errorf("list IngressRoutes: %w", err)
	}
	for i := range routes.Items {
		ir := &routes.Items[i]
		if ir.GetAnnotations()[WiredAnnotation] != MiddlewareName {
			continue
		}
		first := true
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if !first {
				if err := c.Get(ctx, client.ObjectKeyFromObject(ir), ir); err != nil {
					return err
				}
			}
			first = false
			return r.wireRoute(ctx, ir, false)
		})
		if client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("unwire IngressRoute %s/%s: %w", ir.GetNamespace(), ir.GetName(), err)
		}
		n.IngressRoutes++
	}

	// After the routes: a router referring to a missing Middleware fails.
	mws := &unstructured.UnstructuredList{}
	mws.SetGroupVersionKind(MiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
	switch err := c.List(ctx, mws, client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}); {
	case meta.IsNoMatchError(err): // Traefik's CRDs are gone
	case err != nil:
		return n, fmt.Errorf("list Middlewares: %w", err)
	}
	for i := range mws.Items {
		m := &mws.Items[i]
		if m.GetName() != MiddlewareName {
			continue
		}
		if err := c.Delete(ctx, m); client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("delete Middleware %s/%s: %w", m.GetNamespace(), m.GetName(), err)
		}
		n.Middlewares++
	}

	// Last: a policy released earlier could go while its routes are wired.
	var policies wafv1alpha1.WAFPolicyList
	switch err := c.List(ctx, &policies); {
	case meta.IsNoMatchError(err): // the CRD is gone
	case err != nil:
		return n, fmt.Errorf("list WAFPolicies: %w", err)
	}
	for i := range policies.Items {
		p := &policies.Items[i]
		if !controllerutil.ContainsFinalizer(p, Finalizer) {
			continue
		}
		first := true
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if !first {
				if err := c.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
					return err
				}
			}
			first = false
			return r.setFinalizer(ctx, p, false)
		})
		if client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("remove the finalizer from WAFPolicy %s/%s: %w", p.Namespace, p.Name, err)
		}
		n.Policies++
	}
	return n, nil
}
