// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Unwire undoes the wiring at uninstall: it removes the operator's
// Middleware from every Ingress it wired, keeping the user's own, then
// deletes the Middlewares it created. Traefik then stops sending those
// routes to the engine, which a proxy pod started after the uninstall
// doesn't have. Run it with the operator stopped, or it wires them again.
// It returns how many Ingresses and Middlewares it changed.
func Unwire(ctx context.Context, c client.Client) (ingresses, middlewares int, err error) {
	var list networkingv1.IngressList
	if err := c.List(ctx, &list); err != nil {
		return 0, 0, fmt.Errorf("list Ingresses: %w", err)
	}
	r := &Reconciler{Client: c}
	for i := range list.Items {
		ing := &list.Items[i]
		if ing.Annotations[WiredAnnotation] == "" {
			continue
		}
		if err := r.annotate(ctx, ing, false); err != nil {
			return ingresses, 0, fmt.Errorf("unwire Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		ingresses++
	}

	// After the Ingresses: a router referring to a missing Middleware fails.
	mws := &unstructured.UnstructuredList{}
	mws.SetGroupVersionKind(MiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
	if err := c.List(ctx, mws, client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}); err != nil {
		if meta.IsNoMatchError(err) {
			return ingresses, 0, nil // Traefik's CRDs are gone
		}
		return ingresses, 0, fmt.Errorf("list Middlewares: %w", err)
	}
	for i := range mws.Items {
		m := &mws.Items[i]
		if m.GetName() != MiddlewareName {
			continue
		}
		if err := c.Delete(ctx, m); client.IgnoreNotFound(err) != nil {
			return ingresses, middlewares, fmt.Errorf("delete Middleware %s/%s: %w", m.GetNamespace(), m.GetName(), err)
		}
		middlewares++
	}
	return ingresses, middlewares, nil
}
