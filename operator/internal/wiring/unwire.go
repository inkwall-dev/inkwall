// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"maps"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

const unwiredMessage = "the routes were unwired at uninstall (inkwall-operator unwire), and no operator wires them"

// Unwired counts what Unwire changed.
type Unwired struct {
	// Objects counts the proxies' objects unwired or deleted, by kind.
	Objects  map[string]int
	Policies int
}

// Unwire undoes the wiring at uninstall: every integration removes its
// wiring, keeping the user's own (for Traefik, the operator's Middleware
// from every Ingress, IngressRoute and HTTPRoute it wired, then the
// Middlewares it created). Then every WAFPolicy is reported
// Programmed=False and Ready=False (Unwired), and released from the
// finalizer, which no operator will remove any more. The proxies then
// stop sending those routes to the engine, which a proxy pod started after
// the uninstall doesn't have. Run it with the operator stopped, or it wires
// them again.
func Unwire(ctx context.Context, c client.Client) (Unwired, error) {
	n := Unwired{Objects: map[string]int{}}
	for _, in := range Integrations(c, c, Config{}) {
		counts, err := in.Unwire(ctx, c)
		maps.Copy(n.Objects, counts)
		if err != nil {
			return n, fmt.Errorf("%s: %w", in.Name(), err)
		}
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
		// No operator will report it any more; Ready follows Programmed.
		if p.DeletionTimestamp == nil {
			err := setProgrammed(ctx, c, p, metav1.ConditionFalse, ReasonUnwired, unwiredMessage, true)
			if client.IgnoreNotFound(err) != nil {
				return n, fmt.Errorf("set the status of WAFPolicy %s/%s: %w", p.Namespace, p.Name, err)
			}
		}
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
			return setFinalizer(ctx, c, p, false)
		})
		if client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("remove the finalizer from WAFPolicy %s/%s: %w", p.Namespace, p.Name, err)
		}
		n.Policies++
	}
	return n, nil
}

// Unwire implements Integration: it removes the operator's Middleware from
// every Ingress, IngressRoute and HTTPRoute it wired, then deletes the
// Middlewares.
func (*Traefik) Unwire(ctx context.Context, c client.Client) (map[string]int, error) {
	n := map[string]int{}
	var list networkingv1.IngressList
	if err := c.List(ctx, &list); err != nil {
		return n, fmt.Errorf("list Ingresses: %w", err)
	}
	for i := range list.Items {
		ing := &list.Items[i]
		if ing.Annotations[WiredAnnotation] == "" {
			continue
		}
		if err := annotate(ctx, c, ing, false); err != nil {
			return n, fmt.Errorf("unwire Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		n["Ingress"]++
	}

	routes := &unstructured.UnstructuredList{}
	routes.SetGroupVersionKind(integrations.TraefikIngressRouteGVK.GroupVersion().WithKind("IngressRouteList"))
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
			return wireRoute(ctx, c, ir, false)
		})
		if client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("unwire IngressRoute %s/%s: %w", ir.GetNamespace(), ir.GetName(), err)
		}
		n["IngressRoute"]++
	}

	hrs := &unstructured.UnstructuredList{}
	hrs.SetGroupVersionKind(HTTPRouteGVK.GroupVersion().WithKind("HTTPRouteList"))
	switch err := c.List(ctx, hrs); {
	case meta.IsNoMatchError(err): // the Gateway API's CRDs are gone
	case err != nil:
		return n, fmt.Errorf("list HTTPRoutes: %w", err)
	}
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if hr.GetAnnotations()[WiredAnnotation] != MiddlewareName {
			continue
		}
		first := true
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if !first {
				if err := c.Get(ctx, client.ObjectKeyFromObject(hr), hr); err != nil {
					return err
				}
			}
			first = false
			return wireHTTPRoute(ctx, c, hr, nil)
		})
		if client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("unwire HTTPRoute %s/%s: %w", hr.GetNamespace(), hr.GetName(), err)
		}
		n["HTTPRoute"]++
	}

	// After the routes: a router referring to a missing Middleware fails.
	mws := &unstructured.UnstructuredList{}
	mws.SetGroupVersionKind(integrations.TraefikMiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
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
		n["Middleware"]++
	}
	return n, nil
}
