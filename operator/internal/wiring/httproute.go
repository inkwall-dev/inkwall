// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
)

// rules selects an HTTPRoute's rules by name; "" selects them all. nil
// selects none.
type rules map[string]bool

func (r rules) with(section string) rules {
	if r == nil {
		r = rules{}
	}
	r[section] = true
	return r
}

func (r rules) has(name string) bool { return r[""] || name != "" && r[name] }

// any reports whether r selects a rule of hr, or all of them.
func (r rules) any(hr *gatewayv1.HTTPRoute) bool {
	return r[""] || slices.ContainsFunc(hr.Spec.Rules, func(rule gatewayv1.HTTPRouteRule) bool {
		return rule.Name != nil && r.has(string(*rule.Name))
	})
}

// isFilter reports whether a rule's filter is the operator's: an
// ExtensionRef to the Middleware in the route's namespace.
func isFilter(f any) bool {
	filter, _ := f.(map[string]any)
	ref, _ := filter["extensionRef"].(map[string]any)
	return filter["type"] == string(gatewayv1.HTTPRouteFilterExtensionRef) &&
		ref["group"] == integrations.TraefikMiddlewareGVK.Group && ref["kind"] == integrations.TraefikMiddlewareGVK.Kind && ref["name"] == MiddlewareName
}

// WithRuleFilter adds the operator's Middleware, as an ExtensionRef filter,
// first to the rules of an HTTPRoute that sel selects, and removes it from
// the others. The reference has no namespace: Traefik looks the Middleware
// up in the HTTPRoute's. The user's filters stay, in order. It reports
// whether hr changed.
func WithRuleFilter(hr *unstructured.Unstructured, sel rules) (bool, error) {
	list, _, err := unstructured.NestedSlice(hr.Object, "spec", "rules")
	if err != nil {
		return false, err
	}
	changed := false
	for i, r := range list {
		rule, ok := r.(map[string]any)
		if !ok {
			return false, fmt.Errorf("spec.rules[%d] is not an object", i)
		}
		name, _ := rule["name"].(string)
		filters, _ := rule["filters"].([]any)
		has := slices.ContainsFunc(filters, isFilter)
		switch want := sel.has(name); {
		case want && !has:
			ours := map[string]any{
				"type": string(gatewayv1.HTTPRouteFilterExtensionRef),
				"extensionRef": map[string]any{
					"group": integrations.TraefikMiddlewareGVK.Group, "kind": integrations.TraefikMiddlewareGVK.Kind, "name": MiddlewareName,
				},
			}
			rule["filters"] = append([]any{ours}, filters...)
		case !want && has:
			if filters = slices.DeleteFunc(filters, isFilter); len(filters) == 0 {
				delete(rule, "filters")
			} else {
				rule["filters"] = filters
			}
		default:
			continue
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, unstructured.SetNestedSlice(hr.Object, list, "spec", "rules")
}

// setRuleFilters wires the rules of hr that sel selects, or unwires it (sel
// nil) if the operator wired it, and marks it. It reports whether hr
// changed.
func setRuleFilters(hr *unstructured.Unstructured, sel rules) (bool, error) {
	wired := hr.GetAnnotations()[WiredAnnotation] == MiddlewareName
	if sel == nil && !wired {
		return false, nil
	}
	changed, err := WithRuleFilter(hr, sel)
	if err != nil || sel != nil && !changed && wired {
		return false, err
	}
	annotations := hr.GetAnnotations()
	if sel != nil {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[WiredAnnotation] = MiddlewareName
	} else {
		delete(annotations, WiredAnnotation)
	}
	hr.SetAnnotations(annotations)
	return true, nil
}

// wireHTTPRoute wires the rules of an HTTPRoute that sel selects, or
// unwires it (sel nil). Only the operator's filters change; the user's stay,
// in order.
func wireHTTPRoute(ctx context.Context, c client.Client, hr *unstructured.Unstructured, sel rules) error {
	orig := hr.DeepCopy()
	if changed, err := setRuleFilters(hr, sel); !changed || err != nil {
		return err
	}
	// spec.rules is one list to a merge patch: the resourceVersion makes
	// sure it doesn't overwrite a change the cache hasn't seen.
	return c.Patch(ctx, hr, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}

// wireHTTPRoute is wireHTTPRoute for a route from the cache. It reads the
// route from the API server before writing it: the cache holds it typed,
// without the fields these Gateway API types don't know, which a write of
// spec.rules would drop.
func (t *Traefik) wireHTTPRoute(ctx context.Context, hr *gatewayv1.HTTPRoute, sel rules) error {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(hr)
	if err != nil {
		return err
	}
	if changed, err := setRuleFilters(&unstructured.Unstructured{Object: obj}, sel); !changed || err != nil {
		return err
	}
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(HTTPRouteGVK)
	if err := t.APIReader.Get(ctx, client.ObjectKeyFromObject(hr), cur); err != nil {
		return client.IgnoreNotFound(err)
	}
	return wireHTTPRoute(ctx, t.Client, cur, sel)
}

// httpRoutes lists the HTTPRoutes, none when their CRD isn't installed,
// with the controllers of the Gateways their parentRefs name.
func (t *Traefik) httpRoutes(ctx context.Context) (map[types.NamespacedName]*gatewayv1.HTTPRoute, map[types.NamespacedName][]string, error) {
	routes := map[types.NamespacedName]*gatewayv1.HTTPRoute{}
	controllers := map[types.NamespacedName][]string{}
	if ok, err := crdwatch.Installed(t.Client.RESTMapper(), HTTPRouteGVK); !ok || err != nil {
		return routes, controllers, err
	}
	var list gatewayv1.HTTPRouteList
	if err := t.Client.List(ctx, &list); err != nil {
		return nil, nil, err
	}

	// GatewayClass name -> controller, Gateway -> its class's controller.
	classes := map[string]string{}
	if ok, err := crdwatch.Installed(t.Client.RESTMapper(), GatewayClassGVK); err != nil {
		return nil, nil, err
	} else if ok {
		// Unstructured, as discovery reads them: one informer.
		gcs := &unstructured.UnstructuredList{}
		gcs.SetGroupVersionKind(GatewayClassGVK.GroupVersion().WithKind("GatewayClassList"))
		if err := t.Client.List(ctx, gcs); err != nil {
			return nil, nil, err
		}
		for _, gc := range gcs.Items {
			classes[gc.GetName()], _, _ = unstructured.NestedString(gc.Object, "spec", "controllerName")
		}
	}
	gateways := map[types.NamespacedName]string{}
	if ok, err := crdwatch.Installed(t.Client.RESTMapper(), GatewayGVK); err != nil {
		return nil, nil, err
	} else if ok {
		var gws gatewayv1.GatewayList
		if err := t.Client.List(ctx, &gws); err != nil {
			return nil, nil, err
		}
		for _, gw := range gws.Items {
			gateways[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = classes[string(gw.Spec.GatewayClassName)]
		}
	}

	for i := range list.Items {
		hr := &list.Items[i]
		k := types.NamespacedName{Namespace: hr.Namespace, Name: hr.Name}
		routes[k] = hr
		var cs []string
		for _, p := range hr.Spec.ParentRefs {
			if p.Group != nil && *p.Group != gatewayv1.GroupName || p.Kind != nil && *p.Kind != "Gateway" {
				continue // a Service (a mesh), or another kind of parent
			}
			gw := types.NamespacedName{Namespace: hr.Namespace, Name: string(p.Name)}
			if p.Namespace != nil {
				gw.Namespace = string(*p.Namespace)
			}
			if c := gateways[gw]; c != "" {
				cs = append(cs, c)
			}
		}
		slices.Sort(cs)
		controllers[k] = slices.Compact(cs)
	}
	return routes, controllers, nil
}

// gatewayControllers reports whether a Traefik Gateway serves an HTTPRoute,
// and the controllers of its other Gateways.
func (st *state) gatewayControllers(k types.NamespacedName) (traefik bool, others []string) {
	for _, c := range st.controllers[k] {
		if c == integrations.Traefik.GatewayController {
			traefik = true
		} else {
			others = append(others, c)
		}
	}
	return traefik, others
}

// traefikOnly reports whether an HTTPRoute is served by Traefik's Gateways
// and no other controller's.
func (st *state) traefikOnly(k types.NamespacedName) bool {
	traefik, others := st.gatewayControllers(k)
	return traefik && len(others) == 0
}
