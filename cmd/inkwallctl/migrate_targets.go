// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"errors"
	"maps"
	"slices"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

// This file points a migrated policy at the routes that replace its
// Ingress (--target httproute or ingressroute). A route replaces it when
// the operator would protect the same requests through it: the route, or
// a named rule of an HTTPRoute, matches only hosts and paths of the
// Ingress, and together the targets match all of them. Hosts and paths are
// compared as the operator's resolver expands them, so nothing is guessed:
// what doesn't line up is TODO.

// The --target values.
const (
	targetIngress      = "ingress"
	targetHTTPRoute    = "httproute"
	targetIngressRoute = "ingressroute"
)

// maxTargets is the CRD's limit on targetRefs.
const maxTargets = 16

// httpRouteGroup is Gateway API's group.
const httpRouteGroup = "gateway.networking.k8s.io"

// candidate is a route a policy can target, and the requests it matches.
type candidate struct {
	ref     wafv1alpha1.TargetRef
	matches map[string]bool // routeMatchKey
}

// replacements are the routes the Ingresses move to, by namespace.
type replacements struct {
	kind       string // HTTPRoute or IngressRoute
	candidates map[string][]candidate
}

// newReplacements expands the routes into candidates: each route, and each
// named rule of an HTTPRoute. Routes the resolver can't expand (header
// matches, regular expressions) are left out.
func newReplacements(kind string, httpRoutes []gatewayv1.HTTPRoute, ingressRoutes []unstructured.Unstructured) *replacements {
	r := &replacements{kind: kind, candidates: map[string][]candidate{}}
	add := func(namespace string, ref wafv1alpha1.TargetRef, in resolver.Input) {
		if m, err := routeMatches(in, namespace, ref); err == nil && len(m) > 0 {
			r.candidates[namespace] = append(r.candidates[namespace], candidate{ref: ref, matches: m})
		}
	}
	for _, hr := range httpRoutes {
		in := resolver.Input{HTTPRoutes: []gatewayv1.HTTPRoute{hr}}
		ref := wafv1alpha1.TargetRef{Group: httpRouteGroup, Kind: "HTTPRoute", Name: hr.Name}
		add(hr.Namespace, ref, in)
		for _, rule := range hr.Spec.Rules {
			if rule.Name != nil {
				ref.SectionName = string(*rule.Name)
				add(hr.Namespace, ref, in)
			}
		}
	}
	for _, ir := range ingressRoutes {
		in := resolver.Input{IngressRoutes: []unstructured.Unstructured{ir}}
		add(ir.GetNamespace(), wafv1alpha1.TargetRef{Group: ingressRouteGVK.Group, Kind: "IngressRoute", Name: ir.GetName()}, in)
	}
	for _, cands := range r.candidates {
		slices.SortFunc(cands, func(a, b candidate) int {
			return cmp.Or(cmp.Compare(a.ref.Name, b.ref.Name), cmp.Compare(a.ref.SectionName, b.ref.SectionName))
		})
	}
	return r
}

// routeMatches resolves a policy targeting ref alone, and returns the
// requests it would apply to.
func routeMatches(in resolver.Input, namespace string, ref wafv1alpha1.TargetRef) (map[string]bool, error) {
	in.Policies = []wafv1alpha1.WAFPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "migrate"},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{ref}, Mode: wafv1alpha1.PolicyDetect},
	}}
	res := resolver.Resolve(in)
	if len(res.Policies) == 0 {
		return nil, errors.New(res.PolicyStatus[types.NamespacedName{Namespace: namespace, Name: "migrate"}].Message)
	}
	m := map[string]bool{}
	for _, rm := range res.Policies[0].GetRoutes() {
		m[routeMatchKey(rm)] = true
	}
	return m, nil
}

// routeMatchKey is a route match as the summary shows it, and the key that
// compares matches: host, path, exact or prefix, methods.
func routeMatchKey(m *bundlev1.RouteMatch) string {
	s := cmp.Or(m.GetHost(), "*") + m.GetPath().GetValue()
	if m.GetPath().GetType() == bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT {
		s += " (exact)"
	}
	if len(m.GetMethods()) > 0 {
		s += " (" + strings.Join(m.GetMethods(), ",") + ")"
	}
	return s
}

// retarget points m's policy at the routes replacing ing. When none does,
// the policy keeps the Ingress as its target, with a TODO.
func (r *replacements) retarget(m *migration, ing *networkingv1.Ingress) {
	if m.policy == nil {
		return
	}
	keep := func(format string, args ...any) {
		m.add(itemTodo, "", "targetRefs: "+format+"; the policy still targets the Ingress", args...)
	}
	want, err := routeMatches(resolver.Input{Ingresses: []networkingv1.Ingress{*ing}}, ing.Namespace,
		wafv1alpha1.TargetRef{Kind: "Ingress", Name: ing.Name})
	switch {
	case err != nil:
		keep("the Ingress's hosts and paths can't be read: %v", err)
		return
	case len(want) == 0:
		keep("the Ingress has no host or path to look for in the %ss", r.kind)
		return
	}

	// Whole routes first; a rule of a route only when the route matches
	// requests the Ingress doesn't.
	var chosen []candidate
	whole := map[string]bool{}
	subset := func(c candidate) bool {
		for k := range c.matches {
			if !want[k] {
				return false
			}
		}
		return true
	}
	for _, sections := range []bool{false, true} {
		for _, c := range r.candidates[ing.Namespace] {
			if (c.ref.SectionName != "") != sections || whole[c.ref.Name] || !subset(c) {
				continue
			}
			if !sections {
				whole[c.ref.Name] = true
			}
			chosen = append(chosen, c)
		}
	}
	if len(chosen) == 0 {
		keep("no %s (or named rule of one) in namespace %s matches only hosts and paths of the Ingress (%s)",
			r.kind, ing.Namespace, strings.Join(slices.Sorted(maps.Keys(want)), ", "))
		return
	}
	if len(chosen) > maxTargets {
		m.add(itemTodo, "", "targetRefs: %d %s targets, more than a WAFPolicy's %d: the last %d are left out", len(chosen), r.kind, maxTargets, len(chosen)-maxTargets)
		chosen = chosen[:maxTargets]
	}
	var (
		refs    []wafv1alpha1.TargetRef
		names   []string
		covered = map[string]bool{}
	)
	for _, c := range chosen {
		refs = append(refs, c.ref)
		maps.Copy(covered, c.matches)
		name := c.ref.Kind + " " + c.ref.Name
		if c.ref.SectionName != "" {
			name = "rule " + c.ref.SectionName + " of " + name
		}
		names = append(names, name)
	}
	m.policy.Spec.TargetRefs = refs
	m.add(itemMapped, "", "targetRefs: %s: the Ingress's hosts and paths", strings.Join(names, ", "))
	var missing []string
	for k := range want {
		if !covered[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		m.add(itemTodo, "", "targetRefs: no %s target matches %s of the Ingress: those requests are not protected until one does",
			r.kind, strings.Join(missing, ", "))
	}
}
