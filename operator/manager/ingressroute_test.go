// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// routeMiddlewares lists an IngressRoute's Middleware names, "," between
// Middlewares and "|" between routes.
func routeMiddlewares(ir *unstructured.Unstructured) string {
	routes, _, _ := unstructured.NestedSlice(ir.Object, "spec", "routes")
	var out []string
	for _, r := range routes {
		var names []string
		mws, _ := r.(map[string]any)["middlewares"].([]any)
		for _, m := range mws {
			name, _ := m.(map[string]any)["name"].(string)
			names = append(names, name)
		}
		out = append(out, strings.Join(names, ","))
	}
	return strings.Join(out, "|")
}

// testIngressRoutes follows a policy on a Traefik IngressRoute: the
// operator runs without the IngressRoute CRD, notices it once installed,
// wires the routes (keeping the user's Middlewares), puts them in the
// bundle, reports a rule it can't read, and unwires when the policy goes.
// It runs after testWiring, whose Traefik pod has the engine.
func testIngressRoutes(ctx context.Context, t *testing.T, c client.Client) {
	const ns = "routes"
	key := types.NamespacedName{Namespace: ns, Name: "app"}
	cond := func(p *wafv1alpha1.WAFPolicy, typ string, st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
				return err.Error()
			}
			cnd := meta.FindStatusCondition(got.Status.Conditions, typ)
			if cnd == nil {
				return "no " + typ
			}
			if cnd.Status != st || cnd.Reason != reason || !strings.Contains(cnd.Message, msg) || cnd.ObservedGeneration != got.Generation {
				return typ + ": " + string(cnd.Status) + " " + cnd.Reason + ": " + cnd.Message
			}
			return ""
		}
	}
	getRoute := func() (*unstructured.Unstructured, error) {
		ir := &unstructured.Unstructured{}
		ir.SetGroupVersionKind(integrations.TraefikIngressRouteGVK)
		return ir, c.Get(ctx, key, ir)
	}

	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Group: "traefik.io", Kind: "IngressRoute", Name: "app"}},
			Mode:       wafv1alpha1.PolicyBlock,
		},
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// No IngressRoute CRD: the operator runs, and says so.
	eventually(t, "Programmed without the CRD", cond(pol, wafv1alpha1.ConditionProgrammed, metav1.ConditionFalse,
		wiring.ReasonWiringFailed, "Traefik's IngressRoute CRD is not installed"))
	eventually(t, "Accepted without the CRD", cond(pol, wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonInvalidRef, "IngressRoute app not found"))

	// Installed later, then the route, with the user's Middleware on one of
	// its routes.
	if err := testenv.InstallLater(env); err != nil {
		t.Fatal(err)
	}
	ir := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"entryPoints": []any{"web"},
		"routes": []any{
			map[string]any{"kind": "Rule", "match": "Host(`app.example.com`) && PathPrefix(`/api`)",
				"middlewares": []any{map[string]any{"name": "auth"}},
				"services":    []any{map[string]any{"name": "app", "port": int64(80)}}},
			map[string]any{"kind": "Rule", "match": "Host(`app.example.com`) && Path(`/login`)",
				"services": []any{map[string]any{"name": "app", "port": int64(80)}}},
		},
	}}}
	ir.SetGroupVersionKind(integrations.TraefikIngressRouteGVK)
	ir.SetNamespace(ns)
	ir.SetName("app")
	if err := c.Create(ctx, ir); err != nil {
		t.Fatal(err)
	}

	eventually(t, "the IngressRoute wired", func() string {
		got, err := getRoute()
		if err != nil {
			return err.Error()
		}
		if m := routeMiddlewares(got); m != "inkwall-waf,auth|inkwall-waf" {
			return "middlewares " + m
		}
		if got.GetAnnotations()[wiring.WiredAnnotation] != wiring.MiddlewareName {
			return "no marker"
		}
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: wiring.MiddlewareName}, m); err != nil {
			return "Middleware: " + err.Error()
		}
		return ""
	})
	eventually(t, "Programmed", cond(pol, wafv1alpha1.ConditionProgrammed, metav1.ConditionTrue, wiring.ReasonProgrammed, "1 IngressRoute(s) wired"))
	eventually(t, "Accepted", cond(pol, wafv1alpha1.ConditionAccepted, metav1.ConditionTrue, resolver.ReasonAccepted, ""))
	eventually(t, "the routes in the bundle", func() string {
		p := findPolicy(current(ctx, t, c), ns+"/app")
		if p == nil {
			return "not in the bundle"
		}
		var got []string
		for _, r := range p.GetRoutes() {
			got = append(got, r.GetHost()+" "+bundlev1.PathMatchType_name[int32(r.GetPath().GetType())]+" "+r.GetPath().GetValue())
		}
		if s := strings.Join(got, ", "); s != "app.example.com PATH_MATCH_TYPE_PREFIX /api, app.example.com PATH_MATCH_TYPE_EXACT /login" {
			return s
		}
		return ""
	})

	// A rule the engine can't match on: not accepted, the route named; the
	// bundle keeps the previous version.
	update(ctx, t, c, ir, func(u *unstructured.Unstructured) {
		routes, _, _ := unstructured.NestedSlice(u.Object, "spec", "routes")
		routes[1].(map[string]any)["match"] = "Host(`app.example.com`) && (Path(`/login`) || Path(`/logout`))"
		_ = unstructured.SetNestedSlice(u.Object, routes, "spec", "routes")
	})
	eventually(t, "Accepted=False on an unreadable rule", cond(pol, wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonTargetUnsupported, "IngressRoute app: spec.routes[1] match"))
	if p := findPolicy(current(ctx, t, c), ns+"/app"); p == nil || len(p.GetRoutes()) != 2 {
		t.Errorf("the previous version must stay in the bundle: %v", p)
	}

	// The policy deleted: Inkwall's entries, marker and Middleware go, the
	// user's stay.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unwired", func() string {
		got, err := getRoute()
		if err != nil {
			return err.Error()
		}
		if m := routeMiddlewares(got); m != "auth|" {
			return "middlewares " + m
		}
		if _, ok := got.GetAnnotations()[wiring.WiredAnnotation]; ok {
			return "marker still there"
		}
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: wiring.MiddlewareName}, m); !apierrors.IsNotFound(err) {
			return "Middleware still there"
		}
		return ""
	})
}
