// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// filters lists an HTTPRoute's filters, by ExtensionRef name or type, ","
// between filters and "|" between rules.
func filters(hr *gatewayv1.HTTPRoute) string {
	var out []string
	for _, r := range hr.Spec.Rules {
		var names []string
		for _, f := range r.Filters {
			if f.ExtensionRef != nil {
				names = append(names, string(f.ExtensionRef.Name))
			} else {
				names = append(names, string(f.Type))
			}
		}
		out = append(out, strings.Join(names, ","))
	}
	return strings.Join(out, "|")
}

// testHTTPRoutes follows a policy on a Gateway API HTTPRoute: the operator
// runs without the Gateway API CRDs, notices them once installed, puts the
// route's matches in the bundle and reports a match it can't read. Once
// the route is attached to a Traefik Gateway, it wires its rules, keeping
// the user's filters, and unwires them when the policy goes. It runs after
// testWiring, whose Traefik pod has the engine.
func testHTTPRoutes(ctx context.Context, t *testing.T, c client.Client) {
	const ns = "gateway"
	cond := func(typ string, st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "app"}, &got); err != nil {
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
	routes := func() string {
		p := findPolicy(current(ctx, t, c), ns+"/app")
		if p == nil {
			return "not in the bundle"
		}
		var got []string
		for _, r := range p.GetRoutes() {
			got = append(got, strings.Join(append([]string{r.GetHost(), bundlev1.PathMatchType_name[int32(r.GetPath().GetType())], r.GetPath().GetValue()}, r.GetMethods()...), " "))
		}
		return strings.Join(got, ", ")
	}

	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"}},
		},
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// No HTTPRoute CRD: the operator runs, and says so.
	eventually(t, "Accepted without the CRD", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonInvalidRef, "HTTPRoute app not found"))

	// Installed later, then the route.
	if err := testenv.InstallGatewayAPI(env); err != nil {
		t.Fatal(err)
	}
	post := gatewayv1.HTTPMethodPost
	exact, prefix := gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix
	hr := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{{Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &prefix, Value: new("/api")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: new("/login")}, Method: &post},
			}}},
		},
	}
	if err := c.Create(ctx, hr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Accepted", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionTrue, resolver.ReasonAccepted, ""))
	eventually(t, "Programmed=False without a Gateway", cond(wafv1alpha1.ConditionProgrammed, metav1.ConditionFalse,
		wiring.ReasonControllerUnsupported, "HTTPRoute app is attached to no Gateway of a known GatewayClass"))
	eventually(t, "the routes in the bundle", func() string {
		if s := routes(); s != "app.example.com PATH_MATCH_TYPE_PREFIX /api, app.example.com PATH_MATCH_TYPE_EXACT /login POST" {
			return s
		}
		return ""
	})

	// A match the engine can't match on: not accepted, the rule named; the
	// bundle keeps the previous version.
	update(ctx, t, c, hr, func(r *gatewayv1.HTTPRoute) {
		r.Spec.Rules[0].Matches[0].Headers = []gatewayv1.HTTPHeaderMatch{{Name: "X-Canary", Value: "1"}}
	})
	eventually(t, "Accepted=False on an unreadable match", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonTargetUnsupported, "HTTPRoute app: spec.rules[0].matches[0]: headers"))
	if s := routes(); !strings.Contains(s, "/login POST") {
		t.Errorf("the previous version must stay in the bundle: %s", s)
	}

	// Attached to a Traefik Gateway, with the user's filter on its first
	// rule and a second, named rule: wired, the user's filter kept.
	gc := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"controllerName": "traefik.io/gateway-controller"}}}
	gc.SetGroupVersionKind(wiring.GatewayClassGVK)
	gc.SetName("traefik")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "traefik"}}
	for _, o := range []client.Object{gc, gw} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	header := gatewayv1.HTTPRouteFilter{Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{Name: "X-Team", Value: "web"}}}}
	update(ctx, t, c, hr, func(r *gatewayv1.HTTPRoute) {
		r.Spec.ParentRefs = []gatewayv1.ParentReference{{Name: "edge"}}
		r.Spec.Rules[0].Matches[0].Headers = nil
		r.Spec.Rules[0].Filters = []gatewayv1.HTTPRouteFilter{header}
		r.Spec.Rules = append(r.Spec.Rules, gatewayv1.HTTPRouteRule{Name: new(gatewayv1.SectionName("admin"))})
	})
	wiredAs := func(want, marker string) func() string {
		return func() string {
			var got gatewayv1.HTTPRoute
			if err := c.Get(ctx, client.ObjectKeyFromObject(hr), &got); err != nil {
				return err.Error()
			}
			if f := filters(&got); f != want {
				return "filters " + f
			}
			if m := got.Annotations[wiring.WiredAnnotation]; m != marker {
				return "marker " + m
			}
			return ""
		}
	}
	eventually(t, "the HTTPRoute wired", wiredAs("inkwall-waf,RequestHeaderModifier|inkwall-waf", wiring.MiddlewareName))
	eventually(t, "Programmed", cond(wafv1alpha1.ConditionProgrammed, metav1.ConditionTrue, wiring.ReasonProgrammed, "1 HTTPRoute(s) wired"))
	middleware := func() error {
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(wiring.MiddlewareGVK)
		return c.Get(ctx, client.ObjectKey{Namespace: ns, Name: wiring.MiddlewareName}, m)
	}
	if err := middleware(); err != nil {
		t.Errorf("Middleware: %v", err)
	}

	// Narrowed to one rule: the other loses the filter.
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.TargetRefs[0].SectionName = "admin" })
	eventually(t, "only the admin rule wired", wiredAs("RequestHeaderModifier|inkwall-waf", wiring.MiddlewareName))

	// The policy deleted: the route as the user wrote it, the Middleware gone.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unwired", wiredAs("RequestHeaderModifier|", ""))
	eventually(t, "the Middleware deleted", func() string {
		if err := middleware(); !apierrors.IsNotFound(err) {
			return fmt.Sprintf("Middleware: %v", err)
		}
		return ""
	})
}
