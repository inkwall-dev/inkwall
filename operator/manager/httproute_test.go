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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
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
		m.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
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

// testMixedGateways follows a policy on an HTTPRoute attached to a Traefik
// Gateway and then also to another controller's: Traefik's filter, which
// the other controller can't resolve and must fail the rules for, comes
// off, and the policy says why, while Envoy Gateway still wires the route
// through its own Gateway. Runs after testEnvoyGateway, which installs
// Envoy Gateway's CRDs; testWiring's Traefik pod has the engine.
func testMixedGateways(ctx context.Context, t *testing.T, c client.Client) {
	const ns = "mixed"
	programmed := func(st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "app"}, &got); err != nil {
				return err.Error()
			}
			cnd := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionProgrammed)
			if cnd == nil {
				return "no Programmed"
			}
			if cnd.Status != st || cnd.Reason != reason || !strings.Contains(cnd.Message, msg) {
				return string(cnd.Status) + " " + cnd.Reason + ": " + cnd.Message
			}
			return ""
		}
	}
	exists := func(gvk schema.GroupVersionKind, name string) error {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		return c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, u)
	}

	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	// Gateways of Traefik, Envoy Gateway and a controller of no
	// integration, and a route on the Traefik one.
	var objs []client.Object
	for name, controller := range map[string]string{
		"mixed-traefik": "traefik.io/gateway-controller", "mixed-eg": "gateway.envoyproxy.io/gatewayclass-controller", "mixed-other": "example.com/gateway",
	} {
		objs = append(objs,
			&gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(controller)}},
			&gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: strings.TrimPrefix(name, "mixed-")}, Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(name), Listeners: []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80}},
			}})
	}
	hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "traefik"}}},
		Hostnames:       []gatewayv1.Hostname{"mixed.example.com"},
		Rules:           []gatewayv1.HTTPRouteRule{{}},
	}}
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"}},
	}}
	// An Envoy pod of the Envoy Gateway Gateway, with the engine.
	envoy := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "eg-system", Name: "envoy-mixed", Labels: map[string]string{
		"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway", "app.kubernetes.io/component": "proxy",
		"gateway.envoyproxy.io/owning-gateway-name": "eg", "gateway.envoyproxy.io/owning-gateway-namespace": ns,
	}}, Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: injection.ContainerName, Image: "inkwall-engine:test"}},
		Containers:     []corev1.Container{{Name: "envoy", Image: "envoy"}},
	}}
	for _, o := range append(objs, hr, pol, envoy) {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
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
	eventually(t, "wired for Traefik", wiredAs(wiring.MiddlewareName, wiring.MiddlewareName))
	eventually(t, "Programmed", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "1 HTTPRoute(s) wired to the engine in Traefik"))

	// Also attached to the Envoy Gateway Gateway: the filter comes off, the
	// Middleware goes, and Envoy Gateway wires the route.
	parents := func(names ...string) {
		t.Helper()
		update(ctx, t, c, hr, func(r *gatewayv1.HTTPRoute) {
			r.Spec.ParentRefs = nil
			for _, n := range names {
				r.Spec.ParentRefs = append(r.Spec.ParentRefs, gatewayv1.ParentReference{Name: gatewayv1.ObjectName(n)})
			}
		})
	}
	parents("traefik", "eg")
	eventually(t, "Traefik's filter removed", wiredAs("", ""))
	eventually(t, "WiringFailed naming Envoy Gateway", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed,
		"HTTPRoute app is also attached to Gateways of gateway.envoyproxy.io/gatewayclass-controller, which would fail its rules with Traefik's filter"))
	eventually(t, "the Middleware deleted", func() string {
		if err := exists(integrations.TraefikMiddlewareGVK, wiring.MiddlewareName); !apierrors.IsNotFound(err) {
			return fmt.Sprintf("Middleware: %v", err)
		}
		return ""
	})
	eventually(t, "wired by Envoy Gateway", func() string {
		if err := exists(wiring.EnvoyExtensionPolicyGVK, "inkwall-waf-app"); err != nil {
			return err.Error()
		}
		return ""
	})

	// On a Gateway of a controller of no integration: the same.
	parents("traefik", "other")
	eventually(t, "WiringFailed naming the other controller", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed,
		"HTTPRoute app is also attached to Gateways of example.com/gateway"))
	if err := wiredAs("", "")(); err != "" {
		t.Errorf("wired with another controller's Gateway: %s", err)
	}

	// Traefik's Gateway only again: wired.
	parents("traefik")
	eventually(t, "wired again", wiredAs(wiring.MiddlewareName, wiring.MiddlewareName))
	eventually(t, "Programmed again", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "1 HTTPRoute(s) wired to the engine in Traefik"))

	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unwired", wiredAs("", ""))
	eventually(t, "the policy released", func() string {
		if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &wafv1alpha1.WAFPolicy{}); !apierrors.IsNotFound(err) {
			return fmt.Sprint(err)
		}
		return ""
	})
	for _, o := range append(objs, hr, envoy) {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
}
