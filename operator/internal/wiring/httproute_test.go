// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// extRef is an ExtensionRef filter to a Traefik Middleware.
func extRef(name string) any {
	return map[string]any{"type": "ExtensionRef", "extensionRef": map[string]any{"group": "traefik.io", "kind": "Middleware", "name": name}}
}

// httpRoute returns an HTTPRoute with one rule per list of filters (nil:
// none), named r0, r1...
func httpRoute(ns, name string, filters ...[]any) *unstructured.Unstructured {
	var rules []any
	for i, f := range filters {
		rule := map[string]any{"name": fmt.Sprintf("r%d", i)}
		if f != nil {
			rule["filters"] = f
		}
		rules = append(rules, rule)
	}
	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"rules": rules}}}
	u.SetGroupVersionKind(HTTPRouteGVK)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

// ruleFilters lists an HTTPRoute's filters, by ExtensionRef name or type,
// "," between filters and "|" between rules.
func ruleFilters(hr *unstructured.Unstructured) string {
	rules, _, _ := unstructured.NestedSlice(hr.Object, "spec", "rules")
	var out []string
	for _, r := range rules {
		var names []string
		fs, _ := r.(map[string]any)["filters"].([]any)
		for _, f := range fs {
			name, ok, _ := unstructured.NestedString(f.(map[string]any), "extensionRef", "name")
			if !ok {
				name = f.(map[string]any)["type"].(string)
			}
			names = append(names, name)
		}
		out = append(out, strings.Join(names, ","))
	}
	return strings.Join(out, "|")
}

func TestWithRuleFilter(t *testing.T) {
	header := map[string]any{"type": "RequestHeaderModifier", "requestHeaderModifier": map[string]any{"set": []any{map[string]any{"name": "X-A", "value": "1"}}}}
	// Another group's object of the same name is the user's.
	theirs := map[string]any{"type": "ExtensionRef", "extensionRef": map[string]any{"group": "example.com", "kind": "Middleware", "name": MiddlewareName}}
	hr := httpRoute("shop", "app", nil, []any{extRef("auth"), header}, []any{theirs})

	changed, err := WithRuleFilter(hr, rules{"": true})
	if err != nil || !changed {
		t.Fatalf("wire: %v %v", changed, err)
	}
	if got := ruleFilters(hr); got != "inkwall-waf|inkwall-waf,auth,RequestHeaderModifier|inkwall-waf,inkwall-waf" {
		t.Errorf("wired: %s", got)
	}
	if changed, _ := WithRuleFilter(hr, rules{"": true}); changed {
		t.Error("wiring twice changed the rules")
	}

	// One rule (sectionName): the others lose it.
	if changed, _ := WithRuleFilter(hr, rules{"r1": true}); !changed {
		t.Error("narrowed to r1: unchanged")
	}
	if got := ruleFilters(hr); got != "|inkwall-waf,auth,RequestHeaderModifier|inkwall-waf" {
		t.Errorf("r1 only: %s", got)
	}

	changed, err = WithRuleFilter(hr, nil)
	if err != nil || !changed {
		t.Fatalf("unwire: %v %v", changed, err)
	}
	if got := ruleFilters(hr); got != "|auth,RequestHeaderModifier|inkwall-waf" {
		t.Errorf("unwired: %s", got)
	}
	list, _, _ := unstructured.NestedSlice(hr.Object, "spec", "rules")
	if _, ok := list[0].(map[string]any)["filters"]; ok {
		t.Error("a rule left without filters keeps an empty list")
	}

	bad := httpRoute("shop", "bad")
	bad.Object["spec"] = map[string]any{"rules": []any{"nope"}}
	if _, err := WithRuleFilter(bad, rules{"": true}); err == nil {
		t.Error("a rule that isn't an object was wired")
	}
}

// The marker is set with the filters and removed with them; a route the
// operator didn't wire isn't touched.
func TestWireHTTPRoute(t *testing.T) {
	ctx := context.Background()
	hr := httpRoute("shop", "app", []any{extRef("auth")}, nil)
	mine := httpRoute("shop", "mine", []any{extRef(MiddlewareName)})
	c := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(hr, mine).Build()
	get := func(name string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(HTTPRouteGVK)
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: name}, u); err != nil {
			t.Fatal(err)
		}
		return u
	}

	if err := wireHTTPRoute(ctx, c, get("app"), rules{"r1": true}); err != nil {
		t.Fatal(err)
	}
	if got := get("app"); ruleFilters(got) != "auth|inkwall-waf" || got.GetAnnotations()[WiredAnnotation] != MiddlewareName {
		t.Errorf("wired: %s %v", ruleFilters(got), got.GetAnnotations())
	}
	// A stale copy: the resourceVersion refuses it.
	stale := get("app")
	if err := wireHTTPRoute(ctx, c, get("app"), rules{"": true}); err != nil {
		t.Fatal(err)
	}
	if err := wireHTTPRoute(ctx, c, stale, nil); err == nil {
		t.Error("a stale copy was written")
	}
	if err := wireHTTPRoute(ctx, c, get("app"), nil); err != nil {
		t.Fatal(err)
	}
	if got := get("app"); ruleFilters(got) != "auth|" || len(got.GetAnnotations()) != 0 {
		t.Errorf("unwired: %s %v", ruleFilters(got), got.GetAnnotations())
	}

	// The user's own reference to a Middleware of that name, unmarked.
	if err := wireHTTPRoute(ctx, c, get("mine"), nil); err != nil {
		t.Fatal(err)
	}
	if got := ruleFilters(get("mine")); got != MiddlewareName {
		t.Errorf("a route Inkwall didn't wire changed: %s", got)
	}
}

func TestProgrammedHTTPRoute(t *testing.T) {
	gw := integrations.Traefik.GatewayController
	k := func(n string) types.NamespacedName { return types.NamespacedName{Namespace: "shop", Name: n} }
	route := func(n string) *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: n},
			Spec: gatewayv1.HTTPRouteSpec{Rules: []gatewayv1.HTTPRouteRule{{Name: ptr.To[gatewayv1.SectionName]("api")}, {}}}}
	}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-1"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	st := &state{
		httpRoutes: map[types.NamespacedName]*gatewayv1.HTTPRoute{
			k("web"): route("web"), k("mixed"): route("mixed"), k("eg"): route("eg"), k("lost"): route("lost"), k("bad"): route("bad"),
			k("envoy"): route("envoy"),
		},
		controllers: map[types.NamespacedName][]string{
			k("web"): {gw}, k("mixed"): {"example.com/eg", gw}, k("eg"): {"example.com/eg"}, k("bad"): {gw},
			k("envoy"): {integrations.EnvoyGateway.GatewayController, gw},
		},
		httpRouteErr: map[types.NamespacedName]string{k("bad"): "HTTPRoute bad: forbidden"},
		traefikCRDs:  true,
		wanted:       map[schema.GroupKind]map[types.NamespacedName]bool{httpRouteKind: {k("web"): true}},
		pods:         []corev1.Pod{withEngine},
	}
	pol := func(name, section string) *wafv1alpha1.WAFPolicy {
		return &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: name, SectionName: section}},
		}}
	}
	for _, tc := range []struct {
		name, route, section string
		status               metav1.ConditionStatus
		reason, msg          string
	}{
		{"wired", "web", "", metav1.ConditionTrue, ReasonProgrammed, "1 HTTPRoute(s) wired to the engine in Traefik"},
		{"one rule", "web", "api", metav1.ConditionTrue, ReasonProgrammed, "1 HTTPRoute(s) wired"},
		{"no such rule", "web", "nope", metav1.ConditionFalse, ReasonNoTargets, "none"},
		// Another controller would fail the rules with Traefik's filter.
		{"Gateways of two controllers", "mixed", "", metav1.ConditionFalse, ReasonWiringFailed,
			"HTTPRoute mixed is also attached to Gateways of example.com/eg, which would fail its rules with Traefik's filter"},
		{"Gateways of Traefik and Envoy Gateway", "envoy", "", metav1.ConditionFalse, ReasonWiringFailed,
			"HTTPRoute envoy is also attached to Gateways of gateway.envoyproxy.io/gatewayclass-controller"},
		{"another controller's", "eg", "", metav1.ConditionFalse, ReasonControllerUnsupported, "HTTPRoute eg is served by example.com/eg"},
		{"no known Gateway", "lost", "", metav1.ConditionFalse, ReasonControllerUnsupported, "HTTPRoute lost is attached to no Gateway of a known GatewayClass"},
		{"not written", "bad", "", metav1.ConditionFalse, ReasonWiringFailed, "HTTPRoute bad: forbidden"},
		{"missing", "gone", "", metav1.ConditionFalse, ReasonNoTargets, "none"},
	} {
		got, reason, msg := traefikProgrammed(pol(tc.route, tc.section), st, metav1.Now().Time)
		if got != tc.status || reason != tc.reason || !strings.Contains(msg, tc.msg) {
			t.Errorf("%s: %s %s %q", tc.name, got, reason, msg)
		}
	}
}

// A target that the proxies of two integrations serve: Programmed counts
// it in each, and waits for both. Traefik refuses an HTTPRoute that Envoy
// Gateway also serves: its traffic through Traefik isn't inspected, so
// Envoy Gateway's wiring doesn't make it True.
func TestProgrammedHTTPRouteBoth(t *testing.T) {
	tg := Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "e"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "web"}},
	}}
	for _, tc := range []struct {
		name           string
		traefik, envoy TargetState
		status         metav1.ConditionStatus
		reason, msg    string
	}{
		{"both wired", TargetState{Wired: true}, TargetState{Wired: true}, metav1.ConditionTrue, ReasonProgrammed,
			"1 HTTPRoute(s) wired to the engine in Traefik; 1 HTTPRoute(s) wired to the engine in Envoy Gateway"},
		{"Envoy Gateway pending", TargetState{Wired: true}, TargetState{Wired: true, Pending: "not accepted yet"}, metav1.ConditionFalse, ReasonPending, "not accepted yet"},
		{"Envoy Gateway failed", TargetState{Wired: true}, TargetState{Failed: "refused"}, metav1.ConditionFalse, ReasonWiringFailed, "refused"},
		{"Traefik refuses it", TargetState{Failed: "also attached"}, TargetState{Wired: true}, metav1.ConditionFalse, ReasonWiringFailed, "also attached"},
	} {
		rep := &report{kinds: []schema.GroupKind{ingressKind, routeKind, httpRouteKind, httpRouteKind}, results: []*Result{
			{Proxy: "Traefik", Pods: []corev1.Pod{withEngine}, Targets: map[Target]TargetState{tg: tc.traefik}},
			{Proxy: "Envoy Gateway", Pods: []corev1.Pod{withEngine}, Targets: map[Target]TargetState{tg: tc.envoy}},
		}}
		if st, reason, msg := programmed(pol, rep); st != tc.status || reason != tc.reason || msg != tc.msg {
			t.Errorf("%s: %s %s %q", tc.name, st, reason, msg)
		}
	}
}
