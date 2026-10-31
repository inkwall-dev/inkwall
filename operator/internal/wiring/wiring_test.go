// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

func TestMiddleware(t *testing.T) {
	m := Middleware("shop")
	if m.GetNamespace() != "shop" || m.GetName() != "inkwall-waf" || m.GetKind() != "Middleware" {
		t.Fatalf("metadata: %v", m.Object)
	}
	fa, _, _ := unstructured.NestedMap(m.Object, "spec", "forwardAuth")
	if fa["trustForwardHeader"] != false || fa["forwardBody"] != true || fa["address"] != "http://127.0.0.1:9001/v1/forward-auth" {
		t.Errorf("forwardAuth %v", fa)
	}
	if !ForwardAuthMatches(m) {
		t.Fatal("the rendered Middleware doesn't match itself")
	}
	// As read back from the API server: numbers decode as JSON numbers.
	raw, _ := json.Marshal(m.Object)
	var back unstructured.Unstructured
	if err := back.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	if !ForwardAuthMatches(&back) {
		t.Fatal("a round-tripped Middleware doesn't match")
	}
	// Someone turned trustForwardHeader on: corrected.
	_ = unstructured.SetNestedField(back.Object, true, "spec", "forwardAuth", "trustForwardHeader")
	if ForwardAuthMatches(&back) {
		t.Fatal("trustForwardHeader: true matched")
	}
	if MiddlewareRef("shop") != "shop-inkwall-waf@kubernetescrd" {
		t.Errorf("ref %s", MiddlewareRef("shop"))
	}
}

func TestAnnotation(t *testing.T) {
	ref := "shop-inkwall-waf@kubernetescrd"
	for _, tc := range []struct{ cur, with, without string }{
		{"", ref, ""},
		{"shop-auth@kubernetescrd", ref + ",shop-auth@kubernetescrd", "shop-auth@kubernetescrd"},
		{ref + ", shop-auth@kubernetescrd", ref + ", shop-auth@kubernetescrd", "shop-auth@kubernetescrd"},
		{"a@kubernetescrd," + ref + ",b@kubernetescrd", "a@kubernetescrd," + ref + ",b@kubernetescrd", "a@kubernetescrd,b@kubernetescrd"},
	} {
		if got := WithMiddleware(tc.cur, ref); got != tc.with {
			t.Errorf("WithMiddleware(%q) = %q, want %q", tc.cur, got, tc.with)
		}
		if got := WithoutMiddleware(tc.with, ref); got != tc.without {
			t.Errorf("WithoutMiddleware(%q) = %q, want %q", tc.with, got, tc.without)
		}
	}
}

// ingressRoute returns an IngressRoute with one route per list of
// Middleware references (nil: none).
func ingressRoute(ns, name string, middlewares ...[]any) *unstructured.Unstructured {
	var routes []any
	for i, m := range middlewares {
		route := map[string]any{"kind": "Rule", "match": fmt.Sprintf("Host(`%s.example.com`) && PathPrefix(`/%d`)", name, i)}
		if m != nil {
			route["middlewares"] = m
		}
		routes = append(routes, route)
	}
	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"routes": routes}}}
	u.SetGroupVersionKind(integrations.TraefikIngressRouteGVK)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

// middlewares lists an IngressRoute's Middleware names, "," between
// Middlewares and "|" between routes.
func middlewares(ir *unstructured.Unstructured) string {
	routes, _, _ := unstructured.NestedSlice(ir.Object, "spec", "routes")
	var out []string
	for _, r := range routes {
		var names []string
		mws, _ := r.(map[string]any)["middlewares"].([]any)
		for _, m := range mws {
			names = append(names, m.(map[string]any)["name"].(string))
		}
		out = append(out, strings.Join(names, ","))
	}
	return strings.Join(out, "|")
}

func TestWithRouteMiddleware(t *testing.T) {
	ref := func(name string, ns ...string) any {
		m := map[string]any{"name": name}
		if len(ns) > 0 {
			m["namespace"] = ns[0]
		}
		return m
	}
	// Routes without Middlewares, with the user's, and already with Inkwall's.
	ir := ingressRoute("shop", "app", nil, []any{ref("auth"), ref("gzip", "shop")}, []any{ref("auth"), ref(MiddlewareName)})
	changed, err := WithRouteMiddleware(ir, true)
	if err != nil || !changed {
		t.Fatalf("wire: %v %v", changed, err)
	}
	if got := middlewares(ir); got != "inkwall-waf|inkwall-waf,auth,gzip|auth,inkwall-waf" {
		t.Errorf("wired: %s", got)
	}
	// By name only: Traefik looks it up in the route's namespace.
	routes, _, _ := unstructured.NestedSlice(ir.Object, "spec", "routes")
	if first := routes[0].(map[string]any)["middlewares"].([]any)[0]; len(first.(map[string]any)) != 1 {
		t.Errorf("the reference must have only a name: %v", first)
	}
	if changed, _ := WithRouteMiddleware(ir, true); changed {
		t.Error("wiring twice changed the routes")
	}

	changed, err = WithRouteMiddleware(ir, false)
	if err != nil || !changed {
		t.Fatalf("unwire: %v %v", changed, err)
	}
	if got := middlewares(ir); got != "|auth,gzip|auth" {
		t.Errorf("unwired: %s", got)
	}
	routes, _, _ = unstructured.NestedSlice(ir.Object, "spec", "routes")
	if _, ok := routes[0].(map[string]any)["middlewares"]; ok {
		t.Error("a route left without Middlewares keeps an empty list")
	}

	// A same-named Middleware in another namespace is the user's.
	other := ingressRoute("shop", "other", []any{ref(MiddlewareName, "edge")})
	if changed, _ := WithRouteMiddleware(other, false); changed {
		t.Error("removed a Middleware of another namespace")
	}
	if changed, _ := WithRouteMiddleware(other, true); !changed || middlewares(other) != "inkwall-waf,inkwall-waf" {
		t.Errorf("wired: %s", middlewares(other))
	}

	bad := ingressRoute("shop", "bad")
	bad.Object["spec"] = map[string]any{"routes": []any{"nope"}}
	if _, err := WithRouteMiddleware(bad, true); err == nil {
		t.Error("a route that isn't an object was wired")
	}
}

func TestController(t *testing.T) {
	classes := map[string]string{"traefik": integrations.Traefik.Controller, "nginx": "k8s.io/ingress-nginx"}
	ing := func(class *string, annotation string) *networkingv1.Ingress {
		i := &networkingv1.Ingress{Spec: networkingv1.IngressSpec{IngressClassName: class}}
		if annotation != "" {
			i.Annotations = map[string]string{"kubernetes.io/ingress.class": annotation}
		}
		return i
	}
	for _, tc := range []struct {
		name         string
		ing          *networkingv1.Ingress
		defaultClass string
		want         string
	}{
		{"class name", ing(ptr.To("traefik"), ""), "", integrations.Traefik.Controller},
		{"another class", ing(ptr.To("nginx"), ""), "traefik", "k8s.io/ingress-nginx"},
		{"legacy annotation", ing(nil, "nginx"), "", "k8s.io/ingress-nginx"},
		{"legacy traefik without IngressClass", ing(nil, "traefik"), "", integrations.Traefik.Controller},
		{"default class", ing(nil, ""), "traefik", integrations.Traefik.Controller},
		{"no class at all", ing(nil, ""), "", ""},
		{"unknown class", ing(ptr.To("haproxy"), ""), "", ""},
	} {
		if got := Controller(tc.ing, classes, tc.defaultClass); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// traefikProgrammed is a policy's Programmed with Traefik's integration
// alone, which found st.
func traefikProgrammed(p *wafv1alpha1.WAFPolicy, st *state, injectingSince time.Time) (metav1.ConditionStatus, string, string) {
	targets := map[Target]bool{}
	for _, ref := range p.Spec.TargetRefs {
		targets[targetOf(p.Namespace, ref)] = true
	}
	return programmed(p, &report{kinds: (&Traefik{}).Kinds(), results: []*Result{st.result(targets)}, injectingSince: injectingSince})
}

func TestProgrammed(t *testing.T) {
	traefik := integrations.Traefik.Controller
	k := func(n string) types.NamespacedName { return types.NamespacedName{Namespace: "shop", Name: n} }
	ings := map[types.NamespacedName]*networkingv1.Ingress{
		k("web"): {ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}},
		k("api"): {ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"}},
		k("bad"): {ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "bad"}},
	}
	wire := map[types.NamespacedName]target{
		k("web"): {ing: ings[k("web")], controller: traefik},
		k("api"): {ing: ings[k("api")], controller: "k8s.io/ingress-nginx"},
		k("bad"): {ing: ings[k("bad")], controller: traefik},
	}
	routes := map[types.NamespacedName]*unstructured.Unstructured{k("app"): ingressRoute("shop", "app", nil), k("bad"): ingressRoute("shop", "bad", nil)}
	// Targets are Ingresses, or IngressRoutes as "route/<name>".
	pol := func(targets ...string) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}}
		for _, t := range targets {
			if name, ok := strings.CutPrefix(t, "route/"); ok {
				p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Group: "traefik.io", Kind: "IngressRoute", Name: name})
				continue
			}
			p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Kind: "Ingress", Name: t})
		}
		return p
	}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-1"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	// The Pod webhook was installed at since: t-old started before it,
	// t-missed after it without the engine (the operator was down).
	since := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	without := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-old", CreationTimestamp: metav1.NewTime(since.Add(-time.Hour))}}
	missed := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-missed", CreationTimestamp: metav1.NewTime(since.Add(time.Hour))}}
	optedOut := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-out", CreationTimestamp: metav1.NewTime(since.Add(time.Hour)),
		Annotations: map[string]string{injection.InjectAnnotation: "false"}}}
	now := metav1.Now()
	terminating := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t-gone", DeletionTimestamp: &now}}

	for _, tc := range []struct {
		name     string
		p        *wafv1alpha1.WAFPolicy
		crds     bool
		mwErr    map[string]string
		pods     []corev1.Pod
		status   metav1.ConditionStatus
		reason   string
		msg      string
		routeCRD bool
	}{
		{"wired", pol("web"), true, nil, []corev1.Pod{withEngine, terminating}, metav1.ConditionTrue, ReasonProgrammed, "1 Ingress(es) wired", true},
		{"IngressRoute wired", pol("route/app"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionTrue, ReasonProgrammed, "1 IngressRoute(s) wired", true},
		{"both wired", pol("web", "route/app"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionTrue, ReasonProgrammed, "1 Ingress(es) and 1 IngressRoute(s) wired", true},
		{"no IngressRoute CRD", pol("web", "route/app"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "IngressRoute CRD is not installed", false},
		{"IngressRoute not written", pol("route/bad"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "IngressRoute bad: forbidden", true},
		{"Ingress not written", pol("bad"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "Ingress bad: forbidden", true},
		{"IngressRoute without the Middleware CRD", pol("route/app"), false, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "Middleware CRD is not installed", true},
		{"IngressRoute, name clash", pol("route/app"), true, map[string]string{"shop": "Middleware shop/inkwall-waf exists"}, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "exists", true},
		{"IngressRoute, old pod", pol("route/app"), true, nil, []corev1.Pod{withEngine, without}, metav1.ConditionFalse, ReasonPendingRestart, "traefik/t-old", true},
		{"missing IngressRoute", pol("route/gone"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonNoTargets, "none", true},
		{"HTTPRoute", &wafv1alpha1.WAFPolicy{Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "HTTPRoute", Name: "h"}}}},
			true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonControllerUnsupported, "only Ingress and IngressRoute targets", true},
		{"not Traefik", pol("web", "api"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonControllerUnsupported, "api is served by k8s.io/ingress-nginx", true},
		{"no CRDs", pol("web"), false, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "CRD is not installed", true},
		{"name clash", pol("web"), true, map[string]string{"shop": "Middleware shop/inkwall-waf exists"}, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "exists", true},
		{"old pod", pol("web"), true, nil, []corev1.Pod{withEngine, without}, metav1.ConditionFalse, ReasonPendingRestart, "traefik/t-old", true},
		{"no pods", pol("web"), true, nil, []corev1.Pod{terminating}, metav1.ConditionFalse, ReasonSidecarMissing, "no Traefik pod selected for the engine is running, so the routes are not wired", true},
		{"missed by the webhook", pol("web"), true, nil, []corev1.Pod{withEngine, without, missed}, metav1.ConditionFalse, ReasonSidecarMissing, "restart them once it is back: traefik/t-missed", true},
		{"opted out", pol("web"), true, nil, []corev1.Pod{withEngine, optedOut}, metav1.ConditionFalse, ReasonSidecarMissing, `opted out with waf.inkwall.dev/inject: "false": traefik/t-out`, true},
		{"missing target", pol("gone"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonNoTargets, "none", true},
	} {
		st, reason, msg := traefikProgrammed(tc.p, &state{ingresses: ings, wire: wire, routes: routes, routeCRD: tc.routeCRD,
			routeErr:    map[types.NamespacedName]string{k("bad"): "IngressRoute bad: forbidden"},
			ingressErr:  map[types.NamespacedName]string{k("bad"): "Ingress bad: forbidden"},
			traefikCRDs: tc.crds, middlewareErr: tc.mwErr, pods: tc.pods}, since)
		if st != tc.status || reason != tc.reason || !strings.Contains(msg, tc.msg) {
			t.Errorf("%s: %s %s %q", tc.name, st, reason, msg)
		}
	}
}

// Without the webhook's creation time, a pod without the engine is
// assumed to predate it.
func TestProgrammedUnknownSince(t *testing.T) {
	k := types.NamespacedName{Namespace: "shop", Name: "web"}
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"},
		Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "t", CreationTimestamp: metav1.Now()}}
	_, reason, _ := traefikProgrammed(p, &state{ingresses: map[types.NamespacedName]*networkingv1.Ingress{k: ing},
		wire: map[types.NamespacedName]target{k: {ing: ing, controller: integrations.Traefik.Controller}}, traefikCRDs: true, pods: []corev1.Pod{pod}}, time.Time{})
	if reason != ReasonPendingRestart {
		t.Errorf("reason %s, want %s", reason, ReasonPendingRestart)
	}
}

// With injection off, nothing is wired, whatever the targets.
func TestProgrammedDisabled(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}}}
	if st, reason, _ := programmed(p, &report{disabled: true}); st != metav1.ConditionFalse || reason != ReasonInjectionDisabled {
		t.Errorf("%s %s, want False %s", st, reason, ReasonInjectionDisabled)
	}
}

// Two integrations share Ingress: each target is reported by the one whose
// proxy serves it.
func TestProgrammedShared(t *testing.T) {
	ingress := func(name string) Target {
		return Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: name}}
	}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "e"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	traefik := &Result{Proxy: "Traefik", Pods: []corev1.Pod{withEngine}, Targets: map[Target]TargetState{
		ingress("web"): {Wired: true},
		ingress("api"): {Unsupported: "Ingress api is served by example.com/other, which Inkwall doesn't wire yet"},
		ingress("old"): {Unsupported: "Ingress old is served by example.com/old, which Inkwall doesn't wire yet"},
	}}
	other := &Result{Proxy: "Other", Pods: []corev1.Pod{withEngine}, Targets: map[Target]TargetState{
		ingress("web"): {Unsupported: "Ingress web is served by traefik.io/ingress-controller"},
		ingress("api"): {Wired: true},
		ingress("old"): {Unsupported: "Ingress old is served by example.com/old"},
	}}
	rep := &report{kinds: []schema.GroupKind{ingressKind, routeKind, ingressKind}, results: []*Result{traefik, other}}
	pol := func(names ...string) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}}
		for _, n := range names {
			p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Kind: "Ingress", Name: n})
		}
		return p
	}
	if st, _, msg := programmed(pol("web", "api"), rep); st != metav1.ConditionTrue ||
		msg != "1 Ingress(es) wired to the engine in Traefik; 1 Ingress(es) wired to the engine in Other" {
		t.Errorf("both served: %s %q", st, msg)
	}
	if _, reason, msg := programmed(pol("web", "old"), rep); reason != ReasonControllerUnsupported || !strings.Contains(msg, "example.com/old, which") {
		t.Errorf("served by neither: %s %q", reason, msg)
	}
}
