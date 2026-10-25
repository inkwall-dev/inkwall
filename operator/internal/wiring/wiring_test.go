// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func TestProgrammed(t *testing.T) {
	traefik := integrations.Traefik.Controller
	k := func(n string) types.NamespacedName { return types.NamespacedName{Namespace: "shop", Name: n} }
	ings := map[types.NamespacedName]*networkingv1.Ingress{
		k("web"): {ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}},
		k("api"): {ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"}},
	}
	wire := map[types.NamespacedName]target{
		k("web"): {ing: ings[k("web")], controller: traefik},
		k("api"): {ing: ings[k("api")], controller: "k8s.io/ingress-nginx"},
	}
	pol := func(targets ...string) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}}
		for _, t := range targets {
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
		name   string
		p      *wafv1alpha1.WAFPolicy
		crds   bool
		mwErr  map[string]string
		pods   []corev1.Pod
		status metav1.ConditionStatus
		reason string
		msg    string
	}{
		{"wired", pol("web"), true, nil, []corev1.Pod{withEngine, terminating}, metav1.ConditionTrue, ReasonProgrammed, "1 Ingress"},
		{"not Traefik", pol("web", "api"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonControllerUnsupported, "api is served by k8s.io/ingress-nginx"},
		{"no CRDs", pol("web"), false, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "CRD is not installed"},
		{"name clash", pol("web"), true, map[string]string{"shop": "Middleware shop/inkwall-waf exists"}, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonWiringFailed, "exists"},
		{"old pod", pol("web"), true, nil, []corev1.Pod{withEngine, without}, metav1.ConditionFalse, ReasonPendingRestart, "traefik/t-old"},
		{"no pods", pol("web"), true, nil, []corev1.Pod{terminating}, metav1.ConditionFalse, ReasonSidecarMissing, "no Traefik pod"},
		{"missed by the webhook", pol("web"), true, nil, []corev1.Pod{withEngine, without, missed}, metav1.ConditionFalse, ReasonSidecarMissing, "restart them once it is back: traefik/t-missed"},
		{"opted out", pol("web"), true, nil, []corev1.Pod{withEngine, optedOut}, metav1.ConditionFalse, ReasonSidecarMissing, `opted out with waf.inkwall.dev/inject: "false": traefik/t-out`},
		{"missing target", pol("gone"), true, nil, []corev1.Pod{withEngine}, metav1.ConditionFalse, ReasonNoTargets, "none"},
	} {
		st, reason, msg := programmed(tc.p, ings, wire, tc.crds, tc.mwErr, tc.pods, since)
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
	_, reason, _ := programmed(p, map[types.NamespacedName]*networkingv1.Ingress{k: ing},
		map[types.NamespacedName]target{k: {ing: ing, controller: integrations.Traefik.Controller}}, true, nil, []corev1.Pod{pod}, time.Time{})
	if reason != ReasonPendingRestart {
		t.Errorf("reason %s, want %s", reason, ReasonPendingRestart)
	}
}
