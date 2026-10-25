// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
)

func ingress(ns, name, class string, annotations map[string]string) *networkingv1.Ingress {
	prefix := networkingv1.PathTypePrefix
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To(class),
			Rules: []networkingv1.IngressRule{{Host: name + "." + ns + ".example.com", IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &prefix,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}}}}}},
			}}},
		},
	}
}

func targeting(ns, name string, ingresses ...string) *wafv1alpha1.WAFPolicy {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	for _, i := range ingresses {
		p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Kind: "Ingress", Name: i})
	}
	return p
}

// testWiring follows a policy on Traefik Ingresses: the Middleware and the
// annotation appear, Programmed and Ready report it, and deleting the policy
// undoes the wiring, leaving the user's own Middlewares alone.
func testWiring(ctx context.Context, t *testing.T, c client.Client) {
	create := func(objs ...client.Object) {
		t.Helper()
		for _, o := range objs {
			if err := c.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	condition := func(p *wafv1alpha1.WAFPolicy, typ string) func() (*metav1.Condition, error) {
		return func() (*metav1.Condition, error) {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
				return nil, err
			}
			return meta.FindStatusCondition(got.Status.Conditions, typ), nil
		}
	}
	want := func(what string, get func() (*metav1.Condition, error), st metav1.ConditionStatus, reason, msg string) {
		t.Helper()
		eventually(t, what, func() string {
			cond, err := get()
			if err != nil {
				return err.Error()
			}
			if cond == nil {
				return "no condition"
			}
			if cond.Status != st || cond.Reason != reason || !strings.Contains(cond.Message, msg) {
				return string(cond.Status) + " " + cond.Reason + ": " + cond.Message
			}
			return ""
		})
	}

	create(
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "traefik"}, Spec: networkingv1.IngressClassSpec{Controller: "traefik.io/ingress-controller"}},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}, Spec: networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "store"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "clash"}},
		// The user's own Middleware stays on the Ingress.
		ingress("store", "web", "traefik", map[string]string{wiring.MiddlewaresAnnotation: "store-auth@kubernetescrd"}),
		ingress("store", "legacy", "nginx", nil),
		ingress("clash", "web", "traefik", nil),
		// A Traefik pod, injected at creation.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik-2", Labels: map[string]string{"app.kubernetes.io/name": "traefik"}},
			Spec:       corev1.PodSpec{ServiceAccountName: "traefik", Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}}},
		},
	)
	web := targeting("store", "web", "web")
	create(web)

	eventually(t, "the Middleware and the annotation", func() string {
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(wiring.MiddlewareGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: "store", Name: wiring.MiddlewareName}, m); err != nil {
			return err.Error()
		}
		if !wiring.ForwardAuthMatches(m) {
			return "Middleware spec"
		}
		var ing networkingv1.Ingress
		if err := c.Get(ctx, types.NamespacedName{Namespace: "store", Name: "web"}, &ing); err != nil {
			return err.Error()
		}
		if got := ing.Annotations[wiring.MiddlewaresAnnotation]; got != "store-inkwall-waf@kubernetescrd,store-auth@kubernetescrd" {
			return "annotation " + got
		}
		return ""
	})
	want("Programmed", condition(web, wafv1alpha1.ConditionProgrammed), metav1.ConditionTrue, wiring.ReasonProgrammed, "1 Ingress")
	// No engine runs the bundle in this test: Ready says so.
	want("Ready names what's missing", condition(web, wafv1alpha1.ConditionReady), metav1.ConditionFalse, "NoEngines", "Enforced:")

	// A Traefik pod that runs without the engine: opted out here (a pod
	// older than the webhook, PendingRestart, can't be made in envtest).
	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik-old", Labels: map[string]string{"app.kubernetes.io/name": "traefik"},
			Annotations: map[string]string{injection.InjectAnnotation: "false"}},
		Spec: corev1.PodSpec{ServiceAccountName: "traefik", Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}}},
	}
	create(old)
	want("SidecarMissing", condition(web, wafv1alpha1.ConditionProgrammed), metav1.ConditionFalse, wiring.ReasonSidecarMissing, "opted out with waf.inkwall.dev/inject: \"false\": proxy/traefik-old")
	if err := c.Delete(ctx, old, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	want("Programmed after the restart", condition(web, wafv1alpha1.ConditionProgrammed), metav1.ConditionTrue, wiring.ReasonProgrammed, "")

	// An Ingress another controller serves.
	legacy := targeting("store", "legacy", "legacy")
	create(legacy)
	want("ControllerUnsupported", condition(legacy, wafv1alpha1.ConditionProgrammed), metav1.ConditionFalse, wiring.ReasonControllerUnsupported, "k8s.io/ingress-nginx")

	// A Middleware of the same name made by someone else is left alone.
	theirs := &unstructured.Unstructured{}
	theirs.SetGroupVersionKind(wiring.MiddlewareGVK)
	theirs.SetNamespace("clash")
	theirs.SetName(wiring.MiddlewareName)
	theirs.Object["spec"] = map[string]any{"headers": map[string]any{}}
	create(theirs)
	clash := targeting("clash", "web", "web")
	create(clash)
	want("WiringFailed", condition(clash, wafv1alpha1.ConditionProgrammed), metav1.ConditionFalse, wiring.ReasonWiringFailed, "wasn't created by Inkwall")
	var clashIng networkingv1.Ingress
	if err := c.Get(ctx, types.NamespacedName{Namespace: "clash", Name: "web"}, &clashIng); err != nil {
		t.Fatal(err)
	}
	if _, ok := clashIng.Annotations[wiring.MiddlewaresAnnotation]; ok {
		t.Error("an Ingress was wired to a Middleware the operator doesn't own")
	}

	// The policy deleted: the operator's entry and Middleware go, the
	// user's stays.
	if err := c.Delete(ctx, web); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unwired", func() string {
		var ing networkingv1.Ingress
		if err := c.Get(ctx, types.NamespacedName{Namespace: "store", Name: "web"}, &ing); err != nil {
			return err.Error()
		}
		if ing.Annotations[wiring.MiddlewaresAnnotation] != "store-auth@kubernetescrd" || ing.Annotations[wiring.WiredAnnotation] != "" {
			return "annotations " + strings.Join([]string{ing.Annotations[wiring.MiddlewaresAnnotation], ing.Annotations[wiring.WiredAnnotation]}, " | ")
		}
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(wiring.MiddlewareGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: "store", Name: wiring.MiddlewareName}, m); !apierrors.IsNotFound(err) {
			return "Middleware still there"
		}
		return ""
	})
}
