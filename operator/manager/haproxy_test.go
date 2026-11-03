// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
)

// testHAProxy follows a policy on an Ingress the HAProxy Kubernetes Ingress
// Controller serves: the Pod webhook gives the controller's pod the engine
// and the SPOE agent's configuration, which the operator keeps in a
// ConfigMap; the Ingress gets its own backend with the filter, the user's
// snippet kept; the policy stays Programmed=False (Unverified) while the
// probe can't reach the pod (envtest runs no pod); and unprotecting puts
// the Ingress back as it was. The probe answering is the kind e2e's
// (hack/kind/haproxy-e2e.sh).
func testHAProxy(ctx context.Context, t *testing.T, c client.Client) {
	const ns, edge = "haproxy-apps", "haproxy-edge"
	for _, n := range []string{ns, edge} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil {
			t.Fatal(err)
		}
	}
	programmed := func(st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "haproxy"}, &got); err != nil {
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
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: integrations.HAProxy.Controller}}
	prefix := networkingv1.PathTypePrefix
	const userSnippet = "http-request set-header X-Mine 1"
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "shop", Annotations: map[string]string{wiring.HAProxySnippetAnnotation: userSnippet}},
		Spec: networkingv1.IngressSpec{IngressClassName: new("haproxy"), Rules: []networkingv1.IngressRule{{
			Host: "shop.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "shop", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "haproxy"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "shop"}},
	}}
	for _, o := range []client.Object{class, ing, pol} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "SidecarMissing without HAProxy pods", programmed(metav1.ConditionFalse, wiring.ReasonSidecarMissing, "no HAProxy pod"))

	// The controller's pod, as its chart makes it: the webhook injects the
	// engine and the agent's configuration.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "hap-1", Labels: map[string]string{"app.kubernetes.io/name": "kubernetes-ingress"}},
		Spec: corev1.PodSpec{
			ServiceAccountName: "haproxy",
			SecurityContext:    &corev1.PodSecurityContext{RunAsUser: new(int64(1000))},
			Containers: []corev1.Container{{Name: injection.HAProxyContainer, Image: "haproxytech/kubernetes-ingress:3.2.19",
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}},
		},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if !injection.HasEngine(pod) || pod.Annotations[injection.HAProxyConfigAnnotation] != injection.HAProxyConfigMounted {
		t.Fatalf("not injected: %v %v", pod.Annotations, pod.Spec.InitContainers)
	}
	mounts := pod.Spec.Containers[0].VolumeMounts
	if !slices.ContainsFunc(mounts, func(m corev1.VolumeMount) bool { return m.MountPath == injection.HAProxyAuxPath }) {
		t.Fatalf("HAProxy's mounts %v", mounts)
	}
	if !slices.Contains(pod.Spec.InitContainers[0].Args, "spoe") {
		t.Fatalf("engine args %v", pod.Spec.InitContainers[0].Args)
	}
	eventually(t, "the agent's ConfigMap", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: injection.HAProxyConfigMap}, &cm); err != nil {
			return err.Error()
		}
		if !strings.Contains(cm.Data[injection.HAProxyAuxKey], "mode spop") {
			return cm.Data[injection.HAProxyAuxKey]
		}
		return ""
	})
	// Not running, no IP: wired, but unverified.
	eventually(t, "the Ingress has its own backend with the filter", func() string {
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKeyFromObject(ing), &got); err != nil {
			return err.Error()
		}
		a := got.Annotations
		if a[wiring.HAProxyStandaloneAnnotation] != "true" || !strings.Contains(a[wiring.HAProxySnippetAnnotation], "filter spoe engine inkwall") ||
			!strings.HasSuffix(a[wiring.HAProxySnippetAnnotation], userSnippet) {
			return a[wiring.HAProxySnippetAnnotation]
		}
		return ""
	})
	eventually(t, "Unverified until the probe answers", programmed(metav1.ConditionFalse, wiring.ReasonUnverified, "Ingress shop is wired"))

	// Unprotected: the Ingress is as it was.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unwired", func() string {
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKeyFromObject(ing), &got); err != nil {
			return err.Error()
		}
		if a := got.Annotations; a[wiring.HAProxySnippetAnnotation] != userSnippet || a[wiring.HAProxyStandaloneAnnotation] != "" || a[wiring.HAProxyWiredAnnotation] != "" {
			return strings.Join([]string{a[wiring.HAProxySnippetAnnotation], a[wiring.HAProxyStandaloneAnnotation]}, " | ")
		}
		return ""
	})
	if err := c.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
}
