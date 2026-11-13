// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
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
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy-edge"}}
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
		// More than HAProxy's default buffer lets the engine see (#345).
		Body: &wafv1alpha1.BodySpec{MaxBytes: new(int64(1 << 20))},
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
				Args:  []string{"--configmap=" + edge + "/hap-config", "--http-bind-port=8080"},
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
	if args := pod.Spec.InitContainers[0].Args; !slices.Contains(args, "spoe") || !slices.Contains(args, injection.ResponseMessagesFlag) {
		t.Fatalf("engine args %v", args)
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

	// body.maxBytes over what HAProxy's buffer lets the engine see: said,
	// without changing the status (bigger bodies fail safe, #345). The
	// controller's ConfigMap has no tune.bufsize: HAProxy's 16384.
	hapConfig := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "hap-config"}, Data: map[string]string{"timeout-connect": "5s"}}
	if err := c.Create(ctx, hapConfig); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the buffer's limit is said", programmed(metav1.ConditionFalse, wiring.ReasonUnverified, "tune.bufsize 16384"))
	// Raised in the global snippet: no longer said.
	hapConfig.Data["global-config-snippet"] = "tune.bufsize 2m\n"
	if err := c.Update(ctx, hapConfig); err != nil {
		t.Fatal(err)
	}
	eventually(t, "not said once the buffer is large enough", func() string {
		// The wiring rereads the ConfigMap at each reconcile (every minute
		// at least): an Ingress event brings it sooner.
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKeyFromObject(ing), &got); err == nil {
			got.Labels = map[string]string{"touched": strings.ReplaceAll(time.Now().Format("150405.000"), ".", "")}
			_ = c.Update(ctx, &got)
		}
		if msg := programmed(metav1.ConditionFalse, wiring.ReasonUnverified, "Ingress shop is wired")(); msg != "" {
			return msg
		}
		var p wafv1alpha1.WAFPolicy
		_ = c.Get(ctx, client.ObjectKeyFromObject(pol), &p)
		if cnd := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionProgrammed); cnd != nil && strings.Contains(cnd.Message, "tune.bufsize") {
			return cnd.Message
		}
		return ""
	})

	// Responses (#470): the pod's engine keeps requests for them, so the
	// Ingress gets the response rules, and the policy isn't
	// ResponsesNotInspected: still Unverified until the probe answers.
	if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true}
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the Ingress gets the response rules", func() string {
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKeyFromObject(ing), &got); err != nil {
			return err.Error()
		}
		sn := got.Annotations[wiring.HAProxySnippetAnnotation]
		for _, want := range []string{"filter spoe engine " + injection.HAProxyResponsesScope, "http-response send-spoe-group", "http-response return status 403"} {
			if !strings.Contains(sn, want) {
				return sn
			}
		}
		return ""
	})
	eventually(t, "responses: Unverified, not ResponsesNotInspected", programmed(metav1.ConditionFalse, wiring.ReasonUnverified, "Ingress shop is wired"))
	eventually(t, "the agent's ConfigMap has the responses scope", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: injection.HAProxyConfigMap}, &cm); err != nil {
			return err.Error()
		}
		if !strings.Contains(cm.Data[injection.HAProxySPOEKey], "spoe-group "+injection.HAProxyResponseGroup) {
			return cm.Data[injection.HAProxySPOEKey]
		}
		return ""
	})
	// A pod whose engine runs without --response-messages (injected
	// before 0.6.0): no response rules, and ResponsesNotInspected naming
	// it, until it is restarted.
	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "hap-old", Labels: map[string]string{"app.kubernetes.io/name": "kubernetes-ingress"},
			Annotations: map[string]string{injection.InjectedAnnotation: "true", injection.HAProxyConfigAnnotation: injection.HAProxyConfigMounted}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: injection.ContainerName, Image: "ghcr.io/inkwall-dev/inkwall-engine:0.5.0", Args: []string{"spoe"},
				RestartPolicy: new(corev1.ContainerRestartPolicyAlways)}},
			Containers: []corev1.Container{{Name: injection.HAProxyContainer, Image: "haproxytech/kubernetes-ingress:3.2.19",
				Args: []string{"--configmap=" + edge + "/hap-config"}}},
		},
	}
	if err := c.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(old.Spec.InitContainers[0].Args, injection.ResponseMessagesFlag) {
		t.Fatalf("the webhook changed an injected pod: %v", old.Spec.InitContainers[0].Args)
	}
	eventually(t, "a pod not ready: ResponsesNotInspected", programmed(metav1.ConditionFalse, wiring.ReasonResponsesNotInspected, edge+"/hap-old"))
	eventually(t, "no response rules while a pod isn't ready", func() string {
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKeyFromObject(ing), &got); err != nil {
			return err.Error()
		}
		if sn := got.Annotations[wiring.HAProxySnippetAnnotation]; strings.Contains(sn, "http-response") || !strings.Contains(sn, "filter spoe engine inkwall config") {
			return sn
		}
		return ""
	})
	if err := c.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pod gone: the response rules back", programmed(metav1.ConditionFalse, wiring.ReasonUnverified, "Ingress shop is wired"))

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
