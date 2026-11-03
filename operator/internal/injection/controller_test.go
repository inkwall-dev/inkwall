// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The grant goes to the ServiceAccounts of enabled integrations' pods only:
// not to a disabled integration's, nor to other pods the cache would hold.
func TestGrantSkipsDisabledIntegrations(t *testing.T) {
	pod := func(namespace, sa string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: sa + "-1", Labels: labels},
			Spec:       corev1.PodSpec{ServiceAccountName: sa},
		}
	}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(
		pod("traefik", "traefik", map[string]string{"app.kubernetes.io/name": "traefik"}),
		pod("envoy-gateway-system", "envoy", map[string]string{"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway"}),
		pod("traefik", "shop", map[string]string{"app": "shop"}),
	).Build()
	r := &Reconciler{Client: c, Namespace: "inkwall-system", Disabled: map[string]string{"envoy-gateway": "not allowed"}}
	ctx := context.Background()
	if err := r.reconcileGrant(ctx); err != nil {
		t.Fatal(err)
	}
	var rb rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Namespace: "inkwall-system", Name: GrantName}, &rb); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(rb.Subjects), fmt.Sprint([]rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "traefik", Name: "traefik"}}); got != want {
		t.Errorf("granted %s, want %s", got, want)
	}

	// Enabled, Envoy Gateway's pods are granted too.
	r.Disabled = nil
	if err := r.reconcileGrant(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "inkwall-system", Name: GrantName}, &rb); err != nil {
		t.Fatal(err)
	}
	if len(rb.Subjects) != 2 || rb.Subjects[0].Name != "envoy" {
		t.Errorf("granted %v, want Envoy's and Traefik's ServiceAccounts", rb.Subjects)
	}
}

// A namespace with HAProxy controller pods gets the agent's ConfigMap,
// which goes once they are gone; other proxies' namespaces get none.
func TestHAProxyConfigMap(t *testing.T) {
	ctx := context.Background()
	hap := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap-1",
		Labels: map[string]string{"app.kubernetes.io/name": "kubernetes-ingress"}}}
	traefik := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-1",
		Labels: map[string]string{"app.kubernetes.io/name": "traefik"}}}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(hap, traefik).Build()
	r := &Reconciler{Client: c, APIReader: c, Namespace: "inkwall-system"}
	for _, ns := range []string{"haproxy-controller", "traefik"} {
		if err := r.reconcileHAProxy(ctx, ns); err != nil {
			t.Fatal(err)
		}
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: "haproxy-controller", Name: HAProxyConfigMap}, &cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data[HAProxyAuxKey] == "" || cm.Data[HAProxySPOEKey] == "" {
		t.Errorf("data %v", cm.Data)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "traefik", Name: HAProxyConfigMap}, &cm); err == nil {
		t.Error("Traefik's namespace got the HAProxy agent's ConfigMap")
	}
	// Edited: restored.
	cm = corev1.ConfigMap{}
	_ = c.Get(ctx, types.NamespacedName{Namespace: "haproxy-controller", Name: HAProxyConfigMap}, &cm)
	cm.Data[HAProxyAuxKey] = "edited"
	if err := c.Update(ctx, &cm); err != nil {
		t.Fatal(err)
	}
	if err := r.reconcileHAProxy(ctx, "haproxy-controller"); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, types.NamespacedName{Namespace: "haproxy-controller", Name: HAProxyConfigMap}, &cm)
	if cm.Data[HAProxyAuxKey] != HAProxyFiles()[HAProxyAuxKey] {
		t.Error("an edited ConfigMap was not restored")
	}
	// The pods are gone, or the integration is disabled: removed.
	r.Disabled = map[string]string{"haproxy": "not allowed"}
	if err := r.reconcileHAProxy(ctx, "haproxy-controller"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "haproxy-controller", Name: HAProxyConfigMap}, &cm); err == nil {
		t.Error("the ConfigMap outlived the integration")
	}
}
