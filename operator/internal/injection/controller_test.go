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
