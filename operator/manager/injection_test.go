// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"bytes"
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// testInjection creates proxy pods as Traefik's Deployment would: the Pod
// webhook adds the engine, and the operator provides the trust ConfigMap
// and the RBAC grant the engine needs.
func testInjection(ctx context.Context, t *testing.T, c client.Client) {
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "proxy"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik"}},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	pod := func(name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: name, Labels: labels},
			Spec: corev1.PodSpec{
				ServiceAccountName: "traefik",
				Containers:         []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}},
			},
		}
	}
	traefik := pod("traefik-1", map[string]string{"app.kubernetes.io/name": "traefik"})
	other := pod("shop-1", map[string]string{"app": "shop"})
	for _, p := range []*corev1.Pod{traefik, other} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	// The webhook answered at creation: the engine is in the Traefik pod.
	if err := c.Get(ctx, client.ObjectKeyFromObject(traefik), traefik); err != nil {
		t.Fatal(err)
	}
	if len(traefik.Spec.InitContainers) != 1 || traefik.Spec.InitContainers[0].Name != injection.ContainerName ||
		traefik.Spec.InitContainers[0].Image != "inkwall-engine:test" {
		t.Fatalf("the engine was not injected: %+v", traefik.Spec.InitContainers)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(other), other); err != nil {
		t.Fatal(err)
	}
	if len(other.Spec.InitContainers) != 0 {
		t.Fatal("a pod that isn't a proxy got the engine")
	}

	eventually(t, "the trust ConfigMap", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: injection.TrustConfigMap}, &cm); err != nil {
			return err.Error()
		}
		if cm.Data["ca.crt"] == "" || len(cm.BinaryData["ed25519.pub"]) != 32 {
			return "incomplete"
		}
		// Between rotations, the one key, also as the set engines trust.
		if !bytes.Equal(cm.BinaryData["trusted-keys.pub"], cm.BinaryData["ed25519.pub"]) {
			return "trusted-keys.pub is not the signing key"
		}
		return ""
	})
	eventually(t, "the RBAC grant", func() string {
		var rb rbacv1.RoleBinding
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: injection.GrantName}, &rb); err != nil {
			return err.Error()
		}
		for _, s := range rb.Subjects {
			if s.Namespace == "proxy" && s.Name == "traefik" {
				return ""
			}
		}
		return "Traefik's ServiceAccount not granted"
	})

	// The proxy's last pod gone: the trust ConfigMap goes too.
	if err := c.Delete(ctx, traefik, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the trust ConfigMap removed", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: injection.TrustConfigMap}, &cm); !apierrors.IsNotFound(err) {
			return "still there"
		}
		return ""
	})
}
