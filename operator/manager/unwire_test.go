// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"log/slog"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
)

// testUninstall stops the operator and runs the uninstall hook's Unwire:
// a policy deleted while the operator is gone waits for it, and the hook
// releases it and the others, although no replica answers the WAFPolicy
// webhook any more. It runs after testWiring (Traefik's IngressClass and
// pod). It also removes what the operator created for the engines: the
// trust ConfigMaps, the bundle grant, and its leader Lease (#260).
func testUninstall(ctx context.Context, t *testing.T, c client.Client, stop func()) {
	const ns = "bye"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, ingress(ns, "web", "traefik", nil)); err != nil {
		t.Fatal(err)
	}
	gone, kept := targeting(ns, "gone", "web"), targeting(ns, "kept", "web")
	for _, p := range []*wafv1alpha1.WAFPolicy{gone, kept} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	held := func(p *wafv1alpha1.WAFPolicy) (bool, error) {
		var got wafv1alpha1.WAFPolicy
		err := c.Get(ctx, client.ObjectKeyFromObject(p), &got)
		return controllerutil.ContainsFinalizer(&got, wiring.Finalizer), err
	}
	wired := func() bool {
		var ing networkingv1.Ingress
		return c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "web"}, &ing) == nil && ing.Annotations[wiring.WiredAnnotation] != ""
	}
	eventually(t, "wired and held", func() string {
		for _, p := range []*wafv1alpha1.WAFPolicy{gone, kept} {
			if h, err := held(p); err != nil || !h {
				return p.Name + " not held"
			}
		}
		if !wired() {
			return "not wired"
		}
		return ""
	})

	// The grant exists while the operator runs, even with no proxy pod.
	eventually(t, "the bundle grant", func() string {
		if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: injection.GrantName}, &rbacv1.RoleBinding{}); err != nil {
			return err.Error()
		}
		return ""
	})

	stop()
	// The manager's context is done.
	ctx = context.Background()
	// A trust ConfigMap the operator created, and one of the user's own,
	// unlabelled (as hack/kind/e2e.sh creates for a standalone engine).
	operators := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: injection.TrustConfigMap,
		Labels: map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"},
	}}
	users := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: injection.TrustConfigMap}}
	for _, cm := range []*corev1.ConfigMap{operators, users} {
		if err := c.Create(ctx, cm); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: leaderElectionID}, &coordinationv1.Lease{}); err != nil {
		t.Fatalf("the leader Lease before the uninstall: %v", err)
	}
	if err := c.Delete(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if h, err := held(gone); err != nil || !h || !wired() {
		t.Fatalf("deleted while the operator is down: held %v (%v), wired %v; want both", h, err, wired())
	}

	if err := Unwire(ctx, c, "default", "inkwall-operator", slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if wired() {
		t.Error("still wired after the uninstall")
	}
	var left corev1.ConfigMapList
	if err := c.List(ctx, &left, client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}); err != nil {
		t.Fatal(err)
	}
	for _, cm := range left.Items {
		t.Errorf("ConfigMap %s/%s left after the uninstall", cm.Namespace, cm.Name)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(users), &corev1.ConfigMap{}); err != nil {
		t.Errorf("the user's own %s ConfigMap: %v, want it kept", injection.TrustConfigMap, err)
	}
	for _, obj := range []client.Object{&rbacv1.Role{}, &rbacv1.RoleBinding{}} {
		if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: injection.GrantName}, obj); !apierrors.IsNotFound(err) {
			t.Errorf("the bundle grant (%T) after the uninstall: %v, want it gone", obj, err)
		}
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: leaderElectionID}, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
		t.Errorf("the leader Lease after the uninstall: %v, want it gone", err)
	}
	if _, err := held(gone); !apierrors.IsNotFound(err) {
		t.Errorf("the policy deleted before the uninstall: %v, want it gone", err)
	}
	if h, err := held(kept); err != nil || h {
		t.Errorf("the policy kept: held %v (%v), want released", h, err)
	}
	// Deleting it now doesn't wait for an operator.
	if err := c.Delete(ctx, kept); err != nil {
		t.Fatal(err)
	}
	if _, err := held(kept); !apierrors.IsNotFound(err) {
		t.Errorf("deleted after the uninstall: %v, want it gone", err)
	}
}
