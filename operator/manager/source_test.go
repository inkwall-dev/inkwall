// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// setMode puts the cluster in mode, creating the InkwallConfig if needed.
func setMode(ctx context.Context, t *testing.T, c client.Client, mode wafv1alpha1.ClusterMode) {
	t.Helper()
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); apierrors.IsNotFound(err) {
		if err := c.Create(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) {
		cfg.Spec.Mode = mode
		cfg.Spec.ControlPlane = nil
		if mode != wafv1alpha1.ModeStandalone {
			// Nothing listens there: the operator only tries to enroll.
			cfg.Spec.ControlPlane = &wafv1alpha1.ControlPlane{
				Endpoint:            "grpcs://localhost:1",
				EnrollmentSecretRef: wafv1alpha1.SecretReference{Namespace: "default", Name: "no-token"},
			}
		}
	})
}

// testSourceGuard checks the webhook as deployed keeps the control plane's
// objects to the operator in Managed mode: the test's client writes as the
// operator does, and alice, a cluster admin, is someone else.
func testSourceGuard(ctx context.Context, t *testing.T, c client.Client) {
	cfg, err := env.User("alice", "system:masters")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := client.New(cfg, client.Options{Scheme: c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	policy := func(name string, labels map[string]string) *wafv1alpha1.WAFPolicy {
		return &wafv1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Labels: labels},
			Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "managed"}}},
		}
	}
	saas := map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}
	managed := policy("managed", saas)
	if err := c.Create(ctx, managed); err != nil {
		t.Fatal(err)
	}
	setMode(ctx, t, c, wafv1alpha1.ModeManaged)
	defer setMode(ctx, t, c, wafv1alpha1.ModeStandalone)

	// The webhook reads the mode from its cache: wait for it.
	eventually(t, "alice's edit refused", func() string {
		p := managed.DeepCopy()
		if err := alice.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
			return err.Error()
		}
		p.Spec.Mode = wafv1alpha1.PolicyBlock
		if err := alice.Update(ctx, p); !apierrors.IsForbidden(err) {
			return "got " + errString(err)
		}
		return ""
	})
	if err := alice.Delete(ctx, managed.DeepCopy()); !apierrors.IsForbidden(err) {
		t.Errorf("alice deletes it: %v", err)
	}
	p := managed.DeepCopy()
	if err := alice.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
		t.Fatal(err)
	}
	delete(p.Labels, wafv1alpha1.SourceLabel)
	if err := alice.Update(ctx, p); !apierrors.IsForbidden(err) {
		t.Errorf("alice removes the label: %v", err)
	}
	if err := alice.Create(ctx, policy("forged", saas)); !apierrors.IsForbidden(err) {
		t.Errorf("alice creates one: %v", err)
	}
	// Her own objects are hers.
	own := policy("alices", nil)
	if err := alice.Create(ctx, own); err != nil {
		t.Errorf("alice's own policy: %v", err)
	}
	if err := alice.Delete(ctx, own); err != nil {
		t.Errorf("alice deletes her own policy: %v", err)
	}
	// The operator may.
	update(ctx, t, c, managed, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })

	// Out of Managed mode, they are ordinary objects.
	setMode(ctx, t, c, wafv1alpha1.ModeGitOps)
	eventually(t, "alice deletes it in GitOps mode", func() string {
		if err := alice.Delete(ctx, managed.DeepCopy()); client.IgnoreNotFound(err) != nil {
			return err.Error()
		}
		return ""
	})
}

func errString(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}
