// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The reconciler lists every policy on each generation change, and only
// reads them: from the cache, without deep copies (#213).
func TestPodWebhookListsWithoutCopies(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "inkwall"},
		Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "pods.inkwall.dev"}},
	}
	policy := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "checkout"},
		Spec:       wafv1alpha1.WAFPolicySpec{Mode: wafv1alpha1.PolicyBlock},
	}
	lists := 0
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cfg, policy).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists++
			if o := (&client.ListOptions{}).ApplyOptions(opts); o.UnsafeDisableDeepCopy == nil || !*o.UnsafeDisableDeepCopy {
				t.Errorf("%T listed with deep copies", list)
			}
			return c.List(ctx, list, opts...)
		},
	}).Build()

	r := &PodWebhookReconciler{Client: c, ConfigName: "inkwall", WebhookName: "pods.inkwall.dev",
		Pods: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "traefik"}}}
	if _, err := r.Reconcile(context.Background(), podWebhookRequest); err != nil {
		t.Fatal(err)
	}
	if lists != 1 {
		t.Fatalf("%d lists, want 1", lists)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(cfg), cfg); err != nil {
		t.Fatal(err)
	}
	if fp := cfg.Webhooks[0].FailurePolicy; fp == nil || *fp != admissionregistrationv1.Fail {
		t.Errorf("failurePolicy %v, want Fail: a policy is in block mode", fp)
	}
}
