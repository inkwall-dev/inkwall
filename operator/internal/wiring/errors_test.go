// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"errors"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Each policy that can't be held is reported, in one flat list: a nested
// errors.Join costs O(n²) to print, half a gigabyte at an initial sync of
// thousands of policies (#213).
func TestReconcileErrorsFlat(t *testing.T) {
	const n = 50
	b := fake.NewClientBuilder().WithScheme(scheme()).WithStatusSubresource(&wafv1alpha1.WAFPolicy{})
	for i := range n {
		b.WithObjects(&wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: fmt.Sprintf("p%d", i)}})
	}
	c := b.WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			return apierrors.NewConflict(schema.GroupResource{Group: wafv1alpha1.GroupVersion.Group, Resource: "wafpolicies"}, obj.GetName(), nil)
		},
	}).Build()

	_, err := (&Reconciler{Client: c}).Reconcile(context.Background(), reconcile.Request{})
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) {
		t.Fatalf("got %v, want the joined errors", err)
	}
	if got := len(joined.Unwrap()); got != n {
		t.Fatalf("%d errors at the top, want %d, one per policy", got, n)
	}
	if !apierrors.IsConflict(err) {
		t.Errorf("the conflicts are lost: %v", err)
	}
}
