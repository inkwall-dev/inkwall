// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

func accepted(keys ...types.NamespacedName) resolver.Result {
	res := resolver.Result{PolicyStatus: map[types.NamespacedName]resolver.Status{}}
	for _, k := range keys {
		res.PolicyStatus[k] = resolver.Status{Accepted: true, Applied: true, Reason: resolver.ReasonAccepted}
	}
	return res
}

// A new leader takes each policy's bundleVersion from the bundle, not from
// the status the previous leader may not have written.
func TestNewLeaderBundleVersion(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	// The previous leader published v5 with p's new spec (generation 2) and
	// stopped before writing p's status, which still names generation 1's
	// bundle 3. q is unchanged since bundle 4, though its status says 2.
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p", Generation: 2}}
	p.Status.BundleVersion, p.Status.ObservedGeneration = 3, 1
	q := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "q", Generation: 1}}
	q.Status.BundleVersion, q.Status.ObservedGeneration = 2, 1
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(p, q).WithStatusSubresource(p, q).Build()
	r := &BundleReconciler{Client: c}
	keyP, keyQ := client.ObjectKeyFromObject(p), client.ObjectKeyFromObject(q)

	for _, tc := range []struct {
		name         string
		versions     []uint64
		wantP, wantQ int64
	}{
		// From an operator before v0.3.0: the bundle's own version.
		{"no policy versions", nil, 5, 5},
		{"policy versions", []uint64{5, 4}, 5, 4},
	} {
		cur := &bundlev1.Bundle{Version: 5, PolicyVersions: tc.versions, Policies: []*bundlev1.Policy{
			{Id: "shop/p", Mode: bundlev1.Mode_MODE_DETECT}, {Id: "shop/q"},
		}}
		var list wafv1alpha1.WAFPolicyList
		if err := c.List(ctx, &list); err != nil {
			t.Fatal(err)
		}
		if err := r.writeStatus(ctx, accepted(keyP, keyQ), cur, list.Items, nil, nil); err != nil {
			t.Fatal(err)
		}
		for _, want := range []struct {
			key     types.NamespacedName
			version int64
		}{{keyP, tc.wantP}, {keyQ, tc.wantQ}} {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, want.key, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.BundleVersion != want.version || got.Status.ObservedGeneration != got.Generation {
				t.Errorf("%s: %s: bundleVersion %d observedGeneration %d, want %d and %d", tc.name, want.key,
					got.Status.BundleVersion, got.Status.ObservedGeneration, want.version, got.Generation)
			}
		}
	}
}

// The build resolved generation 1; the user edits the policy (generation 2)
// while its status is written. The conflict retry doesn't report the
// build's result as generation 2's: the next build does.
func TestStatusConflictNewGeneration(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p", Generation: 1}}
	key := client.ObjectKeyFromObject(p)
	first := true
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(p).WithStatusSubresource(p).WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if first {
				first = false
				var cur wafv1alpha1.WAFPolicy
				if err := cl.Get(ctx, key, &cur); err != nil {
					return err
				}
				cur.Generation = 2
				cur.Spec.Mode = wafv1alpha1.PolicyBlock
				if err := cl.Update(ctx, &cur); err != nil {
					return err
				}
				return apierrors.NewConflict(schema.GroupResource{Resource: "wafpolicies"}, "p", nil)
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	}).Build()
	r := &BundleReconciler{Client: c}
	cur := &bundlev1.Bundle{Version: 5, Policies: []*bundlev1.Policy{{Id: "shop/p"}}}
	var got wafv1alpha1.WAFPolicy
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	if err := r.writeStatus(ctx, accepted(key), cur, []wafv1alpha1.WAFPolicy{got}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Generation != 2 || got.Status.ObservedGeneration == 2 {
		t.Fatalf("generation %d reported observed (%d) with bundleVersion %d, which holds generation 1's spec",
			got.Generation, got.Status.ObservedGeneration, got.Status.BundleVersion)
	}
}
