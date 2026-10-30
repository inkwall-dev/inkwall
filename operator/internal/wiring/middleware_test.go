// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestMiddlewareResponseLimit(t *testing.T) {
	m := Middleware("shop")
	if v, _, _ := unstructured.NestedInt64(m.Object, "spec", "forwardAuth", "maxResponseBodySize"); v != 64<<10 {
		t.Errorf("maxResponseBodySize %d, want 64 KiB", v)
	}
	// A Middleware an older operator made, without the limit: corrected.
	old := middleware("shop", false)
	if ForwardAuthMatches(old) {
		t.Error("a Middleware without maxResponseBodySize matched")
	}
}

// TestEnsureMiddleware runs against an API server that keeps
// maxResponseBodySize (Traefik v3.7 and later) and one that drops it.
func TestEnsureMiddleware(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		drops    bool
		existing *unstructured.Unstructured
		writes   int // Creates and Updates over three reconciles
		limit    bool
	}{
		{name: "new", writes: 1, limit: true},
		{name: "from an older operator", existing: middleware("shop", false), writes: 1, limit: true},
		{name: "new, field dropped", drops: true, writes: 1},
		{name: "from an older operator, field dropped", drops: true, existing: middleware("shop", false), writes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			drop := func(obj client.Object) {
				writes++
				if u, ok := obj.(*unstructured.Unstructured); ok && tc.drops {
					unstructured.RemoveNestedField(u.Object, "spec", "forwardAuth", "maxResponseBodySize")
				}
			}
			b := fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					drop(obj)
					return c.Create(ctx, obj, opts...)
				},
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					drop(obj)
					return c.Update(ctx, obj, opts...)
				},
			})
			if tc.existing != nil {
				b = b.WithObjects(tc.existing)
			}
			c := b.Build()
			r := &Reconciler{Client: c, APIReader: c}
			for range 3 {
				if err := r.ensureMiddleware(ctx, "shop"); err != nil {
					t.Fatal(err)
				}
			}
			if writes != tc.writes {
				t.Errorf("%d writes, want %d", writes, tc.writes)
			}
			got := middleware("shop", true)
			if err := c.Get(ctx, client.ObjectKeyFromObject(got), got); err != nil {
				t.Fatal(err)
			}
			if hasResponseLimit(got) != tc.limit {
				t.Errorf("maxResponseBodySize kept: %v, want %v", hasResponseLimit(got), tc.limit)
			}
			if !forwardAuthMatches(got, tc.limit) {
				t.Errorf("stored Middleware isn't the operator's: %v", got.Object["spec"])
			}
		})
	}
}
