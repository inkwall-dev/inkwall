// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestUnwire(t *testing.T) {
	ctx := context.Background()
	ref := MiddlewareRef("shop")
	ing := func(name string, annotations map[string]string) *networkingv1.Ingress {
		return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, Annotations: annotations}}
	}
	wired := ing("web", map[string]string{
		MiddlewaresAnnotation: "shop-auth@kubernetescrd," + ref + ",shop-gzip@kubernetescrd",
		WiredAnnotation:       ref,
	})
	onlyOurs := ing("api", map[string]string{MiddlewaresAnnotation: ref, WiredAnnotation: ref})
	untouched := ing("blog", map[string]string{MiddlewaresAnnotation: "shop-auth@kubernetescrd"})

	ours := Middleware("shop")
	theirs := Middleware("legacy")
	theirs.SetLabels(nil) // a Middleware of that name Inkwall didn't create

	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(wired, onlyOurs, untouched, ours, theirs).Build()

	ingresses, middlewares, err := Unwire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if ingresses != 2 || middlewares != 1 {
		t.Errorf("unwired %d Ingresses and %d Middlewares, want 2 and 1", ingresses, middlewares)
	}

	get := func(name string) *networkingv1.Ingress {
		var got networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: name}, &got); err != nil {
			t.Fatal(err)
		}
		return &got
	}
	if a := get("web").Annotations; a[MiddlewaresAnnotation] != "shop-auth@kubernetescrd,shop-gzip@kubernetescrd" || a[WiredAnnotation] != "" {
		t.Errorf("the user's Middlewares must stay, in order, without the marker: %v", a)
	}
	if a := get("api").Annotations; a[MiddlewaresAnnotation] != "" || a[WiredAnnotation] != "" {
		t.Errorf("an Ingress with only Inkwall's Middleware: %v", a)
	}
	if a := get("blog").Annotations; a[MiddlewaresAnnotation] != "shop-auth@kubernetescrd" {
		t.Errorf("an Ingress Inkwall didn't wire changed: %v", a)
	}

	mw := func(namespace string) error {
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(MiddlewareGVK)
		return c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: MiddlewareName}, m)
	}
	if err := mw("shop"); !apierrors.IsNotFound(err) {
		t.Errorf("Inkwall's Middleware not deleted: %v", err)
	}
	if err := mw("legacy"); err != nil {
		t.Errorf("a Middleware Inkwall didn't create was deleted: %v", err)
	}

	// Again: nothing left to do.
	if i, m, err := Unwire(ctx, c); err != nil || i != 0 || m != 0 {
		t.Errorf("second run: %d, %d, %v", i, m, err)
	}
}
