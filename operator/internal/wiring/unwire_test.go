// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"maps"
	"slices"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
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

	// An IngressRoute wired with the user's Middlewares on one route, and
	// one Inkwall didn't wire.
	wiredRoute := ingressRoute("shop", "app", []any{
		map[string]any{"name": MiddlewareName},
		map[string]any{"name": "auth"},
	}, []any{map[string]any{"name": MiddlewareName, "namespace": "shop"}})
	wiredRoute.SetAnnotations(map[string]string{WiredAnnotation: MiddlewareName})
	userRoute := ingressRoute("shop", "mine", []any{map[string]any{"name": MiddlewareName}})
	// The same for HTTPRoutes.
	wiredHTTPRoute := httpRoute("shop", "app", []any{extRef(MiddlewareName), extRef("auth")}, []any{extRef(MiddlewareName)})
	wiredHTTPRoute.SetAnnotations(map[string]string{WiredAnnotation: MiddlewareName})
	userHTTPRoute := httpRoute("shop", "mine", []any{extRef(MiddlewareName)})

	// Policies the operator holds: one is kept, one is being deleted; and
	// another controller's finalizer, which stays.
	// Both were Accepted, Programmed and Ready; one wasn't held yet.
	wasProgrammed := wafv1alpha1.WAFPolicyStatus{Conditions: []metav1.Condition{{
		Type: wafv1alpha1.ConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.Now(),
	}, {
		Type: wafv1alpha1.ConditionProgrammed, Status: metav1.ConditionTrue, Reason: ReasonProgrammed, LastTransitionTime: metav1.Now(),
	}, {
		Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now(),
	}}}
	kept := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "kept", Finalizers: []string{Finalizer, "example.com/other"}},
		Status: wasProgrammed}
	unheld := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "unheld"}, Status: wasProgrammed}
	deleting := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "deleting", Finalizers: []string{Finalizer},
		DeletionTimestamp: ptr.To(metav1.Now())}}

	c := fake.NewClientBuilder().WithScheme(scheme()).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).
		WithObjects(wired, onlyOurs, untouched, ours, theirs, wiredRoute, userRoute, wiredHTTPRoute, userHTTPRoute, kept, unheld, deleting).Build()

	n, err := Unwire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if n.Policies != 2 || !maps.Equal(n.Objects, map[string]int{"Ingress": 2, "IngressRoute": 1, "HTTPRoute": 1, "Middleware": 1}) {
		t.Errorf("unwired %+v, want 2 Ingresses, 1 IngressRoute, 1 HTTPRoute, 1 Middleware and 2 policies", n)
	}
	var p wafv1alpha1.WAFPolicy
	if err := c.Get(ctx, client.ObjectKeyFromObject(kept), &p); err != nil || !slices.Equal(p.Finalizers, []string{"example.com/other"}) {
		t.Errorf("kept policy: %v, finalizers %v; want only the other controller's", err, p.Finalizers)
	}
	for _, obj := range []*wafv1alpha1.WAFPolicy{kept, unheld} {
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), &p); err != nil {
			t.Fatal(err)
		}
		if cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionProgrammed); cond == nil ||
			cond.Status != metav1.ConditionFalse || cond.Reason != ReasonUnwired {
			t.Errorf("policy %s: Programmed %+v, want False (Unwired)", obj.Name, cond)
		}
		if cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionReady); cond == nil ||
			cond.Status != metav1.ConditionFalse || cond.Reason != ReasonUnwired {
			t.Errorf("policy %s: Ready %+v, want False (Unwired)", obj.Name, cond)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(deleting), &p); !apierrors.IsNotFound(err) {
		t.Errorf("a policy being deleted, released: %v, want it gone", err)
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

	route := func(name string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(IngressRouteGVK)
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: name}, u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	app := route("app")
	if got := middlewares(app); got != "auth|" || app.GetAnnotations()[WiredAnnotation] != "" {
		t.Errorf("the user's Middlewares must stay, without Inkwall's or the marker: %q %v", got, app.GetAnnotations())
	}
	if got := middlewares(route("mine")); got != MiddlewareName {
		t.Errorf("an IngressRoute Inkwall didn't wire changed: %q", got)
	}

	hr := func(name string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(HTTPRouteGVK)
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: name}, u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	if app := hr("app"); ruleFilters(app) != "auth|" || app.GetAnnotations()[WiredAnnotation] != "" {
		t.Errorf("the user's filters must stay, without Inkwall's or the marker: %q %v", ruleFilters(app), app.GetAnnotations())
	}
	if got := ruleFilters(hr("mine")); got != MiddlewareName {
		t.Errorf("an HTTPRoute Inkwall didn't wire changed: %q", got)
	}

	// Again: nothing left to do.
	if n, err := Unwire(ctx, c); err != nil || n.Policies != 0 || len(n.Objects) != 0 {
		t.Errorf("second run: %+v, %v", n, err)
	}
}

// Without Traefik's CRDs, only the Ingresses are unwired.
func TestUnwireWithoutTraefikCRDs(t *testing.T) {
	ref := MiddlewareRef("shop")
	wired := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web",
		Annotations: map[string]string{MiddlewaresAnnotation: ref, WiredAnnotation: ref}}}
	c := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(wired).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok {
				return &meta.NoKindMatchError{GroupKind: u.GroupVersionKind().GroupKind()}
			}
			return c.List(ctx, list, opts...)
		},
	}).Build()
	n, err := Unwire(context.Background(), c)
	if err != nil || n.Policies != 0 || !maps.Equal(n.Objects, map[string]int{"Ingress": 1}) {
		t.Errorf("unwired %+v, %v; want 1 Ingress", n, err)
	}
}

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	return s
}
