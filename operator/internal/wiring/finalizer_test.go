// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

// TestFinalizer runs the wiring controller against an API server, one
// reconcile at a time: between two, the operator is down. Each reconciler
// gets a new client, as a restarted operator would.
func TestFinalizer(t *testing.T) {
	testenv.Skip(t, env)
	ctx := context.Background()
	s := scheme()
	newClient := func(funcs *interceptor.Funcs) client.Client {
		t.Helper()
		c, err := client.NewWithWatch(env.Config, client.Options{Scheme: s})
		if err != nil {
			t.Fatal(err)
		}
		if funcs != nil {
			return interceptor.NewClient(c, *funcs)
		}
		return c
	}
	c := newClient(nil)
	traefikPods := integrations.Defaults().Selector(integrations.Traefik.Name)
	// reconcileWith is one reconcile of an operator that has just
	// (re)started; reconcileOnce, with a new client.
	reconcileWith := func(r *Reconciler) error {
		t.Helper()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		return err
	}
	reconcileOnce := func() {
		t.Helper()
		cl := newClient(nil)
		if err := reconcileWith(&Reconciler{Client: cl, APIReader: cl, TraefikPods: traefikPods}); err != nil {
			t.Fatal(err)
		}
	}
	create := func(objs ...client.Object) {
		t.Helper()
		for _, o := range objs {
			if err := c.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	del := func(o client.Object) {
		t.Helper()
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	policy := func(name string, targets ...wafv1alpha1.TargetRef) *wafv1alpha1.WAFPolicy {
		return &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}, Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: targets}}
	}
	ingressRef := wafv1alpha1.TargetRef{Kind: "Ingress", Name: "web"}
	routeRef := wafv1alpha1.TargetRef{Group: "traefik.io", Kind: "IngressRoute", Name: "app"}
	// held reports whether p exists and has the finalizer; gone: it doesn't
	// exist.
	held := func(p *wafv1alpha1.WAFPolicy) (has, gone bool) {
		t.Helper()
		var got wafv1alpha1.WAFPolicy
		switch err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); {
		case apierrors.IsNotFound(err):
			return false, true
		case err != nil:
			t.Fatal(err)
		}
		return controllerutil.ContainsFinalizer(&got, Finalizer), false
	}
	wantHeld := func(what string, p *wafv1alpha1.WAFPolicy) {
		t.Helper()
		if has, gone := held(p); !has || gone {
			t.Errorf("%s: %s not held by the finalizer (gone: %v)", what, p.Name, gone)
		}
	}
	wantGone := func(what string, p *wafv1alpha1.WAFPolicy) {
		t.Helper()
		if _, gone := held(p); !gone {
			t.Errorf("%s: %s still there", what, p.Name)
		}
	}
	ingressWired := func() bool {
		t.Helper()
		var ing networkingv1.Ingress
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: "web"}, &ing); err != nil {
			t.Fatal(err)
		}
		return ing.Annotations[WiredAnnotation] != ""
	}
	routeWired := func() bool {
		t.Helper()
		ir := &unstructured.Unstructured{}
		ir.SetGroupVersionKind(IngressRouteGVK)
		if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: "app"}, ir); err != nil {
			t.Fatal(err)
		}
		return ir.GetAnnotations()[WiredAnnotation] != "" || middlewares(ir) != "auth"
	}
	middlewareExists := func() bool {
		t.Helper()
		m := &unstructured.Unstructured{}
		m.SetGroupVersionKind(MiddlewareGVK)
		err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: MiddlewareName}, m)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
		return err == nil
	}
	programmedReason := func(p *wafv1alpha1.WAFPolicy) string {
		t.Helper()
		var got wafv1alpha1.WAFPolicy
		if err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
			t.Fatal(err)
		}
		if cnd := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionProgrammed); cnd != nil {
			return cnd.Reason
		}
		return ""
	}

	create(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "proxy"}},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "traefik"}, Spec: networkingv1.IngressClassSpec{Controller: integrations.Traefik.Controller}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("traefik"),
			DefaultBackend:   &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}},
		}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik", Labels: map[string]string{"app.kubernetes.io/name": "traefik"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}}},
		},
	)

	// The IngressRoute CRD isn't installed, and the Ingress targeted is
	// gone: nothing holds the policy once deleted.
	orphan := policy("orphan", routeRef, wafv1alpha1.TargetRef{Kind: "Ingress", Name: "gone"})
	create(orphan)
	reconcileOnce()
	wantHeld("held before it is wired", orphan)
	del(orphan)
	reconcileOnce()
	wantGone("no target to unwire", orphan)

	if err := testenv.InstallLater(env); err != nil {
		t.Fatal(err)
	}
	ir := ingressRoute("shop", "app", []any{map[string]any{"name": "auth"}})
	create(ir)

	// Wired, then deleted while the operator is down: the routes stay wired
	// and the policy stays until the operator is back.
	web := policy("web", ingressRef, routeRef)
	create(web)
	reconcileOnce()
	wantHeld("wired", web)
	if !ingressWired() || !routeWired() || !middlewareExists() {
		t.Fatalf("not wired: Ingress %v, IngressRoute %v, Middleware %v", ingressWired(), routeWired(), middlewareExists())
	}
	del(web)
	wantHeld("deleted while the operator is down", web)
	if !ingressWired() || !routeWired() {
		t.Fatal("unwired without the operator")
	}
	reconcileOnce()
	wantGone("the operator back", web)
	if ingressWired() || routeWired() || middlewareExists() {
		t.Errorf("still wired once the policy went: Ingress %v, IngressRoute %v, Middleware %v", ingressWired(), routeWired(), middlewareExists())
	}

	// An IngressRoute that can't be unwired holds its policy until it can.
	route := policy("route", routeRef)
	create(route)
	reconcileOnce()
	if !routeWired() {
		t.Fatal("IngressRoute not wired")
	}
	del(route)
	refuse := newClient(&interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if obj.GetObjectKind().GroupVersionKind().Kind == IngressRouteGVK.Kind {
			return apierrors.NewForbidden(schema.GroupResource{Group: "traefik.io", Resource: "ingressroutes"}, obj.GetName(), nil)
		}
		return c.Patch(ctx, obj, patch, opts...)
	}})
	if err := reconcileWith(&Reconciler{Client: refuse, APIReader: refuse, TraefikPods: traefikPods}); err == nil {
		t.Error("an IngressRoute not unwired: no error")
	}
	wantHeld("an IngressRoute not unwired", route)
	reconcileOnce()
	wantGone("the IngressRoute unwired", route)

	// A cache that doesn't show yet that the Ingress was wired: the
	// policy waits until the API server shows it unwired.
	stale := policy("stale", ingressRef)
	create(stale)
	reconcileOnce()
	if !ingressWired() {
		t.Fatal("Ingress not wired")
	}
	del(stale)
	api := newClient(nil)
	cached := newClient(&interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if err := c.List(ctx, list, opts...); err != nil {
			return err
		}
		if l, ok := list.(*networkingv1.IngressList); ok {
			for i := range l.Items {
				l.Items[i].Annotations = nil
			}
		}
		return nil
	}})
	if err := reconcileWith(&Reconciler{Client: cached, APIReader: api, TraefikPods: traefikPods}); err == nil {
		t.Error("released with the Ingress still wired: no error")
	}
	wantHeld("the Ingress still wired", stale)
	reconcileOnce()
	wantGone("the Ingress unwired", stale)

	// A policy that can't be held yet (the webhook not answering, say) is
	// wired anyway: unwiring it would drop its protection.
	unheld := policy("unheld", ingressRef)
	create(unheld)
	refusePolicies := newClient(&interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*wafv1alpha1.WAFPolicy); ok {
			return apierrors.NewServiceUnavailable("webhook down")
		}
		return c.Patch(ctx, obj, patch, opts...)
	}})
	if err := reconcileWith(&Reconciler{Client: refusePolicies, APIReader: refusePolicies, TraefikPods: traefikPods}); err == nil {
		t.Error("finalizer not added: no error")
	}
	if has, _ := held(unheld); has || !ingressWired() {
		t.Errorf("not held yet: held %v, wired %v; want wired, not held", has, ingressWired())
	}
	reconcileOnce()
	wantHeld("held once it can be", unheld)
	del(unheld)
	reconcileOnce()
	wantGone("deleted", unheld)

	// Another policy keeps a shared target wired.
	first, second := policy("first", ingressRef), policy("second", ingressRef)
	create(first, second)
	reconcileOnce()
	del(first)
	reconcileOnce()
	wantGone("one of two policies deleted", first)
	if !ingressWired() {
		t.Error("the other policy's Ingress was unwired")
	}

	// No Traefik pod selected (the InkwallConfig's selector doesn't match
	// it, or was deleted): new Traefik pods won't have the engine, the
	// routes are unwired. The policy is still held.
	cl := newClient(nil)
	edge := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/component": "edge-proxy"})
	if err := reconcileWith(&Reconciler{Client: cl, APIReader: cl, TraefikPods: edge}); err != nil {
		t.Fatal(err)
	}
	if ingressWired() || middlewareExists() {
		t.Error("wired without a Traefik pod that gets the engine")
	}
	wantHeld("no Traefik pod selected", second)
	if r := programmedReason(second); r != ReasonSidecarMissing {
		t.Errorf("Programmed %s, want %s", r, ReasonSidecarMissing)
	}
	reconcileOnce()
	if !ingressWired() {
		t.Fatal("not wired again with the Traefik pod selected")
	}

	// Injection off: everything unwired, the policies released.
	off := func() {
		t.Helper()
		cl := newClient(nil)
		if err := reconcileWith(&Reconciler{Client: cl, APIReader: cl, TraefikPods: traefikPods, Disabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	off()
	if ingressWired() || middlewareExists() {
		t.Error("still wired with injection off")
	}
	if has, gone := held(second); has || gone {
		t.Errorf("injection off: held %v, gone %v; want released and kept", has, gone)
	}
	if r := programmedReason(second); r != ReasonInjectionDisabled {
		t.Errorf("Programmed %s, want %s", r, ReasonInjectionDisabled)
	}
	// A policy deleted then is gone at once.
	del(second)
	wantGone("deleted with injection off", second)

	// The uninstall releases every policy, also one being deleted.
	kept, deleting := policy("kept", ingressRef), policy("deleting", routeRef)
	create(kept, deleting)
	reconcileOnce()
	del(deleting)
	n, err := Unwire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if n.Policies != 2 || n.Ingresses != 1 || n.IngressRoutes != 1 {
		t.Errorf("unwired %+v, want 2 policies, 1 Ingress, 1 IngressRoute", n)
	}
	if has, gone := held(kept); has || gone {
		t.Errorf("after the uninstall: held %v, gone %v; want released and kept", has, gone)
	}
	wantGone("deleted before the uninstall", deleting)
	if ingressWired() || routeWired() {
		t.Error("still wired after the uninstall")
	}
	del(kept)
	wantGone("deleted after the uninstall", kept)
}
