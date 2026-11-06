// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The Istio ingress wiring lists the pods a Gateway selects from the API
// server once per selector and reconcile, not once per VirtualService
// (#373): thousands of VirtualServices on one Gateway were thousands of
// uncached cluster-wide LIST calls.
func TestIstioIngressListsPodsOncePerSelector(t *testing.T) {
	ctx := context.Background()
	m := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{IstioVirtualServiceGVK, IstioGatewayGVK, EnvoyFilterGVK} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	sel := map[string]string{"istio": "ingressgateway"}
	objs := []client.Object{&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "gw-1", Labels: sel, UID: "gw-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}}
	for _, name := range []string{"edge", "edge-2"} {
		gw := newObject(IstioGatewayGVK, "shop", name)
		gw.SetLabels(nil)
		gw.Object["spec"] = map[string]any{"selector": map[string]any{"istio": "ingressgateway"}}
		objs = append(objs, gw)
	}
	targets := map[Target]bool{}
	const n = 20
	for i := range n {
		gws := "[edge]"
		if i%2 == 1 {
			gws = "[edge, edge-2]"
		}
		vs := testVS(t, "shop", fmt.Sprintf("web-%d", i), fmt.Sprintf("{gateways: %s, http: [{name: api}]}", gws))
		objs = append(objs, vs)
		targets[Target{Kind: virtualServiceKind, Key: types.NamespacedName{Namespace: "shop", Name: vs.GetName()}}] = true
	}
	c := fake.NewClientBuilder().WithScheme(scheme()).WithRESTMapper(m).WithObjects(objs...).Build()
	var lists atomic.Int32
	reader := interceptor.NewClient(c, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.PodList); ok {
				lists.Add(1)
			}
			return c.List(ctx, list, opts...)
		},
	})
	in := &IstioIngress{Client: c, APIReader: reader, Pods: labels.SelectorFromSet(sel), PodLabels: sel}
	res, err := in.Wire(ctx, targets, false)
	if err != nil || res == nil {
		t.Fatalf("Wire: %v %v", res, err)
	}
	if got := lists.Load(); got != 1 {
		t.Errorf("%d pod lists from the API server for %d VirtualServices on 2 Gateways with one selector, want 1", got, n)
	}
	if len(res.Targets) != n {
		t.Errorf("%d targets in the result, want %d", len(res.Targets), n)
	}
}

// stubIntegration wires what it is told: a nil Result and err from Wire
// when err is set, else every target wired, on pods.
type stubIntegration struct {
	name  string
	kinds []schema.GroupKind
	err   error
	pods  []corev1.Pod
	// rolling: the proxy's own controller replaces its pods.
	rolling bool
}

func (s *stubIntegration) Name() string              { return s.name }
func (s *stubIntegration) Kinds() []schema.GroupKind { return s.kinds }
func (s *stubIntegration) Watch(controller.Controller, cache.Cache, handler.EventHandler) error {
	return nil
}
func (s *stubIntegration) Wire(_ context.Context, targets map[Target]bool, _ bool) (*Result, error) {
	if s.err != nil {
		return nil, s.err
	}
	res := &Result{Proxy: s.name, Targets: map[Target]TargetState{}, Pods: s.pods, Rolling: s.rolling}
	for t := range targets {
		res.Targets[t] = TargetState{Wired: true}
	}
	return res, nil
}
func (s *stubIntegration) Wired(context.Context, Target) (bool, error) { return false, s.err }
func (s *stubIntegration) Unwire(context.Context, client.Client) (map[string]int, error) {
	return nil, nil
}

func withEngine(ns, name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name)},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "proxy"}, {Name: "inkwall-engine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func policyOn(name, kind string, deleted bool) *wafv1alpha1.WAFPolicy {
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, Generation: 1, Finalizers: []string{Finalizer}},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Group: "example.com", Kind: kind, Name: name}}},
	}
	if deleted {
		p.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
	}
	return p
}

// One integration that fails doesn't stop the others reporting Programmed,
// nor the release of a deleted policy whose targets aren't wired (#373).
// The failing integration's targets are WiringFailed, not left out.
func TestReconcileOneIntegrationFails(t *testing.T) {
	ctx := context.Background()
	good := &stubIntegration{name: "good", kinds: []schema.GroupKind{{Group: "example.com", Kind: "Good"}},
		pods: []corev1.Pod{withEngine("proxy", "good-1")}}
	bad := &stubIntegration{name: "bad", kinds: []schema.GroupKind{{Group: "example.com", Kind: "Bad"}}, err: errors.New("the API is down")}
	c := fake.NewClientBuilder().WithScheme(scheme()).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).
		WithObjects(policyOn("served", "Good", false), policyOn("broken", "Bad", false), policyOn("gone", "Good", true)).Build()
	r := &Reconciler{Client: c, Integrations: []Integration{bad, good}}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil || !strings.Contains(err.Error(), "the API is down") {
		t.Errorf("reconcile: %v, want the integration's error", err)
	}
	get := func(name string) *wafv1alpha1.WAFPolicy {
		var p wafv1alpha1.WAFPolicy
		if err := c.Get(ctx, types.NamespacedName{Namespace: "shop", Name: name}, &p); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			t.Fatal(err)
		}
		return &p
	}
	if c := meta.FindStatusCondition(get("served").Status.Conditions, wafv1alpha1.ConditionProgrammed); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("the other integration's policy: Programmed %v", c)
	}
	if c := meta.FindStatusCondition(get("broken").Status.Conditions, wafv1alpha1.ConditionProgrammed); c == nil ||
		c.Status != metav1.ConditionFalse || c.Reason != ReasonWiringFailed || !strings.Contains(c.Message, "the API is down") {
		t.Errorf("the failing integration's policy: Programmed %v", c)
	}
	if p := get("gone"); p != nil && controllerutil.ContainsFinalizer(p, Finalizer) {
		t.Error("the deleted policy is still held")
	}
}

// Programmed names the workloads whose pods lack the engine, not the pods:
// a rollout of N pods then rewrites each policy's status a bounded number
// of times, not once per pod (#373, 0004 §4.8).
func TestSidecarsNameWorkloads(t *testing.T) {
	owned := func(name string, engine bool) corev1.Pod {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-7d9f-" + name, UID: types.UID(name),
				Labels:          map[string]string{"pod-template-hash": "7d9f"},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "traefik-7d9f", Controller: ptr.To(true)}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		if engine {
			p.Spec.Containers = []corev1.Container{{Name: "inkwall-engine"}}
		}
		return p
	}
	for _, rolling := range []bool{false, true} {
		var msgs []string
		// A rollout: the pods get the engine one by one.
		for done := range 3 {
			var pods []corev1.Pod
			for i, n := range []string{"a", "b", "c"} {
				pods = append(pods, owned(n, i < done))
			}
			st, reason, msg := sidecars(&Result{Proxy: "Traefik", Pods: pods, Rolling: rolling}, time.Time{})
			if st != metav1.ConditionFalse || reason != ReasonPendingRestart {
				t.Fatalf("rolling %v, %d done: %s %s", rolling, done, st, reason)
			}
			if !strings.Contains(msg, "Deployment traefik/traefik") || strings.Contains(msg, "traefik-7d9f") {
				t.Errorf("rolling %v: %q doesn't name the Deployment, or names a pod", rolling, msg)
			}
			msgs = append(msgs, msg)
		}
		if msgs[0] != msgs[1] || msgs[1] != msgs[2] {
			t.Errorf("rolling %v: the message changes with each pod:\n%s", rolling, strings.Join(msgs, "\n"))
		}
	}
}

// A status write that fails doesn't leave the other policies' Programmed
// stale: report writes them all, a bounded number at once, and returns
// every error (#373).
func TestReportWritesEveryStatus(t *testing.T) {
	ctx := context.Background()
	good := &stubIntegration{name: "good", kinds: []schema.GroupKind{{Group: "example.com", Kind: "Good"}},
		pods: []corev1.Pod{withEngine("proxy", "good-1")}}
	const n = 40
	b := fake.NewClientBuilder().WithScheme(scheme()).WithStatusSubresource(&wafv1alpha1.WAFPolicy{})
	for i := range n {
		b.WithObjects(policyOn(fmt.Sprintf("p%02d", i), "Good", false))
	}
	var inFlight, most atomic.Int32
	c := b.WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			cur := inFlight.Add(1)
			defer inFlight.Add(-1)
			for m := most.Load(); cur > m && !most.CompareAndSwap(m, cur); m = most.Load() {
			}
			time.Sleep(5 * time.Millisecond)
			if name := obj.GetName(); name == "p03" || name == "p17" {
				return fmt.Errorf("refused %s", name)
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}).Build()
	r := &Reconciler{Client: c, Integrations: []Integration{good}}
	_, err := r.Reconcile(ctx, reconcile.Request{})
	if err == nil || !strings.Contains(err.Error(), "refused p03") || !strings.Contains(err.Error(), "refused p17") {
		t.Errorf("reconcile: %v, want both refusals", err)
	}
	var list wafv1alpha1.WAFPolicyList
	if err := c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	written := 0
	for _, p := range list.Items {
		if meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionProgrammed) != nil {
			written++
		}
	}
	if written != n-2 {
		t.Errorf("%d policies have Programmed, want %d", written, n-2)
	}
	if m := most.Load(); m < 2 || m > statusWriters {
		t.Errorf("at most %d status writes at once, want 2 to %d", m, statusWriters)
	}
}
