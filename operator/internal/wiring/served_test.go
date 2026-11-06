// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// podsIntegration wires every target of its kind on its pods, but those
// it is told have failed.
type podsIntegration struct {
	name   string
	kind   schema.GroupKind
	pods   []corev1.Pod
	failed map[string]bool
}

func (s *podsIntegration) Name() string              { return s.name }
func (s *podsIntegration) Kinds() []schema.GroupKind { return []schema.GroupKind{s.kind} }
func (s *podsIntegration) Watch(controller.Controller, cache.Cache, handler.EventHandler) error {
	return nil
}

func (s *podsIntegration) Wire(_ context.Context, targets map[Target]bool, _ bool) (*Result, error) {
	res := &Result{Proxy: s.name, Targets: map[Target]TargetState{}, Pods: s.pods}
	for t := range targets {
		if s.failed[t.Key.Name] {
			res.Targets[t] = TargetState{Failed: "broken"}
		} else {
			res.Targets[t] = TargetState{Wired: true}
		}
	}
	return res, nil
}
func (s *podsIntegration) Wired(context.Context, Target) (bool, error) { return false, nil }
func (s *podsIntegration) Unwire(context.Context, client.Client) (map[string]int, error) {
	return nil, nil
}

func enginePod(ns, name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "proxy"}, {Name: "inkwall-engine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// Two proxies, one of whose engines rejects the bundle: the policies only
// the other proxy serves stay Enforced; the bad proxy's policies, and one
// whose pods aren't known (its target failed), are EngineNack (#371). The
// wiring controller maps the policies to the pods, the Reporter counts
// only their engines, against an API server.
func TestEnforcedCountsServingEngines(t *testing.T) {
	testenv.Skip(t, env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := client.New(env.Config, client.Options{Scheme: scheme()})
	if err != nil {
		t.Fatal(err)
	}
	const ns = "served-371"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	policies := map[string]wafv1alpha1.TargetRef{
		"on-envoy":   {Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "web"},
		"on-haproxy": {Kind: "Ingress", Name: "shop"},
		"unknown":    {Kind: "Ingress", Name: "broken"},
	}
	versions := map[string]uint64{}
	for name, ref := range policies {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{ref}}}
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		p.Status.ObservedGeneration = p.Generation
		p.Status.BundleVersion = 2
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: wafv1alpha1.ConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: p.Generation})
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		versions[ns+"/"+name] = 2
	}

	served := &distribution.ServedPods{}
	r := &Reconciler{Client: c, Served: served, Integrations: []Integration{
		&podsIntegration{name: "envoy-gateway", kind: schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"},
			pods: []corev1.Pod{enginePod("envoy", "a1")}},
		&podsIntegration{name: "haproxy", kind: schema.GroupKind{Group: "networking.k8s.io", Kind: "Ingress"},
			pods: []corev1.Pod{enginePod("haproxy", "b1")}, failed: map[string]bool{"broken": true}},
	}}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}

	store := distribution.NewStore()
	store.SetPolicies(versions, false)
	table := distribution.NewTable()
	table.Connect(distribution.Engine{ID: "a1", PodNamespace: "envoy", PodName: "a1", Applied: 2})
	table.Connect(distribution.Engine{ID: "b1", PodNamespace: "haproxy", PodName: "b1", Applied: 1, Rejected: 2, RejectError: "bad rule"})
	pub := &distribution.Publisher{Client: c, Reader: c, Namespace: ns, Replica: "r1", Engines: table, Interval: 50 * time.Millisecond, Refresh: time.Second}
	rep := &distribution.Reporter{Client: c, Reader: c, Namespace: ns, Interval: 100 * time.Millisecond, Stale: time.Minute, Store: store, Served: served}
	for _, run := range []func(context.Context) error{pub.Start, rep.Start} {
		go func() { _ = run(ctx) }()
	}

	want := map[string]string{"on-envoy": distribution.ReasonEnforced, "on-haproxy": distribution.ReasonEngineNack, "unknown": distribution.ReasonEngineNack}
	deadline := time.Now().Add(30 * time.Second)
	for {
		got := map[string]string{}
		for name := range want {
			var p wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
				t.Fatal(err)
			}
			if cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionEnforced); cond != nil {
				got[name] = cond.Reason
			}
		}
		if equalMaps(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Enforced reasons %v, want %v", got, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
