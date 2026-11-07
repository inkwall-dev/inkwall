// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policystatus

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func policy(name string, conds ...metav1.Condition) *wafv1alpha1.WAFPolicy {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}}
	for _, c := range conds {
		meta.SetStatusCondition(&p.Status.Conditions, c)
	}
	return p
}

func cond(t, status, reason string) metav1.Condition {
	return metav1.Condition{Type: t, Status: metav1.ConditionStatus(status), Reason: reason, Message: reason + " message"}
}

func drain(rec *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// The gauge counts the policies by condition, status and reason; a
// transition of Ready, Programmed or Enforced records one Event; flapping
// faster than Every records one per Every, the last state included; a
// policy seen for the first time (the operator starting) records none.
func TestWatcher(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	ready := []metav1.Condition{cond("Accepted", "True", "Accepted"), cond("Programmed", "True", "Programmed"),
		cond("Enforced", "True", "Enforced"), cond("Ready", "True", "Ready")}
	a, b := policy("a", ready...), policy("b", ready...)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(a, b).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).Build()
	rec := events.NewFakeRecorder(100)
	now := time.Unix(1_800_000_000, 0)
	w := &Watcher{Client: c, Recorder: rec, Every: 30 * time.Second, Now: func() time.Time { return now }}
	reconcileOne := func(name string) reconcile.Result {
		t.Helper()
		res, err := w.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "shop", Name: name}})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	set := func(p *wafv1alpha1.WAFPolicy, cs ...metav1.Condition) {
		t.Helper()
		if err := c.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
			t.Fatal(err)
		}
		for _, x := range cs {
			meta.SetStatusCondition(&p.Status.Conditions, x)
		}
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	gauge := func(condition, status, reason string) float64 {
		return testutil.ToFloat64(policies.WithLabelValues(condition, status, reason))
	}

	reconcileOne("a")
	reconcileOne("b")
	if got := drain(rec); len(got) != 0 {
		t.Errorf("events for policies seen for the first time: %q", got)
	}
	if g := gauge("Ready", "True", "Ready"); g != 2 {
		t.Errorf("Ready True: %v policies, want 2", g)
	}

	// An engine rejects the bundle: one Warning Event, for Enforced and
	// Ready together.
	nack := cond("Enforced", "False", "EngineNack")
	set(a, nack, cond("Ready", "False", "EngineNack"))
	reconcileOne("a")
	got := drain(rec)
	if len(got) != 1 || !strings.HasPrefix(got[0], "Warning EngineNack") || !strings.Contains(got[0], "Enforced") {
		t.Errorf("events after EngineNack: %q, want one Warning EngineNack", got)
	}
	if g, r := gauge("Ready", "True", "Ready"), gauge("Ready", "False", "EngineNack"); g != 1 || r != 1 {
		t.Errorf("Ready True %v, False EngineNack %v; want 1 and 1", g, r)
	}

	// Flapping: back to Ready within Every records nothing yet, and asks
	// to be reconciled when Every has passed.
	now = now.Add(time.Second)
	set(a, ready...)
	if res := reconcileOne("a"); res.RequeueAfter <= 0 || res.RequeueAfter > 30*time.Second {
		t.Errorf("a suppressed transition requeues after %v", res.RequeueAfter)
	}
	if got := drain(rec); len(got) != 0 {
		t.Errorf("events within Every: %q", got)
	}
	for range 10 {
		now = now.Add(time.Second)
		set(a, nack, cond("Ready", "False", "EngineNack"))
		reconcileOne("a")
		set(a, ready...)
		reconcileOne("a")
	}
	if got := drain(rec); len(got) != 0 {
		t.Errorf("events while flapping within Every: %q", got)
	}
	now = now.Add(30 * time.Second)
	reconcileOne("a")
	got = drain(rec)
	if len(got) != 1 || !strings.HasPrefix(got[0], "Normal Ready") {
		t.Errorf("events after Every: %q, want one Normal Ready", got)
	}
	// Nothing changed since: nothing more.
	now = now.Add(time.Minute)
	reconcileOne("a")
	if got := drain(rec); len(got) != 0 {
		t.Errorf("events without a change: %q", got)
	}

	// Deleted: out of the gauge.
	if err := c.Delete(ctx, b); err != nil {
		t.Fatal(err)
	}
	reconcileOne("b")
	if g := gauge("Ready", "True", "Ready"); g != 1 {
		t.Errorf("Ready True after a deletion: %v, want 1", g)
	}
}
