// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policystatus

import (
	"context"
	"strings"
	"testing"
	"time"

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

// TestGeoDatabaseUnavailableEvent: a policy with spec.geo whose cluster has
// no country database gets one Warning Event when Enforced turns
// GeoDatabaseUnavailable (design 0011 §7), and none again while it stays.
func TestGeoDatabaseUnavailableEvent(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	ready := []metav1.Condition{cond("Accepted", "True", "Accepted"), cond("Programmed", "True", "Programmed"),
		cond("Enforced", "True", "Enforced"), cond("Ready", "True", "Ready")}
	p := policy("geo", ready...)
	p.Spec.Geo = &wafv1alpha1.GeoSpec{Deny: []wafv1alpha1.CountryCode{"RU"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(p).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).Build()
	rec := events.NewFakeRecorder(10)
	now := time.Unix(1_800_000_000, 0)
	w := &Watcher{Client: c, Recorder: rec, Every: 30 * time.Second, Now: func() time.Time { return now }}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "shop", Name: "geo"}}
	if _, err := w.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	unavailable := cond("Enforced", "False", "GeoDatabaseUnavailable")
	for range 2 {
		now = now.Add(time.Minute)
		if err := c.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
			t.Fatal(err)
		}
		meta.SetStatusCondition(&p.Status.Conditions, unavailable)
		// As the Reporter sets it: Ready follows Enforced.
		meta.SetStatusCondition(&p.Status.Conditions, cond("Ready", "False", "GeoDatabaseUnavailable"))
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	got := drain(rec)
	if len(got) != 1 || !strings.HasPrefix(got[0], "Warning GeoDatabaseUnavailable") {
		t.Errorf("events: %q, want one Warning GeoDatabaseUnavailable", got)
	}
}
