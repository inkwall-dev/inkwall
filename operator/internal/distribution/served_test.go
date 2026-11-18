// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Only the engines on the pods that serve a policy's routes count for its
// Enforced (#371): one proxy's bad engine doesn't make the policies of
// another proxy EngineNack, EnginesBehind or EnginesOutdated. A policy
// whose pods aren't known, an engine without a pod, and an engine on a pod
// no policy is mapped to count as before: everywhere.
func TestEnforcedServedEngines(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	policy := func(name string, websocket bool) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: name, Generation: 1}}
		if websocket {
			p.Spec.WebSocket = &wafv1alpha1.WebSocketSpec{AllowedOrigins: []wafv1alpha1.WebSocketOrigin{"https://example.com"}}
		}
		p.Status.ObservedGeneration = 1
		p.Status.BundleVersion = 2
		for _, c := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed} {
			meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c, ObservedGeneration: 1})
		}
		return p
	}
	good := Engine{ID: "a1", PodNamespace: "envoy", PodName: "a1", Applied: 2, EngineVersion: "0.5.0"}
	for _, tc := range []struct {
		name string
		bad  Engine
		// websocket: the policies set spec.webSocket, which an engine
		// before 0.4.0 ignores.
		websocket bool
		reason    string
	}{
		{"rejected", Engine{ID: "b1", PodNamespace: "haproxy", PodName: "b1", Applied: 1, Rejected: 2, RejectError: "bad rule"}, false, ReasonEngineNack},
		{"behind", Engine{ID: "b1", PodNamespace: "haproxy", PodName: "b1", Applied: 1}, false, ReasonEnginesBehind},
		{"outdated", Engine{ID: "b1", PodNamespace: "haproxy", PodName: "b1", Applied: 2, EngineVersion: "0.3.3"}, true, ReasonEnginesOutdated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + "a", Labels: map[string]string{EnginesLabel: "true"}}}
			c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).
				WithObjects(policy("envoy-only", tc.websocket), policy("haproxy-only", tc.websocket), policy("unknown", tc.websocket), report).Build()
			served := &ServedPods{}
			served.Set(map[string]map[string]ServedPod{
				"web/envoy-only":   {"envoy/a1": {Integration: "envoy-gateway"}},
				"web/haproxy-only": {"haproxy/b1": {Integration: "haproxy"}},
			})
			r := &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: time.Minute, Store: NewStore(), Served: served}
			enforced := func(name string) *metav1.Condition {
				t.Helper()
				var p wafv1alpha1.WAFPolicy
				if err := c.Get(ctx, client.ObjectKey{Namespace: "web", Name: name}, &p); err != nil {
					t.Fatal(err)
				}
				return meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionEnforced)
			}
			step := func(engines []Engine, want map[string]string) {
				t.Helper()
				data, _ := json.Marshal(engines)
				report.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
				if err := c.Update(ctx, report); err != nil {
					t.Fatal(err)
				}
				if err := r.report(ctx); err != nil {
					t.Fatal(err)
				}
				for name, reason := range want {
					if got := enforced(name); got == nil || got.Reason != reason {
						t.Errorf("%s: Enforced %v, want %s", name, got, reason)
					}
				}
			}
			step([]Engine{good, tc.bad}, map[string]string{"envoy-only": ReasonEnforced, "haproxy-only": tc.reason, "unknown": tc.reason})
			// The engines metric names each engine's integration.
			if n := testutil.ToFloat64(engineCount.WithLabelValues("current", "envoy-gateway")); n != 1 {
				t.Errorf("current envoy-gateway engines: %v, want 1", n)
			}
			// An engine without a pod, or on a pod no policy is mapped
			// to, counts for every policy.
			for _, e := range []Engine{
				{ID: "x", Applied: tc.bad.Applied, Rejected: tc.bad.Rejected, RejectError: tc.bad.RejectError, EngineVersion: tc.bad.EngineVersion},
				{ID: "y", PodNamespace: "new", PodName: "y", Applied: tc.bad.Applied, Rejected: tc.bad.Rejected, RejectError: tc.bad.RejectError, EngineVersion: tc.bad.EngineVersion},
			} {
				step([]Engine{good, e}, map[string]string{"envoy-only": tc.reason, "unknown": tc.reason})
			}
			// No mapping at all: every engine counts.
			served.Set(nil)
			step([]Engine{good, tc.bad}, map[string]string{"envoy-only": tc.reason})
		})
	}
}

// A served pod with the engine container whose engine isn't connected
// holds its policy back (#652): while that engine reconnects, the pod may
// serve an older bundle, whatever the other engines run. A pod without the
// engine container (not injected, not running) isn't waited for, and an
// engine that reports no pod may be any pod's, so then none is.
func TestEnforcedWaitsForServedPodsEngines(t *testing.T) {
	served := &ServedPods{}
	served.Set(map[string]map[string]ServedPod{
		"web/eg": {
			"envoy/a1": {Integration: "envoy-gateway", Engine: true},
			"envoy/a2": {Integration: "envoy-gateway", Engine: true},
			"envoy/a3": {Integration: "envoy-gateway"},
		},
	})
	v := served.view()
	a1 := Engine{ID: "a1", PodNamespace: "envoy", PodName: "a1", Applied: 2}
	a2 := Engine{ID: "a2", PodNamespace: "envoy", PodName: "a2", Applied: 2}
	// The standalone engine: a pod no integration maps, so it counts.
	standalone := Engine{ID: "s", PodNamespace: "web", PodName: "standalone", Applied: 2}
	anonymous := Engine{ID: "x", Applied: 2}
	for _, tc := range []struct {
		name    string
		engines []Engine
		missing int
		reason  string
	}{
		{"every served engine connected", []Engine{a1, a2, standalone}, 0, ReasonEnforced},
		{"a served pod's engine reconnecting", []Engine{a1, standalone}, 1, ReasonEnginesBehind},
		{"only other engines connected", []Engine{standalone}, 2, ReasonEnginesBehind},
		{"an engine without a pod", []Engine{a1, anonymous}, 0, ReasonEnforced},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mine, missing := v.enginesFor("web/eg", tc.engines)
			if missing != tc.missing {
				t.Errorf("missing %d, want %d", missing, tc.missing)
			}
			st, reason, msg := Enforced(2, mine, 0, missing)
			if reason != tc.reason || (st == metav1.ConditionTrue) != (tc.reason == ReasonEnforced) {
				t.Errorf("Enforced %s %s (%s), want %s", st, reason, msg, tc.reason)
			}
		})
	}
	// A policy whose pods aren't known: nothing to wait for.
	if _, missing := v.enginesFor("web/other", []Engine{standalone}); missing != 0 {
		t.Errorf("unknown policy: missing %d, want 0", missing)
	}
}

// An engine that disconnected holds back, for Reporter.Gone, the policies
// it counts for while it hasn't run their current version (#675): until it
// reconnects, it serves the bundle it last ran. Raw Envoy's pods aren't
// known, so nothing else tells that its engine is missing. An engine gone
// with the policy's version doesn't change the status; a new leader knows
// the engines of the old one's report.
func TestEnforcedWaitsForDisconnectedEngines(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "raw-envoy", Name: "app", Generation: 1}}
	p.Status.ObservedGeneration = 1
	p.Status.BundleVersion = 2
	for _, c := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed} {
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c, ObservedGeneration: 1})
	}
	reportOf := func(replica string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + replica, Labels: map[string]string{EnginesLabel: "true"}}}
	}
	a, b := reportOf("a"), reportOf("b")
	// Raw Envoy's pod: while it exists, its engine is reconnecting.
	rawPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "raw-envoy", Name: "envoy-1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).WithObjects(p, a, b, rawPod).Build()
	now := time.Now()
	setReport := func(cm *corev1.ConfigMap, at time.Time, engines ...Engine) {
		t.Helper()
		data, _ := json.Marshal(engines)
		cm.Data = map[string]string{enginesKey: string(data), updatedAtKey: at.UTC().Format(time.RFC3339Nano)}
		if err := c.Update(ctx, cm); err != nil {
			t.Fatal(err)
		}
	}
	edit := func(version int64) {
		t.Helper()
		var got wafv1alpha1.WAFPolicy
		if err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
			t.Fatal(err)
		}
		got.Status.BundleVersion = version
		if err := c.Status().Update(ctx, &got); err != nil {
			t.Fatal(err)
		}
	}
	check := func(r *Reporter, what, want string) {
		t.Helper()
		if err := r.report(ctx); err != nil {
			t.Fatal(err)
		}
		var got wafv1alpha1.WAFPolicy
		if err := c.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
			t.Fatal(err)
		}
		if cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEnforced); cond == nil || cond.Reason != want {
			t.Errorf("%s: Enforced %v, want %s", what, cond, want)
		}
	}
	raw := func(applied uint64) Engine {
		return Engine{ID: "raw", PodNamespace: "raw-envoy", PodName: "envoy-1", Applied: applied}
	}
	other := func(applied uint64) Engine {
		return Engine{ID: "traefik", PodNamespace: "traefik", PodName: "traefik-1", Applied: applied}
	}
	clock := func() time.Time { return now }
	r := &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: 30 * time.Second, Gone: time.Minute, Store: NewStore(), Now: clock}

	setReport(a, now, raw(2), other(2))
	check(r, "every engine runs it", ReasonEnforced)
	setReport(a, now, other(2))
	check(r, "raw Envoy's engine reconnecting, with the policy's version", ReasonEnforced)
	edit(3)
	setReport(a, now, other(3))
	check(r, "edited while raw Envoy's engine reconnects", ReasonEnginesBehind)
	setReport(b, now, raw(3))
	check(r, "raw Envoy's engine reconnected, runs it", ReasonEnforced)

	// A new leader: raw Envoy's engine was on the old leader, whose report
	// is stale; it reconnects to another replica.
	edit(4)
	setReport(a, now, other(4))
	setReport(b, now.Add(-40*time.Second), raw(3))
	r = &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: 30 * time.Second, Gone: time.Minute, Store: NewStore(), Now: clock}
	check(r, "new leader, raw Envoy's engine reconnecting", ReasonEnginesBehind)
	// It never comes back (its pod was deleted): it counts for Gone only.
	now = now.Add(61 * time.Second)
	setReport(a, now, other(4))
	check(r, "raw Envoy's engine gone for good", ReasonEnforced)

	// An integration's pod (Traefik's) deleted: its engine doesn't hold
	// raw Envoy's policy back, though every engine counts for it.
	served := &ServedPods{}
	served.Set(map[string]map[string]ServedPod{"web/traefik": {"traefik/traefik-1": {Integration: "traefik", Engine: true}}})
	r = &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: 30 * time.Second, Gone: time.Minute, Store: NewStore(), Now: clock, Served: served}
	setReport(b, now, raw(4))
	check(r, "every engine runs it, Traefik's pod known", ReasonEnforced)
	served.Set(nil)
	edit(5)
	setReport(a, now)
	setReport(b, now, raw(5))
	check(r, "Traefik's pod deleted, then an edit", ReasonEnforced)

	// Raw Envoy's pod deleted (a rollout): its engine won't come back, and
	// doesn't hold an edit back for Gone.
	edit(6)
	setReport(a, now, other(6))
	setReport(b, now)
	check(r, "edited while raw Envoy's engine is away, its pod there", ReasonEnginesBehind)
	if err := c.Delete(ctx, rawPod); err != nil {
		t.Fatal(err)
	}
	check(r, "raw Envoy's pod deleted", ReasonEnforced)
}

// A policy whose pods are known isn't held back by an engine that
// disconnected: enginesFor counts its pods whose engine isn't connected, and
// a pod deleted since (a rollout) has no say (#675's fix, which a Traefik
// rollout in the e2e caught).
func TestGoneForKnownPods(t *testing.T) {
	served := &ServedPods{}
	served.Set(map[string]map[string]ServedPod{
		"web/traefik": {"traefik/new": {Integration: "traefik", Engine: true}},
	})
	v := served.view()
	old := Engine{ID: "old", PodNamespace: "traefik", PodName: "old", Applied: 1}
	if got := v.goneFor("web/traefik", []Engine{old}); len(got) != 0 {
		t.Errorf("known pods: gone %v, want none", got)
	}
	if got := v.goneFor("raw-envoy/app", []Engine{old}); len(got) != 1 {
		t.Errorf("unknown pods: gone %v, want the engine", got)
	}
}
