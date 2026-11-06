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
			served.Set(map[string]map[string]string{
				"web/envoy-only":   {"envoy/a1": "envoy-gateway"},
				"web/haproxy-only": {"haproxy/b1": "haproxy"},
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
