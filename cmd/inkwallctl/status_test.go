// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
)

// statusCluster is a healthy cluster: Traefik and an Ingress class nobody
// wires, two Ready policies, two operator replicas of 0.5.0, bundle 7,
// and two engines of v0.5.0 running it, reported by two replicas (one
// engine moving between them), plus a stale report of a gone replica.
type statusCluster struct {
	config   *wafv1alpha1.InkwallConfig
	policies []*wafv1alpha1.WAFPolicy
	engines  map[string][]enginereport.Engine // replica -> its report
	stale    []enginereport.Engine
}

var statusNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func healthyCluster() *statusCluster {
	ready := func(ns, name string) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 2}}
		p.Status.Conditions = []metav1.Condition{{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: 2}}
		return p
	}
	engine := func(id, pod, replica string, applied uint64, at time.Duration) enginereport.Engine {
		return enginereport.Engine{ID: id, PodNamespace: "traefik", PodName: pod, EngineVersion: "v0.5.0", Applied: applied,
			Replica: replica, ConnectedAt: statusNow.Add(-at)}
	}
	return &statusCluster{
		config: &wafv1alpha1.InkwallConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       wafv1alpha1.InkwallConfigSpec{Mode: wafv1alpha1.ModeStandalone},
			Status: wafv1alpha1.InkwallConfigStatus{Proxies: []wafv1alpha1.ProxyStatus{
				{ControllerName: "traefik.io/ingress-controller", Integration: "traefik", IngressClasses: []string{"traefik"}, Support: wafv1alpha1.SupportFull},
				{ControllerName: "k8s.io/ingress-nginx", IngressClasses: []string{"nginx"}, Support: wafv1alpha1.SupportUnsupported, Message: "Inkwall has no integration for this controller"},
			}},
		},
		policies: []*wafv1alpha1.WAFPolicy{ready("shop", "web"), ready("shop", "api")},
		engines: map[string][]enginereport.Engine{
			"inkwall-operator-a": {engine("traefik-1", "traefik-1", "inkwall-operator-a", 7, time.Hour), engine("traefik-2", "traefik-2", "inkwall-operator-a", 6, 2*time.Hour)},
			// traefik-2 reconnected here since, and runs 7.
			"inkwall-operator-b": {engine("traefik-2", "traefik-2", "inkwall-operator-b", 7, time.Minute)},
		},
		stale: []enginereport.Engine{engine("gone", "gone", "inkwall-operator-old", 1, 3*time.Hour)},
	}
}

func (sc *statusCluster) client(t *testing.T) client.Reader {
	t.Helper()
	objs := []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: bundle.BundleSecret,
			Annotations: map[string]string{bundle.VersionAnnotation: "7"}}, Data: map[string][]byte{bundle.BundleKey: make([]byte, 4096)}},
	}
	for _, name := range []string{"inkwall-operator-a", "inkwall-operator-b"} {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: name,
				Labels: map[string]string{"app.kubernetes.io/component": "operator", "app.kubernetes.io/part-of": "inkwall"}},
			Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "operator", Image: "ghcr.io/inkwall-dev/inkwall-operator:0.5.0"}}},
			Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		})
	}
	report := func(replica string, engines []enginereport.Engine, updated time.Time) *corev1.ConfigMap {
		raw, err := json.Marshal(engines)
		if err != nil {
			t.Fatal(err)
		}
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: enginereport.NamePrefix + replica, Labels: map[string]string{enginereport.Label: "true"}},
			Data: map[string]string{enginereport.EnginesKey: string(raw), enginereport.UpdatedAtKey: updated.Format(time.RFC3339Nano),
				enginereport.LeftOutKey: "0"},
		}
	}
	for replica, engines := range sc.engines {
		objs = append(objs, report(replica, engines, statusNow.Add(-2*time.Second)))
	}
	objs = append(objs, report("inkwall-operator-old", sc.stale, statusNow.Add(-time.Hour)))
	if sc.config != nil {
		objs = append(objs, sc.config)
	}
	for _, p := range sc.policies {
		objs = append(objs, p)
	}
	return fake.NewClientBuilder().WithScheme(statusScheme()).WithObjects(objs...).Build()
}

func (sc *statusCluster) status(t *testing.T) *Status {
	t.Helper()
	st, err := clusterStatus(t.Context(), sc.client(t), "inkwall-system", 30*time.Second, statusNow)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The healthy cluster's report, as -o json prints it: the documented shape
// (docs/troubleshooting.md), kept in testdata/status/healthy.json.
func TestStatusHealthy(t *testing.T) {
	st := healthyCluster().status(t)
	if !st.Healthy || len(st.Problems) != 0 || len(st.Warnings) != 0 {
		t.Fatalf("not healthy: %q %q", st.Problems, st.Warnings)
	}
	got, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "status/healthy.json", string(got)+"\n")

	var text strings.Builder
	printStatus(&text, st)
	golden(t, "status/healthy.txt", text.String())
}

// A policy that isn't Ready is listed under its reason, with its message;
// one the operator hasn't reported on (an older generation) is Unknown.
func TestStatusPolicyNotReady(t *testing.T) {
	sc := healthyCluster()
	sc.policies[0].Status.Conditions[0] = metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: "WiringFailed", Message: "can't patch Ingress shop/web", ObservedGeneration: 2}
	sc.policies[1].Generation = 3
	st := sc.status(t)
	if st.Healthy || st.Policies.Ready != 0 || len(st.Policies.NotReady) != 2 {
		t.Fatalf("policies %+v, healthy %t", st.Policies, st.Healthy)
	}
	if g := st.Policies.NotReady[1]; g.Reason != "WiringFailed" || g.Policies[0].Name != "web" || g.Policies[0].Message != "can't patch Ingress shop/web" {
		t.Errorf("WiringFailed group %+v", g)
	}
	if g := st.Policies.NotReady[0]; g.Reason != "Unknown" || g.Policies[0].Name != "api" {
		t.Errorf("Unknown group %+v", g)
	}
}

// An engine behind, one that rejected the bundle, and one of another
// version are named, with what to do.
func TestStatusEngines(t *testing.T) {
	sc := healthyCluster()
	sc.engines["inkwall-operator-a"][0].Applied = 6
	sc.engines["inkwall-operator-b"] = append(sc.engines["inkwall-operator-b"],
		enginereport.Engine{ID: "eg-1", PodNamespace: "envoy-gateway-system", PodName: "envoy-1", EngineVersion: "v0.5.0", Applied: 6,
			Rejected: 7, RejectError: "rule set crs: unknown directive", Replica: "inkwall-operator-b", ConnectedAt: statusNow},
		enginereport.Engine{ID: "ha-1", PodNamespace: "haproxy-controller", PodName: "haproxy-1", EngineVersion: "v0.4.1", Applied: 7,
			Replica: "inkwall-operator-b", ConnectedAt: statusNow},
	)
	st := sc.status(t)
	if st.Healthy || st.Engines.Total != 4 {
		t.Fatalf("engines %+v, healthy %t", st.Engines, st.Healthy)
	}
	want := map[string]EngineVersionGroup{
		"v0.5.0": {Version: "v0.5.0", Current: 1, Behind: 1, Rejected: 1},
		"v0.4.1": {Version: "v0.4.1", Current: 1},
	}
	for _, g := range st.Engines.ByVersion {
		if g != want[g.Version] {
			t.Errorf("version %s: %+v, want %+v", g.Version, g, want[g.Version])
		}
	}
	states := map[string]EngineRef{}
	for _, e := range st.Engines.Attention {
		states[e.Pod] = e
	}
	if e := states["traefik-1"]; e.State != engineBehind {
		t.Errorf("traefik-1: %+v", e)
	}
	if e := states["envoy-1"]; e.State != engineRejected || e.RejectError == "" {
		t.Errorf("envoy-1: %+v", e)
	}
	if e := states["haproxy-1"]; !e.Outdated || !strings.Contains(e.Hint, "kubectl -n haproxy-controller delete pod haproxy-1") {
		t.Errorf("haproxy-1: %+v", e)
	}
	if _, ok := states["traefik-2"]; ok || len(states) != 3 {
		t.Errorf("attention: %+v", st.Engines.Attention)
	}
}

// Suspended inspection needs attention, and so does a cluster with
// policies and no engine.
func TestStatusSuspended(t *testing.T) {
	sc := healthyCluster()
	sc.config.Spec.Suspend = true
	st := sc.status(t)
	if st.Healthy || !st.Config.Suspended || !strings.Contains(strings.Join(st.Problems, "\n"), "suspended") {
		t.Fatalf("suspended: %+v", st)
	}

	sc = healthyCluster()
	sc.engines = nil
	sc.config = nil
	st = sc.status(t)
	if st.Healthy || st.Config.Exists || st.Config.Mode != "Standalone" ||
		!strings.Contains(strings.Join(st.Problems, "\n"), "no engine is connected") {
		t.Fatalf("no engines: %+v", st)
	}
}

// The command: exit 0 when healthy, 1 when not, 2 on a usage error.
func TestRunStatus(t *testing.T) {
	sc := healthyCluster()
	defer func(f func(string, string) (client.Reader, error), clock func() time.Time) {
		newStatusClient, statusClock = f, clock
	}(newStatusClient, statusClock)
	newStatusClient = func(string, string) (client.Reader, error) { return sc.client(t), nil }
	statusClock = func() time.Time { return statusNow }

	if code, out, errOut := runCLI(t, "status"); code != 0 || !strings.Contains(out, "OK: nothing needs attention.") {
		t.Fatalf("status: exit %d\n%s\n%s", code, out, errOut)
	}
	sc.config.Spec.Suspend = true
	code, out, _ := runCLI(t, "status", "-o", "json")
	var st Status
	if err := json.Unmarshal([]byte(out), &st); err != nil || code != 1 || st.Healthy || !st.Config.Suspended {
		t.Fatalf("suspended, -o json: exit %d, %v\n%s", code, err, out)
	}
	if code, _, _ := runCLI(t, "status", "-o", "yaml"); code != 2 {
		t.Errorf("-o yaml: exit %d, want 2", code)
	}
	if code, _, _ := runCLI(t, "status", "extra"); code != 2 {
		t.Errorf("extra argument: exit %d, want 2", code)
	}
}
