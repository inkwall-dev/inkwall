// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// stateEnv is a connected cluster with a policy, two Traefik pods (one
// with the engine), an engine report and a bundle.
func stateEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.conn.StatePoll = 50 * time.Millisecond
	ctx := context.Background()

	policy := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "checkout", Generation: 3, Labels: map[string]string{"team": "payments"}},
		Spec:       wafv1alpha1.WAFPolicySpec{Mode: wafv1alpha1.PolicyBlock},
	}
	traefik := map[string]string{"app.kubernetes.io/name": "traefik"}
	withEngine := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-a", Labels: traefik},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik"}, {Name: injection.ContainerName}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	without := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-b", Labels: traefik},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: "traefik-c", Labels: traefik},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	engines, _ := json.Marshal([]distribution.Engine{{
		ID: "engine-a", PodNamespace: "traefik", PodName: "traefik-a", NodeName: "node-1", EngineVersion: "0.2.0", Applied: 7, Replica: "op-0",
	}})
	report := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "inkwall-engines-op-0", Labels: map[string]string{distribution.EnginesLabel: "true"}},
		Data:       map[string]string{"engines.json": string(engines), "updatedAt": time.Now().UTC().Format(time.RFC3339Nano)},
	}
	for _, o := range []client.Object{policy, withEngine, without, pending, report} {
		if err := e.client.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer := bundle.NewSigner(key)
	b := &bundlev1.Bundle{Version: 7, ContentHash: []byte("hash-7")}
	signed, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Store(ctx, e.client, e.client, ns, b, signed, signer.Public()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) states() []*controlplanev1.ClusterState { return e.cp.Stats().States }

func (e *env) waitStates(t *testing.T, n int) []*controlplanev1.ClusterState {
	t.Helper()
	waitFor(t, "ClusterState", func() bool { return len(e.states()) >= n })
	return e.states()
}

func TestClusterStateAfterWelcome(t *testing.T) {
	e := stateEnv(t)
	e.run(t)
	st := e.waitStates(t, 1)[0]

	if st.GetTime() == nil {
		t.Error("no time")
	}
	var kinds []string
	var policy *controlplanev1.Object
	for _, o := range st.GetObjects() {
		kinds = append(kinds, o.GetKind()+" "+o.GetNamespace()+"/"+o.GetName())
		if o.GetKind() == "WAFPolicy" {
			policy = o
		}
	}
	if want := []string{"InkwallConfig /default", "WAFPolicy shop/checkout"}; !slices.Equal(kinds, want) {
		t.Fatalf("objects = %v, want %v", kinds, want)
	}
	if policy.GetApiVersion() != "waf.inkwall.dev/v1alpha1" || policy.GetGeneration() != 3 || policy.GetLabels()["team"] != "payments" {
		t.Errorf("policy = %v", policy)
	}
	var spec wafv1alpha1.WAFPolicySpec
	if err := json.Unmarshal(policy.GetSpec(), &spec); err != nil || spec.Mode != wafv1alpha1.PolicyBlock {
		t.Errorf("policy spec = %s (%v)", policy.GetSpec(), err)
	}

	in := st.GetIntegrations()
	if len(in) != 1 || in[0].GetName() != "traefik" || in[0].GetController() != "traefik.io/ingress-controller" ||
		in[0].GetPods() != 2 || in[0].GetPodsWithEngine() != 1 {
		t.Errorf("integrations = %v, want traefik with 2 running pods, 1 with the engine", in)
	}
	en := st.GetEngines()
	if len(en) != 1 || en[0].GetEngineId() != "engine-a" || en[0].GetPodName() != "traefik-a" || en[0].GetAppliedBundleVersion() != 7 {
		t.Errorf("engines = %v", en)
	}
	if st.GetBundleVersion() != 7 || string(st.GetBundleContentHash()) != "hash-7" {
		t.Errorf("bundle = %d %q", st.GetBundleVersion(), st.GetBundleContentHash())
	}
}

func TestClusterStateOnChangeOnly(t *testing.T) {
	e := stateEnv(t)
	e.run(t)
	e.waitStates(t, 1)

	// Unchanged: nothing more, though the leader looks every 50 ms.
	time.Sleep(300 * time.Millisecond)
	if n := len(e.states()); n != 1 {
		t.Fatalf("%d states sent for an unchanged cluster, want 1", n)
	}

	var p wafv1alpha1.WAFPolicy
	ctx := context.Background()
	if err := e.client.Get(ctx, types.NamespacedName{Namespace: "shop", Name: "checkout"}, &p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Mode = wafv1alpha1.PolicyDetect
	if err := e.client.Update(ctx, &p); err != nil {
		t.Fatal(err)
	}
	st := e.waitStates(t, 2)[1]
	for _, o := range st.GetObjects() {
		if o.GetKind() == "WAFPolicy" {
			var spec wafv1alpha1.WAFPolicySpec
			_ = json.Unmarshal(o.GetSpec(), &spec)
			if spec.Mode != wafv1alpha1.PolicyDetect {
				t.Errorf("the new state has mode %q, want Detect", spec.Mode)
			}
		}
	}
}

func TestClusterStateResync(t *testing.T) {
	e := stateEnv(t)
	e.run(t)
	e.waitStates(t, 1)
	open, err := e.cp.Resync()
	if err != nil || !open {
		t.Fatalf("Resync: open=%v, %v", open, err)
	}
	// A full state again, though nothing changed.
	e.waitStates(t, 2)
}

func TestClusterStateResentPeriodically(t *testing.T) {
	e := stateEnv(t)
	e.conn.StateResend = 200 * time.Millisecond
	e.run(t)
	e.waitStates(t, 3)
}

func TestClusterStateWithoutBundle(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.run(t)
	st := e.waitStates(t, 1)[0]
	if st.GetBundleVersion() != 0 || len(st.GetEngines()) != 0 || st.GetIntegrations()[0].GetPods() != 0 {
		t.Errorf("state = %v, want no bundle, engines or pods", st)
	}
}

// However many engines report, the state stays within the limit: the
// engines that don't fit are left out, and counted.
func TestAddEnginesWithinLimit(t *testing.T) {
	st := &controlplanev1.ClusterState{BundleVersion: 7}
	engines := make([]distribution.Engine, 100)
	for i := range engines {
		engines[i] = distribution.Engine{ID: fmt.Sprintf("engine-%03d", i), PodNamespace: "traefik", RejectError: strings.Repeat("r", 100)}
	}
	const limit = 4 << 10
	left := addEngines(st, engines, limit)
	if size := proto.Size(st); size > limit || left == 0 || len(st.GetEngines())+left != len(engines) {
		t.Fatalf("%d bytes, %d engines, %d left out", size, len(st.GetEngines()), left)
	}
	if st.GetEngines()[0].GetEngineId() != "engine-000" {
		t.Errorf("first engine %s, want engine-000", st.GetEngines()[0].GetEngineId())
	}
	st.Engines = nil
	if left := addEngines(st, engines, maxState); left != 0 || len(st.GetEngines()) != len(engines) {
		t.Fatalf("%d engines, %d left out, want all", len(st.GetEngines()), left)
	}
}
