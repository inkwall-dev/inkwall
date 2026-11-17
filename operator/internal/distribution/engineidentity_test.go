// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
)

// An engine with a pod-bound token has its pod's record: a Hello that gives
// the engine ID of another pod's engine adds a record, and each stream's
// Nack and Heartbeat update only its own.
func TestEngineRecordBoundToTokenPod(t *testing.T) {
	store, table := NewStore(), NewTable()
	store.Set(signed(1), 1)
	c := serve(t, NewServer(store, table, podAuth{}, "r", logr.Discard()))

	a, err := c.Watch(withToken(t.Context(), "traefik-a"))
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Send(hello(&agentv1.Hello{EngineId: "e-a"}))
	if _, err := a.Recv(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "engine a", func() bool { got, _ := table.Snapshot(); return len(got) == 1 })

	// Pod b's engine gives a's engine ID, and another pod.
	b, err := c.Watch(withToken(t.Context(), "traefik-b"))
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Send(hello(&agentv1.Hello{EngineId: "e-a", PodNamespace: "edge", PodName: "traefik-a", BundleVersion: 1}))
	waitFor(t, "engine b", func() bool { got, _ := table.Snapshot(); return len(got) == 2 })

	_ = a.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Nack{Nack: &agentv1.Nack{BundleVersion: 1, Error: "bad"}}})
	_ = b.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{BundleVersion: 1}}})
	waitFor(t, "the nack", func() bool {
		got, _ := table.Snapshot()
		for _, e := range got {
			if e.PodName == "traefik-a" {
				return e.Rejected == 1
			}
		}
		return false
	})
	got, _ := table.Snapshot()
	for _, e := range got {
		switch e.PodName {
		case "traefik-a":
			if e.Applied != 0 || e.Rejected != 1 {
				t.Errorf("pod a's record: %+v", e)
			}
		case "traefik-b":
			if e.Applied != 1 || e.Rejected != 0 {
				t.Errorf("pod b's record: %+v", e)
			}
		default:
			t.Errorf("record of pod %q: %+v", e.PodName, e)
		}
	}
	if st, reason, msg := Enforced(1, got, 0); st == "True" {
		t.Errorf("Enforced %s %s %s with a rejecting engine", st, reason, msg)
	}
}

// A stream replaced by a newer one of the same pod no longer updates the
// record.
func TestEngineRecordOldStream(t *testing.T) {
	tab := NewTable()
	key := Key(Identity{ServiceAccount: "edge/traefik", PodNamespace: "edge", PodName: "p"}, "e1")
	old := tab.Connect(key, Engine{ID: "e1"})
	tab.Connect(key, Engine{ID: "e2"})
	tab.Update(key, old, func(e *Engine) bool { return set(&e.Rejected, 1) })
	if got, _ := tab.Snapshot(); len(got) != 1 || got[0].ID != "e2" || got[0].Rejected != 0 {
		t.Fatalf("the old stream changed the new record: %+v", got)
	}
	if Key(Identity{ServiceAccount: "a/x"}, "e1") == Key(Identity{ServiceAccount: "b/y"}, "e1") {
		t.Error("engines of two ServiceAccounts share a record")
	}
}

// Merging the replicas' reports keeps two engines of different pods that
// give the same engine ID.
func TestReadEnginesSameIDTwoPods(t *testing.T) {
	now := time.Now()
	report := func(replica string, e Engine) *corev1.ConfigMap {
		data, _ := json.Marshal([]Engine{e})
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + replica, Labels: map[string]string{EnginesLabel: "true"}},
			Data:       map[string]string{enginesKey: string(data), updatedAtKey: now.Format(time.RFC3339Nano)},
		}
	}
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		report("a", Engine{ID: "e1", ServiceAccount: "edge/traefik", PodNamespace: "edge", PodName: "v", Rejected: 1, ConnectedAt: now.Add(-time.Minute)}),
		report("b", Engine{ID: "e1", ServiceAccount: "edge/traefik", PodNamespace: "edge", PodName: "x", Applied: 1, ConnectedAt: now}),
	).Build()
	got, _, err := ReadEngines(context.Background(), c, "inkwall-system", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("engines %+v", got)
	}
}
