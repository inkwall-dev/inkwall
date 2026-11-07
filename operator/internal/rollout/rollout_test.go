// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package rollout

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

const (
	operatorNS = "inkwall-system"
	newImage   = "ghcr.io/inkwall-dev/inkwall-engine:0.5.0"
	oldImage   = "ghcr.io/inkwall-dev/inkwall-engine:0.4.1"
)

func traefikPod(name, rs, image string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "traefik", Name: name, UID: types.UID(name), Labels: map[string]string{"app.kubernetes.io/name": "traefik"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs, UID: types.UID("rs-" + rs), Controller: ptrTrue()}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	if image != "" {
		p.Spec.InitContainers = []corev1.Container{{Name: injection.ContainerName, Image: image}}
	}
	return p
}

func ptrTrue() *bool { t := true; return &t }

type world struct {
	t       *testing.T
	c       client.Client
	r       *Rollout
	now     time.Time
	evicted []string
	refuse  error
}

func newWorld(t *testing.T, rollout wafv1alpha1.RolloutPolicy, pods ...*corev1.Pod) *world {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	cfg.Spec.Engine.Rollout = rollout
	bundleSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNS, Name: bundle.BundleSecret,
		Annotations: map[string]string{bundle.VersionAnnotation: "7"}}}
	objs := []client.Object{cfg, bundleSecret}
	for _, p := range pods {
		objs = append(objs, p)
	}
	w := &world{t: t, now: time.Unix(1_800_000_000, 0)}
	w.c = fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&wafv1alpha1.InkwallConfig{}).Build()
	w.r = &Rollout{
		Client: w.c, Reader: w.c, Namespace: operatorNS,
		Sidecar: injection.Sidecar{Image: newImage}, Pods: integrations.Defaults(),
		Integrations: []string{integrations.Traefik.Name},
		ReadyTimeout: 5 * time.Minute, EngineStale: time.Hour,
		Now: func() time.Time { return w.now },
		Evict: func(_ context.Context, p *corev1.Pod) error {
			if w.refuse != nil {
				return w.refuse
			}
			w.evicted = append(w.evicted, p.Name)
			return w.c.Delete(context.Background(), p)
		},
	}
	w.engines()
	return w
}

// engines writes an engine report: each pod with an engine runs bundle 7.
func (w *world) engines() {
	var list corev1.PodList
	if err := w.c.List(context.Background(), &list); err != nil {
		w.t.Fatal(err)
	}
	var es []distribution.Engine
	for _, p := range list.Items {
		if injection.HasEngine(&p) {
			es = append(es, distribution.Engine{ID: p.Name, PodNamespace: p.Namespace, PodName: p.Name, Applied: 7})
		}
	}
	data, _ := json.Marshal(es)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNS, Name: "inkwall-engines-a", Labels: map[string]string{distribution.EnginesLabel: "true"}},
		Data: map[string]string{enginereport.EnginesKey: string(data), enginereport.UpdatedAtKey: w.now.UTC().Format(time.RFC3339Nano)}}
	var old corev1.ConfigMap
	if err := w.c.Get(context.Background(), client.ObjectKeyFromObject(cm), &old); err == nil {
		cm.ResourceVersion = old.ResourceVersion
		if err := w.c.Update(context.Background(), cm); err != nil {
			w.t.Fatal(err)
		}
		return
	}
	if err := w.c.Create(context.Background(), cm); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) step() {
	w.t.Helper()
	if err := w.r.step(context.Background()); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) condition() *metav1.Condition {
	w.t.Helper()
	var cfg wafv1alpha1.InkwallConfig
	if err := w.c.Get(context.Background(), types.NamespacedName{Name: "default"}, &cfg); err != nil {
		w.t.Fatal(err)
	}
	return meta.FindStatusCondition(cfg.Status.Conditions, wafv1alpha1.ConditionEngineRollout)
}

// replace stands in for the ReplicaSet: a new pod for an evicted one, with
// the engine the webhook injects.
func (w *world) replace(name, rs, image string) {
	w.t.Helper()
	if err := w.c.Create(context.Background(), traefikPod(name, rs, image)); err != nil {
		w.t.Fatal(err)
	}
	w.engines()
}

// Manual: nothing is evicted, and there is no condition.
func TestManual(t *testing.T) {
	w := newWorld(t, "", traefikPod("a", "rs1", ""), traefikPod("b", "rs1", oldImage))
	w.step()
	if len(w.evicted) != 0 || w.condition() != nil {
		t.Errorf("Manual: evicted %v, condition %+v", w.evicted, w.condition())
	}
}

// Automatic: pods without the engine, or with another image, are evicted
// one at a time, each after the last one's replacement is ready and runs
// the current bundle; pods with the configured engine, opted out, or
// without a controller are left alone.
func TestAutomatic(t *testing.T) {
	optedOut := traefikPod("opted-out", "rs1", "")
	optedOut.Labels[injection.InjectAnnotation] = "false"
	bare := traefikPod("bare", "", "")
	bare.OwnerReferences = nil
	w := newWorld(t, wafv1alpha1.RolloutAutomatic,
		traefikPod("a", "rs1", ""), traefikPod("b", "rs1", oldImage), traefikPod("c", "rs1", newImage), optedOut, bare)

	w.step()
	if !slices.Equal(w.evicted, []string{"a"}) {
		t.Fatalf("evicted %v, want [a]", w.evicted)
	}
	if c := w.condition(); c == nil || c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "traefik/a") {
		t.Errorf("condition %+v, want True naming traefik/a", c)
	}
	// The replacement isn't there yet: nothing more.
	w.now = w.now.Add(10 * time.Second)
	w.step()
	if len(w.evicted) != 1 {
		t.Fatalf("evicted %v before the replacement is ready", w.evicted)
	}
	// Ready, but its engine doesn't run the bundle yet: still waiting.
	notYet := traefikPod("a2", "rs1", newImage)
	if err := w.c.Create(context.Background(), notYet); err != nil {
		t.Fatal(err)
	}
	w.step()
	if len(w.evicted) != 1 {
		t.Fatalf("evicted %v before the replacement's engine runs the bundle", w.evicted)
	}
	w.engines()
	w.step()
	if !slices.Equal(w.evicted, []string{"a", "b"}) {
		t.Fatalf("evicted %v, want [a b]; %+v", w.evicted, w.condition())
	}
	w.replace("b2", "rs1", newImage)
	w.step()
	if !slices.Equal(w.evicted, []string{"a", "b"}) {
		t.Errorf("evicted %v; c, opted-out and bare should stay", w.evicted)
	}
	if c := w.condition(); c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonDone {
		t.Errorf("condition %+v, want False Done", c)
	}
}

// A PodDisruptionBudget refusing the eviction pauses the rollout, and says
// so; it goes on once the eviction is allowed.
func TestEvictionRefused(t *testing.T) {
	w := newWorld(t, wafv1alpha1.RolloutAutomatic, traefikPod("a", "rs1", oldImage))
	w.refuse = apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 10)
	w.step()
	if c := w.condition(); c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonPaused || !strings.Contains(c.Message, "disruption budget") {
		t.Errorf("condition %+v, want False Paused naming the disruption budget", c)
	}
	w.refuse = nil
	w.now = w.now.Add(time.Minute)
	w.step()
	if !slices.Equal(w.evicted, []string{"a"}) {
		t.Errorf("evicted %v once allowed, want [a]", w.evicted)
	}
}

// A replacement not ready within ReadyTimeout pauses the rollout: no
// other pod is evicted.
func TestReplacementNotReady(t *testing.T) {
	w := newWorld(t, wafv1alpha1.RolloutAutomatic, traefikPod("a", "rs1", oldImage), traefikPod("b", "rs2", oldImage))
	w.step()
	stuck := traefikPod("a2", "rs1", "") // the webhook didn't inject it
	if err := w.c.Create(context.Background(), stuck); err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(6 * time.Minute)
	w.step()
	if len(w.evicted) != 1 {
		t.Fatalf("evicted %v with a replacement not ready", w.evicted)
	}
	if c := w.condition(); c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonPaused || !strings.Contains(c.Message, "traefik/a2") {
		t.Errorf("condition %+v, want False Paused naming traefik/a2", c)
	}
}
