// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package policystatus turns the WAFPolicies' conditions into metrics and
// Kubernetes Events (#378): the inkwall_operator_policies gauge counts the
// policies by condition, status and reason, and a change of a policy's
// Ready, Programmed or Enforced condition records an Event on it, so
// `kubectl describe wafpolicy` and event-based tooling see it. It runs on
// the leader.
package policystatus

import (
	"cmp"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Events go in the policies' namespaces.
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// DefaultEvery is the least time between two Events on a policy.
const DefaultEvery = 30 * time.Second

// noteBytes bounds an Event's note (the API server refuses over 1 KiB).
const noteBytes = 1000

var policies = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "inkwall_operator_policies",
	Help: "WAFPolicies by condition (Accepted, Programmed, Enforced, Ready), status and reason. Reported by the leader.",
}, []string{"condition", "status", "reason"})

func init() { metrics.Registry.MustRegister(policies) }

// counted are the conditions the gauge counts; evented, those whose
// changes record an Event.
var (
	counted = []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced, wafv1alpha1.ConditionReady}
	evented = []string{wafv1alpha1.ConditionReady, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced}
)

// state is a condition's status and reason.
type state struct{ status, reason string }

type entry struct {
	// counted is what the gauge counts for the policy, by condition.
	counted map[string]state
	// evented is the state the last Event (or the first sight) recorded.
	evented   map[string]state
	lastEvent time.Time
}

// Watcher reconciles WAFPolicies into the gauge and Events.
type Watcher struct {
	Client   client.Client
	Recorder events.EventRecorder
	// Every is the least time between two Events on a policy: changes
	// within it are recorded together, once it has passed; 0: DefaultEvery.
	Every time.Duration
	// Now is the clock; nil: time.Now.
	Now func() time.Time

	mu       sync.Mutex
	policies map[types.NamespacedName]*entry
	counts   map[[3]string]int
}

// SetupWithManager registers the watcher.
func (w *Watcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).Named("policystatus").For(&wafv1alpha1.WAFPolicy{}).Complete(w)
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Reconcile updates the gauge with the policy's conditions, and records an
// Event when Ready, Programmed or Enforced changed since the last.
func (w *Watcher) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var p wafv1alpha1.WAFPolicy
	err := w.Client.Get(ctx, req.NamespacedName, &p)
	if apierrors.IsNotFound(err) {
		w.forget(req.NamespacedName)
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.policies == nil {
		w.policies, w.counts = map[types.NamespacedName]*entry{}, map[[3]string]int{}
	}
	cur := map[string]state{}
	for _, t := range counted {
		if c := meta.FindStatusCondition(p.Status.Conditions, t); c != nil {
			cur[t] = state{string(c.Status), c.Reason}
		}
	}
	e := w.policies[req.NamespacedName]
	if e == nil {
		// First sight (a new policy, or the operator starting): no Event.
		e = &entry{evented: cur}
		w.policies[req.NamespacedName] = e
	}
	w.count(e.counted, -1)
	e.counted = cur
	w.count(cur, 1)

	var changed []string
	for _, t := range evented {
		if cur[t] != e.evented[t] {
			changed = append(changed, t)
		}
	}
	if len(changed) == 0 {
		return reconcile.Result{}, nil
	}
	if wait := e.lastEvent.Add(cmp.Or(w.Every, DefaultEvery)).Sub(now); !e.lastEvent.IsZero() && wait > 0 {
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	w.record(&p, changed)
	e.evented, e.lastEvent = cur, now
	return reconcile.Result{}, nil
}

// record records one Event for the changed conditions: Warning while the
// policy isn't Ready; its reason is Ready's when that changed.
func (w *Watcher) record(p *wafv1alpha1.WAFPolicy, changed []string) {
	var notes []string
	reason := ""
	for _, t := range changed {
		c := meta.FindStatusCondition(p.Status.Conditions, t)
		if c == nil {
			notes = append(notes, t+" is not reported")
			continue
		}
		notes = append(notes, fmt.Sprintf("%s %s (%s): %s", t, c.Status, c.Reason, c.Message))
		if reason == "" {
			reason = c.Reason
		}
	}
	kind := corev1.EventTypeNormal
	if c := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionReady); c == nil || c.Status != metav1.ConditionTrue {
		kind = corev1.EventTypeWarning
	}
	note := strings.Join(notes, "; ")
	if len(note) > noteBytes {
		note = strings.ToValidUTF8(note[:noteBytes], "")
	}
	w.Recorder.Eventf(p, nil, kind, cmp.Or(reason, "ConditionsChanged"), "StatusChanged", "%s", note)
}

func (w *Watcher) count(st map[string]state, d int) {
	for t, s := range st {
		k := [3]string{t, s.status, s.reason}
		w.counts[k] += d
		if w.counts[k] <= 0 {
			delete(w.counts, k)
			policies.DeleteLabelValues(k[0], k[1], k[2])
			continue
		}
		policies.WithLabelValues(k[0], k[1], k[2]).Set(float64(w.counts[k]))
	}
}

func (w *Watcher) forget(key types.NamespacedName) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.policies[key]; e != nil {
		w.count(e.counted, -1)
		delete(w.policies, key)
	}
}
