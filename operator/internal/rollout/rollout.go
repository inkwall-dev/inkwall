// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package rollout replaces proxy pods that need a new engine, when the
// InkwallConfig asks for it (spec.engine.rollout: Automatic, #376): pods
// the Pod webhook would inject that run without the engine (started before
// Inkwall) or with an injected engine of another image than the one
// configured (an engine in the pod's own spec is the user's). It evicts
// them one at a time through the Eviction API, which respects
// PodDisruptionBudgets, and evicts the next only once the last one's
// workload has all its pods ready, each with the configured engine running
// the current bundle. It runs on the leader.
package rollout

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// Evicting a proxy's pods is granted with its integration's role, so the
// chart leaves it out with the integration.
// +kubebuilder:rbac:groups="",resources=pods/eviction,verbs=create,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups="",resources=pods/eviction,verbs=create,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups="",resources=pods/eviction,verbs=create,roleName=inkwall-operator-istio-ingress

// Reasons of the InkwallConfig's EngineRollout condition.
const (
	// ReasonRollingOut: a pod was evicted; its replacement is awaited.
	ReasonRollingOut = "RollingOut"
	// ReasonDone: no proxy pod needs a new engine.
	ReasonDone = "Done"
	// ReasonPaused: an eviction was refused, or a replacement isn't ready
	// in time; the message says which.
	ReasonPaused = "Paused"
)

// Defaults.
const (
	DefaultInterval     = 10 * time.Second
	DefaultReadyTimeout = 5 * time.Minute
)

// flight is the pod last evicted.
type flight struct {
	pod   types.NamespacedName
	uid   types.UID
	owner types.UID
	at    time.Time
	// before are the workload's other pods at the eviction: the others
	// are its replacements.
	before map[types.UID]bool
}

// Rollout evicts proxy pods that need a new engine.
type Rollout struct {
	// Client reads the InkwallConfig and the proxy pods (cached) and
	// writes the InkwallConfig's status.
	Client client.Client
	// Reader reads the engine reports and the bundle Secret, uncached.
	Reader    client.Reader
	Namespace string
	// Sidecar is the engine as injected; the InkwallConfig's
	// spec.engine.image overrides its image.
	Sidecar injection.Sidecar
	// Pods select the proxy pods; Integrations are those whose pods the
	// Pod webhook injects (the others roll their pods themselves), and
	// Disabled those the operator may not wire.
	Pods         *integrations.Selectors
	Integrations []string
	Disabled     map[string]string
	// Evict evicts a pod; nil: the Eviction API through Client.
	Evict func(context.Context, *corev1.Pod) error
	// Interval between steps, ReadyTimeout for a replacement, EngineStale
	// for the engine reports; 0: the defaults.
	Interval, ReadyTimeout, EngineStale time.Duration
	// Now is the clock; nil: time.Now.
	Now func() time.Time

	last *flight
}

// Start implements manager.Runnable.
func (r *Rollout) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("rollout")
	tick := time.NewTicker(cmp.Or(r.Interval, DefaultInterval))
	defer tick.Stop()
	for {
		if err := r.step(ctx); err != nil && ctx.Err() == nil {
			logger.Error(err, "engine rollout")
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// NeedLeaderElection implements LeaderElectionRunnable.
func (*Rollout) NeedLeaderElection() bool { return true }

func (r *Rollout) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// step takes the rollout's next step.
func (r *Rollout) step(ctx context.Context) error {
	var cfg wafv1alpha1.InkwallConfig
	if err := r.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		return client.IgnoreNotFound(err)
	}
	if cfg.Spec.Engine.Rollout != wafv1alpha1.RolloutAutomatic {
		r.last = nil
		return r.report(ctx, nil)
	}
	image := r.Sidecar.Configured(cfg.Spec.Engine).Image
	var list corev1.PodList
	if err := r.Client.List(ctx, &list); err != nil {
		return err
	}
	pods := slices.DeleteFunc(list.Items, func(p corev1.Pod) bool { return !r.ours(&p) })

	if r.last != nil {
		waiting, err := r.waiting(ctx, pods, image)
		if err != nil {
			return err
		}
		if waiting != "" {
			if r.now().Sub(r.last.at) > cmp.Or(r.ReadyTimeout, DefaultReadyTimeout) {
				return r.report(ctx, &metav1.Condition{Status: metav1.ConditionFalse, Reason: ReasonPaused, Message: fmt.Sprintf(
					"paused: the replacement of %s isn't ready after %s: %s; no other pod is evicted until it is", r.last.pod, cmp.Or(r.ReadyTimeout, DefaultReadyTimeout), waiting)})
			}
			return r.report(ctx, &metav1.Condition{Status: metav1.ConditionTrue, Reason: ReasonRollingOut,
				Message: fmt.Sprintf("evicted %s for engine %s; waiting: %s", r.last.pod, image, waiting)})
		}
		r.last = nil
	}

	var next *corev1.Pod
	for i := range pods {
		if needsEngine(&pods[i], image) {
			next = &pods[i]
			break
		}
	}
	if next == nil {
		return r.report(ctx, &metav1.Condition{Status: metav1.ConditionFalse, Reason: ReasonDone,
			Message: "every proxy pod the operator injects runs engine " + image})
	}
	evict := r.Evict
	if evict == nil {
		evict = r.evict
	}
	key := client.ObjectKeyFromObject(next)
	if err := evict(ctx, next); err != nil {
		if apierrors.IsTooManyRequests(err) || apierrors.IsForbidden(err) {
			return r.report(ctx, &metav1.Condition{Status: metav1.ConditionFalse, Reason: ReasonPaused,
				Message: fmt.Sprintf("paused: evicting %s was refused: %v", key, err)})
		}
		return fmt.Errorf("evict %s: %w", key, err)
	}
	log.FromContext(ctx).Info("evicted a proxy pod for a new engine", "pod", key.String(), "image", image)
	owner := metav1.GetControllerOf(next).UID
	before := map[types.UID]bool{}
	for _, p := range pods {
		if c := metav1.GetControllerOf(&p); c != nil && c.UID == owner {
			before[p.UID] = true
		}
	}
	r.last = &flight{pod: key, uid: next.UID, owner: owner, at: r.now(), before: before}
	return r.report(ctx, &metav1.Condition{Status: metav1.ConditionTrue, Reason: ReasonRollingOut,
		Message: fmt.Sprintf("evicted %s for engine %s; waiting for its replacement", key, image)})
}

// ours reports whether the rollout may replace p: a running pod of an
// enabled integration the Pod webhook injects, with a controller to
// replace it, not opted out of injection.
func (r *Rollout) ours(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || metav1.GetControllerOf(p) == nil || injection.OptedOut(p) {
		return false
	}
	for _, name := range r.Integrations {
		if r.Disabled[name] == "" && r.Pods.Selector(name).Matches(labels.Set(p.Labels)) {
			return true
		}
	}
	return false
}

// needsEngine reports whether a running pod lacks the engine image: it has
// no engine, or one the webhook injected with another image. An engine in
// the pod's own spec, not injected, is left alone: the webhook doesn't
// touch a pod that has one, so its replacement would run the same image
// and the rollout would wait for it forever.
func needsEngine(p *corev1.Pod, image string) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	img, ok := engineImage(p)
	if !ok {
		return true
	}
	return p.Annotations[injection.InjectedAnnotation] == "true" && img != image
}

func engineImage(p *corev1.Pod) (string, bool) {
	for _, c := range slices.Concat(p.Spec.InitContainers, p.Spec.Containers) {
		if c.Name == injection.ContainerName {
			return c.Image, true
		}
	}
	return "", false
}

// waiting says what the last eviction's workload still waits for: the
// evicted pod gone, a replacement, every pod of the workload ready, and
// each replacement with the engine image running the current bundle; ""
// when nothing.
func (r *Rollout) waiting(ctx context.Context, pods []corev1.Pod, image string) (string, error) {
	var siblings []corev1.Pod
	for _, p := range pods {
		if p.UID == r.last.uid {
			return r.last.pod.String() + " is still running", nil
		}
		if c := metav1.GetControllerOf(&p); c != nil && c.UID == r.last.owner {
			siblings = append(siblings, p)
		}
	}
	if !slices.ContainsFunc(siblings, func(p corev1.Pod) bool { return !r.last.before[p.UID] }) {
		return "no replacement pod yet", nil
	}
	version, err := r.bundleVersion(ctx)
	if err != nil {
		return "", err
	}
	engines, _, err := distribution.ReadEngines(ctx, r.Reader, r.Namespace, cmp.Or(r.EngineStale, 30*time.Second), r.now())
	if err != nil {
		return "", err
	}
	applied := map[types.NamespacedName]uint64{}
	for _, e := range engines {
		k := types.NamespacedName{Namespace: e.PodNamespace, Name: e.PodName}
		applied[k] = max(applied[k], e.Applied)
	}
	var why []string
	for _, p := range siblings {
		key := client.ObjectKeyFromObject(&p)
		img, ok := engineImage(&p)
		switch {
		case !ready(&p):
			why = append(why, key.String()+" is not ready")
		case r.last.before[p.UID]:
			// Not a replacement: its turn comes.
		case !ok:
			why = append(why, key.String()+" has no engine (is the injection webhook answering?)")
		case img != image:
			why = append(why, fmt.Sprintf("%s runs engine %s", key, img))
		case applied[key] < version:
			why = append(why, fmt.Sprintf("%s's engine doesn't run bundle %d yet", key, version))
		}
	}
	return strings.Join(why, "; "), nil
}

func ready(p *corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// bundleVersion is the version of the bundle published.
func (r *Rollout) bundleVersion(ctx context.Context) (uint64, error) {
	var s corev1.Secret
	err := r.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: bundle.BundleSecret}, &s)
	if apierrors.IsNotFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, _ := strconv.ParseUint(s.Annotations[bundle.VersionAnnotation], 10, 64)
	return v, nil
}

// evict evicts p through the Eviction API.
func (r *Rollout) evict(ctx context.Context, p *corev1.Pod) error {
	return r.Client.SubResource("eviction").Create(ctx, p, &policyv1.Eviction{
		ObjectMeta:    metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name},
		DeleteOptions: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &p.UID}},
	})
}

// report sets the EngineRollout condition (nil: removes it), on change.
func (r *Rollout) report(ctx context.Context, c *metav1.Condition) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cfg wafv1alpha1.InkwallConfig
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
			return client.IgnoreNotFound(err)
		}
		var changed bool
		if c == nil {
			changed = meta.RemoveStatusCondition(&cfg.Status.Conditions, wafv1alpha1.ConditionEngineRollout)
		} else {
			c.Type, c.ObservedGeneration = wafv1alpha1.ConditionEngineRollout, cfg.Generation
			changed = meta.SetStatusCondition(&cfg.Status.Conditions, *c)
		}
		if !changed {
			return nil
		}
		return r.Client.Status().Update(ctx, &cfg)
	})
}
