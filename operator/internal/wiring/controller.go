// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The wiring controller holds each WAFPolicy with a finalizer, has every
// integration wire its proxy's protected routes, releases a deleted policy
// once its routes are unwired, and reports Programmed.
//
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies,verbs=get;list;watch;update;patch

// Reasons of the Programmed condition.
const (
	ReasonProgrammed            = "Programmed"
	ReasonControllerUnsupported = "ControllerUnsupported"
	ReasonWiringFailed          = "WiringFailed"
	ReasonPendingRestart        = "PendingRestart"
	ReasonSidecarMissing        = "SidecarMissing"
	ReasonNoTargets             = "NoTargets"
	ReasonInjectionDisabled     = "InjectionDisabled"
	// ReasonUnwired: `inkwall-operator unwire` (helm uninstall) unwired
	// the routes and stopped the operator.
	ReasonUnwired = "Unwired"
)

// Finalizer holds a WAFPolicy until the operator has unwired its routes, so
// a policy deleted while the operator is down is unwired once it is back.
// Only the wiring controller adds it; it and `inkwall-operator unwire`
// remove it.
const Finalizer = "waf.inkwall.dev/unwire"

const (
	debounce = time.Second
	// resync also notices a proxy's CRDs being installed later.
	resync = time.Minute
)

var clusterRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "wiring"}}

// Reconciler wires protected routes. It runs on the leader.
type Reconciler struct {
	Client client.Client
	// PodWebhook is the MutatingWebhookConfiguration that injects the
	// engine: a proxy pod created after it without the engine was missed
	// by the webhook (SidecarMissing), one created before it predates
	// Inkwall (PendingRestart).
	PodWebhook string
	// Integrations wire the proxies (Integrations).
	Integrations []Integration
	// Disabled: the engine isn't injected (--inject=false), so new proxy
	// pods won't have it. Every route the operator wired is unwired, and
	// the policies are released from the finalizer.
	Disabled bool
}

// policyChanged: a WAFPolicy's spec, its deletion or its finalizers.
var policyChanged = predicate.Or[client.Object](predicate.GenerationChangedPredicate{}, predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		return !slices.Equal(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers()) ||
			!e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp())
	},
})

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueue := handler.Funcs{
		CreateFunc: func(_ context.Context, _ event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		UpdateFunc: func(_ context.Context, _ event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		DeleteFunc: func(_ context.Context, _ event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		GenericFunc: func(_ context.Context, _ event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.Add(clusterRequest)
		},
	}
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &corev1.Pod{}}
	c, err := ctrl.NewControllerManagedBy(mgr).
		Named("wiring").
		Watches(&wafv1alpha1.WAFPolicy{}, enqueue, builder.WithPredicates(policyChanged)).
		WatchesRawSource(source.Channel(start, enqueue)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Build(r)
	if err != nil {
		return err
	}
	for _, in := range r.Integrations {
		if err := in.Watch(c, mgr.GetCache(), enqueue); err != nil {
			return fmt.Errorf("%s: %w", in.Name(), err)
		}
	}
	return nil
}

// report is what the integrations found, for Programmed.
type report struct {
	// disabled: the engine isn't injected, nothing is wired.
	disabled bool
	// kinds are the target kinds the integrations wire.
	kinds []schema.GroupKind
	// results are the integrations', in order.
	results        []*Result
	injectingSince time.Time
}

// Reconcile has every integration wire the protected routes of its proxy
// and unwire the rest, releases the deleted policies once their routes are
// unwired, and reports Programmed.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	var policies wafv1alpha1.WAFPolicyList
	if err := r.Client.List(ctx, &policies); err != nil {
		return reconcile.Result{}, err
	}

	// A policy is held by the finalizer before its routes are wired; one
	// being deleted isn't wired. One that couldn't be held yet (say, the
	// webhook isn't answering yet) is wired anyway, and retried: unwiring
	// it would drop its protection.
	var errs error
	targets := map[Target]bool{}
	for i := range policies.Items {
		p := &policies.Items[i]
		if r.Disabled || p.DeletionTimestamp != nil {
			continue
		}
		switch err := setFinalizer(ctx, r.Client, p, true); {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			errs = errors.Join(errs, fmt.Errorf("add the finalizer to WAFPolicy %s/%s: %w", p.Namespace, p.Name, err))
		}
		// A policy that isn't accepted yet is wired too: until its rules
		// are in a bundle, the engine lets its routes through (no-policy).
		for _, ref := range p.Spec.TargetRefs {
			targets[targetOf(p.Namespace, ref)] = true
		}
	}

	rep := &report{disabled: r.Disabled, injectingSince: r.injectingSince(ctx)}
	for _, in := range r.Integrations {
		kinds := in.Kinds()
		mine := map[Target]bool{}
		for t := range targets {
			if slices.Contains(kinds, t.Kind) {
				mine[t] = true
			}
		}
		res, err := in.Wire(ctx, mine, r.Disabled)
		if res == nil {
			return reconcile.Result{}, errors.Join(errs, err)
		}
		errs = errors.Join(errs, err)
		record(in.Name(), res)
		rep.kinds = append(rep.kinds, kinds...)
		rep.results = append(rep.results, res)
	}
	if err := r.report(ctx, policies.Items, rep); err != nil {
		errs = errors.Join(errs, err)
	}

	// Release the policies being deleted once none of their targets is
	// still wired for them alone. With the engine not injected, the
	// unwiring doesn't depend on the policies: all are released.
	for i := range policies.Items {
		p := &policies.Items[i]
		if !r.Disabled {
			if p.DeletionTimestamp == nil || !controllerutil.ContainsFinalizer(p, Finalizer) {
				continue
			}
			if err := r.unwiredFor(ctx, p, rep); err != nil {
				errs = errors.Join(errs, fmt.Errorf("WAFPolicy %s/%s deleted: %w", p.Namespace, p.Name, err))
				continue
			}
		}
		if err := setFinalizer(ctx, r.Client, p, false); client.IgnoreNotFound(err) != nil {
			errs = errors.Join(errs, fmt.Errorf("remove the finalizer from WAFPolicy %s/%s: %w", p.Namespace, p.Name, err))
		}
	}
	if errs != nil {
		return reconcile.Result{}, errs
	}
	return reconcile.Result{RequeueAfter: resync}, nil
}

// unwiredFor returns an error while one of a deleted policy's targets is
// still wired and no other policy wants it. The integrations read it from
// the API server: the cache may not show yet a wiring done a moment ago.
func (r *Reconciler) unwiredFor(ctx context.Context, p *wafv1alpha1.WAFPolicy, rep *report) error {
	for _, ref := range p.Spec.TargetRefs {
		t := targetOf(p.Namespace, ref)
		if slices.ContainsFunc(rep.results, func(res *Result) bool { return res.Targets[t].Wired }) {
			continue
		}
		for _, in := range r.Integrations {
			if !slices.Contains(in.Kinds(), t.Kind) {
				continue // never wired
			}
			switch wired, err := in.Wired(ctx, t); {
			case err != nil:
				return err
			case wired:
				return fmt.Errorf("%s %s is still wired", ref.Kind, ref.Name)
			}
		}
	}
	return nil
}

// setFinalizer adds the finalizer to a policy (on) or removes it.
func setFinalizer(ctx context.Context, c client.Client, p *wafv1alpha1.WAFPolicy, on bool) error {
	orig := p.DeepCopy()
	if on && !controllerutil.AddFinalizer(p, Finalizer) || !on && !controllerutil.RemoveFinalizer(p, Finalizer) {
		return nil
	}
	// metadata.finalizers is one list to a merge patch: the resourceVersion
	// makes sure it doesn't drop another controller's.
	return c.Patch(ctx, p, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}

// running are the pods that run or start: not finished or terminating.
func running(pods []corev1.Pod) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp == nil && pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
			out = append(out, pod)
		}
	}
	return out
}

// injectingSince is when the Pod webhook was installed; zero if unknown.
func (r *Reconciler) injectingSince(ctx context.Context) time.Time {
	if r.PodWebhook == "" {
		return time.Time{}
	}
	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	if err := r.Client.Get(ctx, types.NamespacedName{Name: r.PodWebhook}, &cfg); err != nil {
		return time.Time{}
	}
	return cfg.CreationTimestamp.Time
}

// programmed computes a policy's Programmed condition.
func programmed(p *wafv1alpha1.WAFPolicy, rep *report) (metav1.ConditionStatus, string, string) {
	if rep.disabled {
		return metav1.ConditionFalse, ReasonInjectionDisabled, "the engine is not injected into proxy pods (injection is off): the routes are not wired"
	}
	var unsupported, failed []string
	// wired counts the wired targets by result, then kind.
	wired := make([]map[schema.GroupKind]int, len(rep.results))
	total := 0
	for _, ref := range p.Spec.TargetRefs {
		t := targetOf(p.Namespace, ref)
		if !slices.Contains(rep.kinds, t.Kind) {
			unsupported = append(unsupported, fmt.Sprintf("%s %s (only %s targets are wired so far)", ref.Kind, ref.Name, kindList(rep.kinds)))
			continue
		}
		// The integration whose proxy serves the target, else why none does.
		served, why := -1, ""
		for i, res := range rep.results {
			s, ok := res.Targets[t]
			if !ok {
				continue
			}
			if s.Unsupported == "" {
				served = i
				break
			}
			if why == "" {
				why = s.Unsupported
			}
		}
		switch {
		case served >= 0:
			if s := rep.results[served].Targets[t]; s.Failed != "" {
				failed = append(failed, s.Failed)
				continue
			}
			if wired[served] == nil {
				wired[served] = map[schema.GroupKind]int{}
			}
			wired[served][t.Kind]++
			total++
		case why != "":
			unsupported = append(unsupported, why)
		}
		// Otherwise the target doesn't exist: reported by Accepted.
	}
	slices.Sort(failed)
	switch {
	case len(failed) > 0:
		return metav1.ConditionFalse, ReasonWiringFailed, strings.Join(slices.Compact(failed), "; ")
	case len(unsupported) > 0:
		return metav1.ConditionFalse, ReasonControllerUnsupported, strings.Join(unsupported, "; ")
	case total == 0:
		return metav1.ConditionFalse, ReasonNoTargets, "none of the policy's targets exists"
	}

	// The routes go to the proxies' pods, whose sidecar must be there.
	var msgs []string
	for i, res := range rep.results {
		if wired[i] == nil {
			continue
		}
		if st, reason, msg := sidecars(res.Proxy, res.Pods, rep.injectingSince); st != metav1.ConditionTrue {
			return st, reason, msg
		}
		var counts []string
		for _, k := range rep.kinds {
			if n := wired[i][k]; n > 0 {
				counts = append(counts, count(n, k.Kind))
				wired[i][k] = 0 // a kind several integrations share is listed once
			}
		}
		msgs = append(msgs, strings.Join(counts, " and ")+" wired to the engine in "+res.Proxy)
	}
	return metav1.ConditionTrue, ReasonProgrammed, strings.Join(msgs, "; ")
}

// sidecars checks that a proxy's running pods have the engine.
func sidecars(proxy string, all []corev1.Pod, injectingSince time.Time) (metav1.ConditionStatus, string, string) {
	var missed, optedOut, before []string
	pods := running(all)
	for _, pod := range pods {
		name := pod.Namespace + "/" + pod.Name
		switch {
		case injection.HasEngine(pod):
		case injection.OptedOut(pod):
			optedOut = append(optedOut, name)
		case !injectingSince.IsZero() && pod.CreationTimestamp.After(injectingSince):
			missed = append(missed, name)
		default:
			before = append(before, name)
		}
	}
	for _, l := range [][]string{missed, optedOut, before} {
		slices.Sort(l)
	}
	switch {
	case len(pods) == 0:
		// Nothing is wired then (Traefik.Wire).
		return metav1.ConditionFalse, ReasonSidecarMissing, fmt.Sprintf("no %[1]s pod selected for the engine is running, so the routes are not wired "+
			"(new %[1]s pods would have no engine to call); if %[1]s runs, the InkwallConfig's selector for it doesn't match its pods", proxy)
	case len(missed) > 0 || len(optedOut) > 0:
		var why []string
		if len(missed) > 0 {
			why = append(why, "created while the operator was unavailable (the injection webhook fails open in detect mode), restart them once it is back: "+strings.Join(missed, ", "))
		}
		if len(optedOut) > 0 {
			why = append(why, "opted out with "+injection.InjectAnnotation+": \"false\": "+strings.Join(optedOut, ", "))
		}
		return metav1.ConditionFalse, ReasonSidecarMissing, proxy + " pods run without the engine, their traffic is not inspected; " + strings.Join(why, "; ")
	case len(before) > 0:
		return metav1.ConditionFalse, ReasonPendingRestart, fmt.Sprintf(
			"%s pods started before Inkwall run without the engine; restart them (kubectl rollout restart) to inject it: %s",
			proxy, strings.Join(before, ", "))
	}
	return metav1.ConditionTrue, "", ""
}

func (r *Reconciler) report(ctx context.Context, policies []wafv1alpha1.WAFPolicy, rep *report) error {
	for i := range policies {
		p := &policies[i]
		if p.DeletionTimestamp != nil {
			continue
		}
		st, reason, msg := programmed(p, rep)
		if err := setProgrammed(ctx, r.Client, p, st, reason, msg, false); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

// setProgrammed sets a policy's Programmed condition, if it changed, and
// with ready recomputes Ready too: at uninstall, no status aggregator will.
func setProgrammed(ctx context.Context, c client.Client, p *wafv1alpha1.WAFPolicy, st metav1.ConditionStatus, reason, msg string, ready bool) error {
	first := true
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if !first {
			if err := c.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
				return err
			}
		}
		first = false
		changed := meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type: wafv1alpha1.ConditionProgrammed, Status: st, Reason: reason, Message: msg, ObservedGeneration: p.Generation,
		})
		if ready && meta.SetStatusCondition(&p.Status.Conditions, distribution.Ready(p.Status.Conditions, p.Generation)) {
			changed = true
		}
		if !changed {
			return nil
		}
		return c.Status().Update(ctx, p)
	})
}
