// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package controller holds the operator's reconcilers.
package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/resolver"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// The bundle builder reads the WAF objects and the routes they target,
// writes their status, and keeps the bundle and signing key Secrets in the
// operator's namespace. The kube-system Namespace's UID identifies the
// cluster.
//
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies;wafrulesets;clusterwafrulesets;inkwallconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies/status;wafrulesets/status;clusterwafrulesets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,resourceNames=kube-system,verbs=get

// Defaults of the builder.
const (
	// DefaultDebounce batches changes: a GitOps sync of many objects
	// produces one bundle, not one per object.
	DefaultDebounce = time.Second
	// resync rebuilds periodically, in case an event was missed.
	resync = 10 * time.Minute
)

// clusterRequest is the single work item: every change rebuilds the whole
// bundle.
var clusterRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "cluster"}}

// BundleReconciler builds the cluster's bundle from its WAF objects and
// reports each object's Accepted condition. It runs on the leader only.
type BundleReconciler struct {
	Client client.Client
	// APIReader reads uncached, for the current bundle.
	APIReader client.Reader
	// Namespace is the operator's, where the bundle Secrets are.
	Namespace string
	Debounce  time.Duration
	Now       func() time.Time

	signer      *bundle.Signer
	clusterID   string
	lastVersion uint64
	// checked caches CheckUserRules results by rule text: compiling with
	// the Core Rule Set takes milliseconds, and rules rarely change.
	checked map[[sha256.Size]byte]error
}

// SetupWithManager registers the builder with mgr.
func (r *BundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Debounce == 0 {
		r.Debounce = DefaultDebounce
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	r.checked = map[[sha256.Size]byte]error{}

	enqueue := handler.Funcs{
		CreateFunc: func(_ context.Context, _ event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, r.Debounce)
		},
		UpdateFunc: func(_ context.Context, _ event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, r.Debounce)
		},
		DeleteFunc: func(_ context.Context, _ event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, r.Debounce)
		},
		GenericFunc: func(_ context.Context, _ event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.Add(clusterRequest)
		},
	}
	// Status writes, ours included, don't change the generation.
	spec := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	bundleSecret := builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == r.Namespace && o.GetName() == bundle.BundleSecret
	}))
	// One build at startup, even in an empty cluster: engines need a bundle.
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &corev1.Secret{}}

	return ctrl.NewControllerManagedBy(mgr).
		Named("bundle").
		Watches(&wafv1alpha1.WAFPolicy{}, enqueue, spec).
		Watches(&wafv1alpha1.WAFRuleSet{}, enqueue, spec).
		Watches(&wafv1alpha1.ClusterWAFRuleSet{}, enqueue, spec).
		Watches(&wafv1alpha1.InkwallConfig{}, enqueue, spec).
		Watches(&networkingv1.Ingress{}, enqueue, spec).
		// The manager only caches ConfigMaps labeled resolver.RulesLabel.
		Watches(&corev1.ConfigMap{}, enqueue).
		// Recreate the bundle Secret if it is deleted or edited.
		Watches(&corev1.Secret{}, enqueue, bundleSecret).
		WatchesRawSource(source.Channel(start, enqueue)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// Reconcile rebuilds the bundle.
func (r *BundleReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	if err := r.init(ctx); err != nil {
		return reconcile.Result{}, err
	}

	in := resolver.Input{CheckRules: r.checkRules}
	var (
		policies        wafv1alpha1.WAFPolicyList
		ingresses       networkingv1.IngressList
		ruleSets        wafv1alpha1.WAFRuleSetList
		clusterRuleSets wafv1alpha1.ClusterWAFRuleSetList
		configMaps      corev1.ConfigMapList
	)
	for _, l := range []client.ObjectList{&policies, &ingresses, &ruleSets, &clusterRuleSets, &configMaps} {
		if err := r.Client.List(ctx, l); err != nil {
			return reconcile.Result{}, err
		}
	}
	in.Policies, in.Ingresses, in.RuleSets, in.ClusterRuleSets, in.ConfigMaps =
		policies.Items, ingresses.Items, ruleSets.Items, clusterRuleSets.Items, configMaps.Items

	var cfg wafv1alpha1.InkwallConfig
	suspended := false
	switch err := r.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case err == nil:
		suspended = cfg.Spec.Suspend
	case !apierrors.IsNotFound(err):
		return reconcile.Result{}, err
	}

	current, err := bundle.Load(ctx, r.APIReader, r.Namespace)
	if err != nil {
		// An unreadable bundle can't be continued safely: report, don't
		// overwrite it blindly.
		return reconcile.Result{}, fmt.Errorf("read the current bundle: %w", err)
	}
	in.Previous = current

	res := resolver.Resolve(in)
	next, changed, err := bundle.Next(current, &bundlev1.Bundle{
		ClusterId: r.clusterID,
		Policies:  res.Policies,
		RuleSets:  res.RuleSets,
		Suspended: suspended,
	}, r.lastVersion, r.Now())
	if err != nil {
		return reconcile.Result{}, err
	}
	if changed {
		signed, err := r.signer.Sign(next)
		if err != nil {
			return reconcile.Result{}, err
		}
		if err := bundle.Store(ctx, r.Client, r.Namespace, next, signed, r.signer.Public()); err != nil {
			if errors.Is(err, bundle.ErrTooLarge) {
				// Retrying won't help until the policy shrinks; keep the
				// current bundle.
				logger.Error(err, "bundle not published")
				return reconcile.Result{RequeueAfter: resync}, nil
			}
			return reconcile.Result{}, fmt.Errorf("store bundle %d: %w", next.GetVersion(), err)
		}
		r.lastVersion = next.GetVersion()
		logger.Info("bundle published", "version", next.GetVersion(), "policies", len(next.GetPolicies()),
			"rule_sets", len(next.GetRuleSets()), "suspended", suspended)
	}

	if err := r.writeStatus(ctx, res, next.GetVersion(), policies.Items, ruleSets.Items, clusterRuleSets.Items); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: resync}, nil
}

func (r *BundleReconciler) init(ctx context.Context) error {
	if r.signer == nil {
		s, err := bundle.LoadOrCreateSigner(ctx, r.Client, r.Namespace)
		if err != nil {
			return err
		}
		r.signer = s
	}
	if r.clusterID == "" {
		var ns corev1.Namespace
		if err := r.APIReader.Get(ctx, types.NamespacedName{Name: "kube-system"}, &ns); err != nil {
			return fmt.Errorf("read the cluster ID (kube-system UID): %w", err)
		}
		r.clusterID = string(ns.UID)
	}
	return nil
}

func (r *BundleReconciler) checkRules(rules string) error {
	k := sha256.Sum256([]byte(rules))
	if err, ok := r.checked[k]; ok {
		return err
	}
	err := coraza.CheckUserRules(rules)
	r.checked[k] = err
	return err
}

func condition(st resolver.Status, generation int64) metav1.Condition {
	status := metav1.ConditionFalse
	if st.Accepted {
		status = metav1.ConditionTrue
	}
	return metav1.Condition{
		Type:               wafv1alpha1.ConditionAccepted,
		Status:             status,
		Reason:             st.Reason,
		Message:            st.Message,
		ObservedGeneration: generation,
	}
}

// writeStatus updates what changed; unchanged objects aren't written.
func (r *BundleReconciler) writeStatus(ctx context.Context, res resolver.Result, version uint64,
	policies []wafv1alpha1.WAFPolicy, ruleSets []wafv1alpha1.WAFRuleSet, clusterRuleSets []wafv1alpha1.ClusterWAFRuleSet) error {
	for i := range policies {
		p := &policies[i]
		st, ok := res.PolicyStatus[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}]
		if !ok {
			continue
		}
		err := r.updateStatus(ctx, p, func(o client.Object) bool {
			pol := o.(*wafv1alpha1.WAFPolicy)
			changed := meta.SetStatusCondition(&pol.Status.Conditions, condition(st, pol.Generation))
			if pol.Status.ObservedGeneration != pol.Generation {
				pol.Status.ObservedGeneration, changed = pol.Generation, true
			}
			if st.Applied && pol.Status.BundleVersion != int64(version) { // #nosec G115 -- versions count builds
				pol.Status.BundleVersion, changed = int64(version), true // #nosec G115
			}
			return changed
		})
		if err != nil {
			return err
		}
	}
	for i := range ruleSets {
		rs := &ruleSets[i]
		if err := r.updateRuleSetStatus(ctx, rs, res.RuleSetStatus[resolver.RuleSetID("WAFRuleSet", rs.Namespace, rs.Name)]); err != nil {
			return err
		}
	}
	for i := range clusterRuleSets {
		rs := &clusterRuleSets[i]
		if err := r.updateRuleSetStatus(ctx, rs, res.RuleSetStatus[resolver.RuleSetID("ClusterWAFRuleSet", "", rs.Name)]); err != nil {
			return err
		}
	}
	return nil
}

func (r *BundleReconciler) updateRuleSetStatus(ctx context.Context, obj client.Object, st resolver.Status) error {
	return r.updateStatus(ctx, obj, func(o client.Object) bool {
		var status *wafv1alpha1.RuleSetStatus
		switch rs := o.(type) {
		case *wafv1alpha1.WAFRuleSet:
			status = &rs.Status
		case *wafv1alpha1.ClusterWAFRuleSet:
			status = &rs.Status
		}
		changed := meta.SetStatusCondition(&status.Conditions, condition(st, o.GetGeneration()))
		if status.ObservedGeneration != o.GetGeneration() {
			status.ObservedGeneration, changed = o.GetGeneration(), true
		}
		return changed
	})
}

// updateStatus applies mutate to the object and writes its status if
// mutate reports a change, retrying on conflicts with a fresh copy.
func (r *BundleReconciler) updateStatus(ctx context.Context, obj client.Object, mutate func(client.Object) bool) error {
	first := true
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if !first {
			if err := r.Client.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				return err
			}
		}
		first = false
		if !mutate(obj) {
			return nil
		}
		return r.Client.Status().Update(ctx, obj)
	})
	if apierrors.IsNotFound(err) {
		return nil // deleted meanwhile
	}
	return err
}
