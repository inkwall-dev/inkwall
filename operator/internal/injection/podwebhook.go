// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"context"
	"fmt"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// PodWebhookReconciler keeps the Pod webhook's objectSelector and
// failurePolicy (0004 §4.3). It runs on the leader; the chart installs the
// webhook with the defaults, and a Helm upgrade that resets them is
// corrected here.
//
// The objectSelector is the proxy pods' selector (InkwallConfig can
// override it), minus pods labeled waf.inkwall.dev/inject: "false".
//
// The failurePolicy follows the policies' modes. Detect only: Ignore, so
// proxy pods start even while the operator is down, without the engine
// (reported as SidecarMissing). Any policy in block mode: Fail, so a proxy
// pod can't start without its engine while its routes must be blocked;
// pods already running keep serving.
type PodWebhookReconciler struct {
	Client client.Client
	// ConfigName is the MutatingWebhookConfiguration, WebhookName its Pod
	// webhook.
	ConfigName  string
	WebhookName string
	// Pods selects the proxy pods (integrations.Selectors.LabelSelector).
	Pods *metav1.LabelSelector
}

var podWebhookRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "pod-webhook"}}

// SetupWithManager registers the controller. The manager must cache the
// MutatingWebhookConfiguration (only ConfigName).
func (r *PodWebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	one := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{podWebhookRequest}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("pod-webhook").
		Watches(&wafv1alpha1.WAFPolicy{}, one, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&admissionregistrationv1.MutatingWebhookConfiguration{}, one, builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetName() == r.ConfigName
		}))).
		Complete(r)
}

// WantFailurePolicy is the Pod webhook's failurePolicy for these policies.
func WantFailurePolicy(policies []wafv1alpha1.WAFPolicy) admissionregistrationv1.FailurePolicyType {
	for i := range policies {
		if policies[i].DeletionTimestamp == nil && policies[i].Spec.Mode == wafv1alpha1.PolicyBlock {
			return admissionregistrationv1.Fail
		}
	}
	return admissionregistrationv1.Ignore
}

// ObjectSelector is the Pod webhook's objectSelector for pods: those pods,
// without the ones that opted out with the label.
func ObjectSelector(pods *metav1.LabelSelector) *metav1.LabelSelector {
	sel := pods.DeepCopy()
	if sel == nil {
		sel = &metav1.LabelSelector{}
	}
	sel.MatchExpressions = append(sel.MatchExpressions, metav1.LabelSelectorRequirement{
		Key: InjectLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"false"},
	})
	return sel
}

// Reconcile sets the objectSelector and failurePolicy.
func (r *PodWebhookReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	// The cache's policies, not copies: they are only read. Each
	// generation change lists them all.
	var policies wafv1alpha1.WAFPolicyList
	if err := r.Client.List(ctx, &policies, client.UnsafeDisableDeepCopy); err != nil {
		return reconcile.Result{}, err
	}
	want := WantFailurePolicy(policies.Items)
	selector := ObjectSelector(r.Pods)

	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	if err := r.Client.Get(ctx, types.NamespacedName{Name: r.ConfigName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{RequeueAfter: time.Minute}, nil
		}
		return reconcile.Result{}, err
	}
	base := cfg.DeepCopy()
	found := false
	for i := range cfg.Webhooks {
		wh := &cfg.Webhooks[i]
		if wh.Name != r.WebhookName {
			continue
		}
		found = true
		if wh.FailurePolicy != nil && *wh.FailurePolicy == want && apiequality.Semantic.DeepEqual(wh.ObjectSelector, selector) {
			return reconcile.Result{}, nil
		}
		wh.FailurePolicy = &want
		wh.ObjectSelector = selector
	}
	if !found {
		return reconcile.Result{}, fmt.Errorf("MutatingWebhookConfiguration %s has no webhook %s", r.ConfigName, r.WebhookName)
	}
	// The whole webhooks list is sent: the optimistic lock keeps it from
	// undoing a CA bundle the certificate rotator wrote meanwhile (a
	// conflict is retried).
	if err := r.Client.Patch(ctx, &cfg, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return reconcile.Result{}, err
	}
	why := "no policy is in block mode: proxy pods start without the engine while the operator is down"
	if want == admissionregistrationv1.Fail {
		why = "a policy is in block mode: proxy pods can't start without the engine while the operator is down"
	}
	sel, _ := metav1.LabelSelectorAsSelector(selector)
	log.FromContext(ctx).Info("Pod webhook updated", "failurePolicy", want, "reason", why, "objectSelector", sel.String())
	return reconcile.Result{}, nil
}
