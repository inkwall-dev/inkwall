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
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
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
// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,resourceNames=kube-system,verbs=get

// Defaults of the builder.
const (
	// DefaultDebounce batches changes: a GitOps sync of many objects
	// produces one bundle, not one per object.
	DefaultDebounce = time.Second
	// resync rebuilds periodically, in case an event was missed.
	resync = 10 * time.Minute
	// DefaultRotationGrace is the least time each phase of a key rotation
	// lasts: the kubelet updates a mounted ConfigMap within a minute or two.
	DefaultRotationGrace = time.Minute
	// DefaultEngineStale is the distribution Reporter's default Stale.
	DefaultEngineStale = 30 * time.Second
	// rotationPoll checks a rotation's progress.
	rotationPoll = 5 * time.Second
)

// warnBytes is the compressed size past which publishing a bundle warns.
const warnBytes = bundle.MaxCompressedBytes * 3 / 4

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
	// EngineStale is how old a replica's engine report may be (the
	// distribution Reporter's Stale); a new leader waits this long before
	// a key rotation trusts the reports to list every engine. 0:
	// DefaultEngineStale.
	EngineStale time.Duration
	// RotationGrace is the least time each phase of a key rotation lasts;
	// 0: DefaultRotationGrace.
	RotationGrace time.Duration
	// IngressRoutes watches Traefik's IngressRoutes once their CRD is
	// installed; nil: they are only read at each build.
	IngressRoutes *crdwatch.Kind

	// keys is the keyring last read or written, to recreate the signing
	// key Secret if it is deleted: engines trust these keys.
	keys        *bundle.Keyring
	started     time.Time
	lastWait    string
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
	if r.RotationGrace == 0 {
		r.RotationGrace = DefaultRotationGrace
	}
	if r.EngineStale == 0 {
		// Every report would be stale: no engine would hold a rotation.
		r.EngineStale = DefaultEngineStale
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
	// The rotation request is an annotation.
	config := builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))
	secrets := builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == r.Namespace && (o.GetName() == bundle.BundleSecret || o.GetName() == bundle.SigningKeySecret ||
			bundlesecret.IsChunk(bundle.BundleSecret, o.GetName()))
	}))
	// One build at startup, even in an empty cluster: engines need a bundle.
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &corev1.Secret{}}

	c, err := ctrl.NewControllerManagedBy(mgr).
		Named("bundle").
		Watches(&wafv1alpha1.WAFPolicy{}, enqueue, spec).
		Watches(&wafv1alpha1.WAFRuleSet{}, enqueue, spec).
		Watches(&wafv1alpha1.ClusterWAFRuleSet{}, enqueue, spec).
		Watches(&wafv1alpha1.InkwallConfig{}, enqueue, config).
		Watches(&networkingv1.Ingress{}, enqueue, spec).
		// The manager only caches ConfigMaps labeled resolver.RulesLabel.
		Watches(&corev1.ConfigMap{}, enqueue).
		// Recreate the bundle, its chunks and the signing key Secret if
		// they are deleted or edited.
		Watches(&corev1.Secret{}, enqueue, secrets).
		WatchesRawSource(source.Channel(start, enqueue)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Build(r)
	if err != nil {
		return err
	}
	if r.IngressRoutes != nil {
		r.IngressRoutes.Add(c, enqueue, predicate.GenerationChangedPredicate{})
	}
	return nil
}

// Reconcile rebuilds the bundle.
func (r *BundleReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	if err := r.init(ctx); err != nil {
		return reconcile.Result{}, err
	}
	keys, keySecret, err := r.loadKeys(ctx)
	if err != nil {
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
	// An error here is not "no IngressRoutes": building without them would
	// drop their protection.
	routes, _, err := wiring.IngressRoutes(ctx, r.Client)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("list IngressRoutes: %w", err)
	}
	in.IngressRoutes = routes

	cfg, err := r.config(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	suspended := cfg != nil && cfg.Spec.Suspend

	current, currentKey, err := bundle.Load(ctx, r.APIReader, r.Namespace)
	if errors.Is(err, bundlesecret.ErrIncomplete) {
		// A chunk deleted or edited: write the bundle again, continuing
		// the version sequence.
		logger.Error(err, "current bundle incomplete; publishing it again")
		r.lastVersion = max(r.lastVersion, current.GetVersion())
		current, currentKey, err = nil, "", nil
	}
	if err != nil {
		// An unreadable bundle can't be continued safely: report, don't
		// overwrite it blindly.
		return reconcile.Result{}, fmt.Errorf("read the current bundle: %w", err)
	}
	in.Previous = current

	if keys, err = r.rotate(ctx, keys, keySecret, cfg, current.GetVersion(), currentKey); err != nil {
		return reconcile.Result{}, err
	}
	signer := keys.Active

	res := resolver.Resolve(in)
	// A bundle signed with another key than the active one (it just
	// rotated) is signed again, as a new version: engines then cache a
	// bundle the active key signed.
	resign := current != nil && currentKey != signer.KeyID()
	next, changed, err := bundle.Next(current, &bundlev1.Bundle{
		ClusterId: r.clusterID,
		Policies:  res.Policies,
		RuleSets:  res.RuleSets,
		Suspended: suspended,
	}, r.lastVersion, r.Now(), resign)
	if err != nil {
		return reconcile.Result{}, err
	}
	if changed {
		signed, err := signer.Sign(next)
		if err != nil {
			return reconcile.Result{}, err
		}
		size, err := bundle.Store(ctx, r.Client, r.APIReader, r.Namespace, next, signed, signer.Public())
		if err != nil {
			if errors.Is(err, bundle.ErrTooLarge) {
				// Retrying won't help until the policy shrinks; keep the
				// current bundle.
				logger.Error(err, "bundle not published")
				return reconcile.Result{RequeueAfter: resync}, nil
			}
			return reconcile.Result{}, fmt.Errorf("store bundle %d: %w", next.GetVersion(), err)
		}
		r.lastVersion = next.GetVersion()
		chunks := 0
		if size > bundlesecret.ChunkBytes {
			chunks = (size + bundlesecret.ChunkBytes - 1) / bundlesecret.ChunkBytes
		}
		logger.Info("bundle published", "version", next.GetVersion(), "policies", len(next.GetPolicies()),
			"rule_sets", len(next.GetRuleSets()), "suspended", suspended, "key", signer.KeyID(), "bytes", size, "chunks", chunks)
		if size > warnBytes {
			// Warn well before builds fail.
			logger.Info("bundle nears its size limit: past it, policy changes are not published",
				"bytes", size, "limit", bundle.MaxCompressedBytes)
		}
	}
	if err := bundle.Prune(ctx, r.Client, r.APIReader, r.Namespace); err != nil {
		return reconcile.Result{}, fmt.Errorf("delete stale bundle chunks: %w", err)
	}

	if err := r.writeStatus(ctx, res, next.GetVersion(), policies.Items, ruleSets.Items, clusterRuleSets.Items); err != nil {
		return reconcile.Result{}, err
	}
	if keys.Phase() != bundle.PhaseIdle {
		return reconcile.Result{RequeueAfter: min(rotationPoll, r.RotationGrace)}, nil
	}
	return reconcile.Result{RequeueAfter: resync}, nil
}

// config reads the InkwallConfig; nil if there is none.
func (r *BundleReconciler) config(ctx context.Context) (*wafv1alpha1.InkwallConfig, error) {
	var cfg wafv1alpha1.InkwallConfig
	err := r.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// loadKeys reads the keyring, uncached: a stale copy would undo a
// rotation step. A missing signing key Secret is created: with a new key
// on first use, and with the keys in memory if it was deleted, so engines
// keep trusting them.
func (r *BundleReconciler) loadKeys(ctx context.Context) (*bundle.Keyring, *corev1.Secret, error) {
	k, s, err := bundle.LoadKeyring(ctx, r.APIReader, r.Namespace)
	if err != nil || s != nil {
		if k != nil {
			r.keys = k
		}
		return k, s, err
	}
	k = r.keys
	if k == nil {
		if k, err = bundle.NewKeyring(r.Now()); err != nil {
			return nil, nil, err
		}
	}
	if err := bundle.SaveKeyring(ctx, r.Client, r.Namespace, k, nil); err != nil {
		return nil, nil, fmt.Errorf("create the signing key Secret: %w", err)
	}
	log.FromContext(ctx).Info("signing key Secret created", "key", k.Active.KeyID(), "trusted", k.TrustedIDs())
	k, s, err = bundle.LoadKeyring(ctx, r.APIReader, r.Namespace)
	if err == nil && s == nil {
		err = errors.New("the signing key Secret is gone again")
	}
	if err != nil {
		return nil, nil, err
	}
	r.keys = k
	return k, s, nil
}

// rotate takes the next step of a signing key rotation, if one is
// requested, due or in progress, and returns the keyring to sign with.
func (r *BundleReconciler) rotate(ctx context.Context, k *bundle.Keyring, s *corev1.Secret, cfg *wafv1alpha1.InkwallConfig,
	version uint64, keyID string) (*bundle.Keyring, error) {
	now := r.Now()
	in := bundle.RotationInput{Now: now, Grace: r.RotationGrace, BundleVersion: version, BundleKeyID: keyID}
	if cfg != nil {
		in.Request = cfg.Annotations[wafv1alpha1.RotateSigningKeyAnnotation]
		if iv := cfg.Spec.SigningKey.RotationInterval; iv != nil {
			in.Interval = iv.Duration
		}
	}
	if k.Phase() != bundle.PhaseIdle {
		engines, err := distribution.ReadEngines(ctx, r.APIReader, r.Namespace, r.EngineStale, now)
		if err != nil {
			return nil, fmt.Errorf("read the engine reports: %w", err)
		}
		for _, e := range engines {
			name := e.ID
			if e.PodName != "" {
				name = e.PodNamespace + "/" + e.PodName
			}
			in.Engines = append(in.Engines, bundle.EngineKeys{Name: name, TrustedKeys: e.TrustedKeys, Applied: e.Applied})
		}
		in.EnginesKnown = now.Sub(r.started) >= r.EngineStale
	}
	step, err := bundle.Rotate(k, in)
	if err != nil {
		return nil, err
	}
	logger := log.FromContext(ctx)
	if step.Waiting != r.lastWait {
		r.lastWait = step.Waiting
		if step.Waiting != "" {
			logger.Info("signing key rotation: " + step.Waiting)
		}
	}
	if !step.Changed {
		return k, nil
	}
	if err := bundle.SaveKeyring(ctx, r.Client, r.Namespace, step.Keyring, s); err != nil {
		return nil, fmt.Errorf("save the signing key Secret: %w", err)
	}
	r.keys = step.Keyring
	switch step.Event {
	case "started":
		logger.Info("signing key rotation started: new key published", "key", step.Keyring.Next.KeyID(), "signing", step.Keyring.Active.KeyID())
	case "switched":
		logger.Info("signing key rotation: switched to the new key", "key", step.Keyring.Active.KeyID(), "previous", bundlekey.ID(step.Keyring.Previous))
	case "retired":
		logger.Info("signing key rotation done: previous key retired", "key", step.Keyring.Active.KeyID())
	}
	return step.Keyring, nil
}

func (r *BundleReconciler) init(ctx context.Context) error {
	if r.started.IsZero() {
		r.started = r.Now()
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
