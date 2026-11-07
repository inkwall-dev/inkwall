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
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

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
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies;wafrulesets;clusterwafrulesets;wafiplists;inkwallconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies/status;wafrulesets/status;clusterwafrulesets/status;inkwallconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;gateways;gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices;gateways,verbs=get;list;watch
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
	// statusWriters is how many policy statuses are written at once.
	statusWriters = 8
)

// HTTPRouteGVK is Gateway API's HTTPRoute, whose CRD may be missing.
var HTTPRouteGVK = schema.GroupVersionKind{Group: gatewayv1.GroupName, Version: "v1", Kind: "HTTPRoute"}

// warnBytes is the compressed size past which publishing a bundle warns.
const warnBytes = bundle.MaxCompressedBytes * 3 / 4

// Reasons the builder reports.
const (
	// ReasonBundleTooLarge: Accepted is False because the bundle with the
	// policy as it is now doesn't fit its Secrets, so it isn't published.
	ReasonBundleTooLarge = "BundleTooLarge"
	// ReasonSuspended and ReasonNotSuspended: the InkwallConfig's
	// Suspended condition.
	ReasonSuspended    = "Suspended"
	ReasonNotSuspended = "NotSuspended"
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
	// HTTPRoutes watches Gateway API's HTTPRoutes once their CRD is
	// installed; nil: they are only read at each build.
	HTTPRoutes *crdwatch.Kind
	// VirtualServices watches Istio's VirtualServices once their CRD is
	// installed; nil: they are only read at each build.
	VirtualServices *crdwatch.Kind

	// current is the bundle last read or stored, so a build decodes the
	// bundle Secret only when someone else changed it.
	current bundle.Current
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
		Watches(&wafv1alpha1.WAFIPList{}, enqueue, spec).
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
	if r.HTTPRoutes != nil {
		r.HTTPRoutes.Add(c, enqueue, predicate.GenerationChangedPredicate{})
	}
	if r.VirtualServices != nil {
		r.VirtualServices.Add(c, enqueue, predicate.GenerationChangedPredicate{})
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
		ipLists         wafv1alpha1.WAFIPListList
	)
	for _, l := range []client.ObjectList{&policies, &ingresses, &ruleSets, &clusterRuleSets, &configMaps, &ipLists} {
		if err := r.Client.List(ctx, l); err != nil {
			return reconcile.Result{}, err
		}
	}
	in.Policies, in.Ingresses, in.RuleSets, in.ClusterRuleSets, in.ConfigMaps, in.IPLists =
		policies.Items, ingresses.Items, ruleSets.Items, clusterRuleSets.Items, configMaps.Items, ipLists.Items
	// An error here is not "no IngressRoutes": building without them would
	// drop their protection.
	routes, _, err := wiring.IngressRoutes(ctx, r.Client)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("list IngressRoutes: %w", err)
	}
	in.IngressRoutes = routes
	if in.HTTPRoutes, err = HTTPRoutes(ctx, r.Client); err != nil {
		return reconcile.Result{}, fmt.Errorf("list HTTPRoutes: %w", err)
	}
	if in.VirtualServices, err = wiring.VirtualServices(ctx, r.Client); err != nil {
		return reconcile.Result{}, fmt.Errorf("list VirtualServices: %w", err)
	}

	cfg, err := r.config(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	suspended := cfg != nil && cfg.Spec.Suspend

	current, currentKey, err := r.current.Load(ctx, r.APIReader, r.Namespace)
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
		ProbeKey:  signer.ProbeKey(),
		Events:    eventsConfig(cfg),
	}, r.lastVersion, r.Now(), resign)
	if err != nil {
		return reconcile.Result{}, err
	}
	// published is the bundle engines get: next, unless it is too large.
	published := next
	var tooLarge error
	if changed {
		switch err := r.publish(ctx, signer, next); {
		case errors.Is(err, bundle.ErrTooLarge):
			// Retrying won't help until the policy shrinks; keep the
			// current bundle, and say so on the policies it doesn't
			// enforce as they are now.
			logger.Error(err, "bundle not published")
			tooLarge, published = err, current
			if current.GetSuspended() != suspended {
				// The switch must work exactly when something is wrong:
				// the bundle in force, flipped, fits as it does (#291).
				if published, err = r.publishSwitched(ctx, signer, current, suspended); err != nil {
					return reconcile.Result{}, err
				}
			}
		case err != nil:
			return reconcile.Result{}, err
		}
	}
	if err := bundle.Prune(ctx, r.Client, r.APIReader, r.Namespace); err != nil {
		return reconcile.Result{}, fmt.Errorf("delete stale bundle chunks: %w", err)
	}

	if tooLarge != nil {
		err = r.writeTooLarge(ctx, res, published, next, tooLarge, policies.Items, ruleSets.Items, clusterRuleSets.Items)
	} else {
		err = r.writeStatus(ctx, res, next, policies.Items, ruleSets.Items, clusterRuleSets.Items)
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.writeConfigStatus(ctx, cfg, published, keys); err != nil {
		return reconcile.Result{}, err
	}
	if keys.Phase() != bundle.PhaseIdle {
		return reconcile.Result{RequeueAfter: min(rotationPoll, r.RotationGrace)}, nil
	}
	return reconcile.Result{RequeueAfter: resync}, nil
}

// publish signs and stores next.
func (r *BundleReconciler) publish(ctx context.Context, signer *bundle.Signer, next *bundlev1.Bundle) error {
	signed, err := signer.Sign(next)
	if err != nil {
		return err
	}
	size, err := r.current.Store(ctx, r.Client, r.APIReader, r.Namespace, next, signed, signer.Public())
	if errors.Is(err, bundle.ErrTooLarge) {
		return err
	}
	if err != nil {
		return fmt.Errorf("store bundle %d: %w", next.GetVersion(), err)
	}
	r.lastVersion = next.GetVersion()
	chunks := 0
	if size > bundlesecret.ChunkBytes {
		chunks = (size + bundlesecret.ChunkBytes - 1) / bundlesecret.ChunkBytes
	}
	logger := log.FromContext(ctx)
	logger.Info("bundle published", "version", next.GetVersion(), "policies", len(next.GetPolicies()),
		"rule_sets", len(next.GetRuleSets()), "suspended", next.GetSuspended(), "key", signer.KeyID(), "bytes", size, "chunks", chunks)
	if size > warnBytes {
		// Warn well before builds fail.
		logger.Info("bundle nears its size limit: past it, policy changes are not published",
			"bytes", size, "limit", bundle.MaxCompressedBytes)
	}
	return nil
}

// publishSwitched publishes the bundle in force, current, with inspection
// suspended or resumed as spec.suspend says, when the bundle built from the
// cluster is too large: suspending must work exactly when something is
// wrong. It enforces what current does, so it fits as current does; with
// no current bundle, it has no policies.
func (r *BundleReconciler) publishSwitched(ctx context.Context, signer *bundle.Signer, current *bundlev1.Bundle,
	suspended bool) (*bundlev1.Bundle, error) {
	content := &bundlev1.Bundle{ClusterId: r.clusterID}
	if current != nil {
		content = proto.Clone(current).(*bundlev1.Bundle)
	}
	content.Suspended = suspended
	next, _, err := bundle.Next(current, content, r.lastVersion, r.Now(), false)
	if err != nil {
		return nil, err
	}
	if err := r.publish(ctx, signer, next); err != nil {
		return nil, fmt.Errorf("publish bundle %d, the bundle in force with suspend %t: %w", next.GetVersion(), suspended, err)
	}
	log.FromContext(ctx).Info("bundle in force published again, as spec.suspend says", "version", next.GetVersion(), "suspended", suspended)
	return next, nil
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
		engines, leftOut, err := distribution.ReadEngines(ctx, r.APIReader, r.Namespace, r.EngineStale, now)
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
		// A report over its size limit leaves engines out: wait, as for a
		// replica that hasn't reported yet.
		in.EnginesKnown = now.Sub(r.started) >= r.EngineStale && leftOut == 0
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

// writeStatus updates what changed; unchanged objects aren't written. A
// policy's bundleVersion is the first bundle that enforces it as it is
// now, which the bundle records (bundle.PolicyVersions), so a bundle that
// changes other policies doesn't write it, and a new leader continues it.
func (r *BundleReconciler) writeStatus(ctx context.Context, res resolver.Result, next *bundlev1.Bundle,
	policies []wafv1alpha1.WAFPolicy, ruleSets []wafv1alpha1.WAFRuleSet, clusterRuleSets []wafv1alpha1.ClusterWAFRuleSet) error {
	versions := bundle.PolicyVersions(next)
	// The writes run in parallel: the first build after a GitOps sync of
	// thousands of policies writes all of them.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(statusWriters)
	for i := range policies {
		p := &policies[i]
		st, ok := res.PolicyStatus[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}]
		if !ok {
			continue
		}
		var version int64
		if st.Applied {
			version = int64(versions[resolver.PolicyID(p.Namespace, p.Name)]) // #nosec G115 -- versions count builds
		}
		g.Go(func() error {
			return r.updateStatus(gctx, p, func(o client.Object) bool {
				pol := o.(*wafv1alpha1.WAFPolicy)
				changed := meta.SetStatusCondition(&pol.Status.Conditions, condition(st, pol.Generation))
				if pol.Status.ObservedGeneration != pol.Generation {
					pol.Status.ObservedGeneration, changed = pol.Generation, true
				}
				if version != 0 && pol.Status.BundleVersion != version {
					pol.Status.BundleVersion, changed = version, true
				}
				return changed
			})
		})
	}
	if err := g.Wait(); err != nil {
		return err
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

// writeTooLarge writes the statuses of a build whose bundle, next, is too
// large to publish (tooLarge says by how much): the engines keep running
// current. A policy next would change (bundle.PolicyHashes), or add, is
// not Accepted: its spec isn't running, and a status for the generation
// before would claim it is. The others run as they are: their status is
// current's.
func (r *BundleReconciler) writeTooLarge(ctx context.Context, res resolver.Result, current, next *bundlev1.Bundle, tooLarge error,
	policies []wafv1alpha1.WAFPolicy, ruleSets []wafv1alpha1.WAFRuleSet, clusterRuleSets []wafv1alpha1.ClusterWAFRuleSet) error {
	was, err := bundle.PolicyHashes(current)
	if err != nil {
		return err
	}
	now, err := bundle.PolicyHashes(next)
	if err != nil {
		return err
	}
	running := "no bundle is published yet"
	if current != nil {
		running = fmt.Sprintf("engines run bundle %d, without this spec", current.GetVersion())
	}
	statuses := make(map[types.NamespacedName]resolver.Status, len(res.PolicyStatus))
	for key, st := range res.PolicyStatus {
		id := resolver.PolicyID(key.Namespace, key.Name)
		if h, ok := now[id]; ok && st.Applied {
			if w, ok := was[id]; !ok || w != h {
				st = resolver.Status{Reason: ReasonBundleTooLarge, Message: fmt.Sprintf(
					"not published: %v; %s. Shrink this policy, its rule sets or others until the bundle fits", tooLarge, running)}
			}
		}
		statuses[key] = st
	}
	res.PolicyStatus = statuses
	return r.writeStatus(ctx, res, current, policies, ruleSets, clusterRuleSets)
}

// writeConfigStatus reports on the InkwallConfig whether the published
// bundle suspends inspection, the published bundle, and the signing key
// and its rotation (#375).
func (r *BundleReconciler) writeConfigStatus(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, published *bundlev1.Bundle,
	keys *bundle.Keyring) error {
	if cfg == nil {
		return nil
	}
	cond := metav1.Condition{Type: wafv1alpha1.ConditionSuspended, Status: metav1.ConditionFalse, Reason: ReasonNotSuspended,
		Message: "engines inspect requests as the policies say", ObservedGeneration: cfg.Generation}
	if published.GetSuspended() {
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonSuspended
		cond.Message = fmt.Sprintf("bundle %d suspends inspection: every engine allows every request", published.GetVersion())
	}
	if published.GetSuspended() != cfg.Spec.Suspend {
		// The bundle with the switch flipped isn't published: too large.
		cond.Message += fmt.Sprintf("; spec.suspend is %t, but its bundle couldn't be published (see the operator's log)", cfg.Spec.Suspend)
	}
	var bs *wafv1alpha1.BundleStatus
	if published != nil {
		bs = &wafv1alpha1.BundleStatus{
			Version:         int64(published.GetVersion()), // #nosec G115 -- versions count builds
			CompressedBytes: int64(r.current.Size()),
			LimitBytes:      bundle.MaxCompressedBytes,
		}
	}
	key, rotation := signingKeyStatus(keys, r.lastWait, cfg.Generation)
	return r.updateStatus(ctx, cfg, func(o client.Object) bool {
		c := o.(*wafv1alpha1.InkwallConfig)
		changed := meta.SetStatusCondition(&c.Status.Conditions, cond)
		if meta.SetStatusCondition(&c.Status.Conditions, rotation) {
			changed = true
		}
		if !apiequality.Semantic.DeepEqual(c.Status.Bundle, bs) {
			c.Status.Bundle, changed = bs, true
		}
		if !apiequality.Semantic.DeepEqual(c.Status.SigningKey, key) {
			c.Status.SigningKey, changed = key, true
		}
		return changed
	})
}

// Reasons of the InkwallConfig's SigningKeyRotation condition: the phase.
const (
	ReasonRotationIdle       = "Idle"
	ReasonRotationPublishing = "Publishing"
	ReasonRotationRetiring   = "Retiring"
)

// signingKeyStatus describes the keyring and what its rotation waits for.
func signingKeyStatus(k *bundle.Keyring, waiting string, generation int64) (*wafv1alpha1.SigningKeyStatus, metav1.Condition) {
	st := &wafv1alpha1.SigningKeyStatus{ActiveKeyID: k.Active.KeyID(), Phase: wafv1alpha1.SigningKeyIdle}
	cond := metav1.Condition{Type: wafv1alpha1.ConditionSigningKeyRotation, Status: metav1.ConditionFalse,
		Reason: ReasonRotationIdle, ObservedGeneration: generation}
	since := k.PhaseSince
	switch k.Phase() {
	case bundle.PhasePublishing:
		st.Phase, cond.Status, cond.Reason = wafv1alpha1.SigningKeyPublishing, metav1.ConditionTrue, ReasonRotationPublishing
		cond.Message = fmt.Sprintf("key %s is published to the engines; key %s still signs", k.Next.KeyID(), k.Active.KeyID())
	case bundle.PhaseRetiring:
		st.Phase, cond.Status, cond.Reason = wafv1alpha1.SigningKeyRetiring, metav1.ConditionTrue, ReasonRotationRetiring
		cond.Message = fmt.Sprintf("key %s signs; the previous key %s stays trusted until every engine runs a bundle it signed",
			k.Active.KeyID(), bundlekey.ID(k.Previous))
	default:
		since, waiting = k.ActiveSince, ""
		cond.Message = fmt.Sprintf("no rotation in progress: key %s signs", k.Active.KeyID())
	}
	if !since.IsZero() {
		t := metav1.NewTime(since.UTC().Truncate(time.Second))
		st.Since = &t
	}
	if waiting != "" {
		st.WaitingFor = truncate(waiting, 1024)
		cond.Message += "; waiting: " + waiting
	}
	return st, cond
}

// truncate cuts s to at most n bytes, on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
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
// mutate reports a change, retrying on conflicts with a fresh copy. A copy
// of another generation isn't written: the status is the build's result
// for the generation it read, and the edit requeues a build that writes
// the new one.
func (r *BundleReconciler) updateStatus(ctx context.Context, obj client.Object, mutate func(client.Object) bool) error {
	first, generation := true, obj.GetGeneration()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if !first {
			if err := r.Client.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				return err
			}
			if obj.GetGeneration() != generation {
				return nil
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

// HTTPRoutes lists Gateway API's HTTPRoutes; none when their CRD isn't
// installed.
func HTTPRoutes(ctx context.Context, c client.Client) ([]gatewayv1.HTTPRoute, error) {
	if installed, err := crdwatch.Installed(c.RESTMapper(), HTTPRouteGVK); !installed || err != nil {
		return nil, err
	}
	var list gatewayv1.HTTPRouteList
	if err := c.List(ctx, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// eventsConfig is the InkwallConfig's events.redact for the engines, nil
// for the defaults: a bundle that doesn't change them keeps its hash.
func eventsConfig(cfg *wafv1alpha1.InkwallConfig) *bundlev1.EventsConfig {
	if cfg == nil {
		return nil
	}
	redact := cfg.Spec.Events.Redact
	out := &bundlev1.EventsConfig{NoSnippets: redact.Snippets != nil && !*redact.Snippets}
	for _, h := range redact.Headers {
		out.RedactHeaders = append(out.RedactHeaders, string(h))
	}
	for _, a := range redact.Arguments {
		out.RedactArguments = append(out.RedactArguments, string(a))
	}
	if !out.NoSnippets && len(out.RedactHeaders) == 0 && len(out.RedactArguments) == 0 {
		return nil
	}
	return out
}
