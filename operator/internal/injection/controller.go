// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/inkwall-dev/inkwall/operator/bundle"
)

// The controller reads proxy pods, writes the trust ConfigMap in their
// namespaces, and grants their ServiceAccounts read access to the bundle
// Secret with a Role and RoleBinding in its own namespace. To grant that,
// it must itself be allowed to read the Secret (it is).
//
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,namespace=inkwall-system,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch

// GrantName names the Role and RoleBinding that let proxy pods read the
// bundle Secret.
const GrantName = "inkwall-bundle-reader"

// grantRequest is the work item for the RoleBinding; every other request
// names a namespace whose trust ConfigMap to reconcile.
var grantRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "\x00grant"}}

// resync rebuilds periodically, in case a ConfigMap was edited (the manager
// doesn't watch them).
const resync = 10 * time.Minute

// Reconciler provides what injected engines need. It runs on the leader.
type Reconciler struct {
	Client client.Client
	// APIReader reads uncached: the trust ConfigMaps aren't cached.
	APIReader client.Reader
	// Namespace is the operator's, with the bundle and certificate Secrets.
	Namespace string
	// CertSecret holds the operator's CA (ca.crt).
	CertSecret string
	// Pods selects the proxy pods (integrations.Selectors.PodSelector).
	Pods labels.Selector
}

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("injection").
		// The manager caches only proxy pods.
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: o.GetNamespace()}}, grantRequest}
		})).
		// A new CA or signing key (a rotation step): every trust ConfigMap.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.allNamespaces), builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetNamespace() == r.Namespace && (o.GetName() == r.CertSecret || o.GetName() == bundle.SigningKeySecret)
		}))).
		Complete(r)
}

func (r *Reconciler) allNamespaces(ctx context.Context, _ client.Object) []reconcile.Request {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: r.Pods}); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []reconcile.Request
	for _, p := range pods.Items {
		if !seen[p.Namespace] {
			seen[p.Namespace] = true
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: p.Namespace}})
		}
	}
	return out
}

// Reconcile reconciles the trust ConfigMap of a namespace, or the grant.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req == grantRequest {
		return reconcile.Result{RequeueAfter: resync}, r.reconcileGrant(ctx)
	}
	return r.reconcileTrust(ctx, req.Name)
}

func managed() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
}

func (r *Reconciler) reconcileTrust(ctx context.Context, namespace string) (reconcile.Result, error) {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: r.Pods}); err != nil {
		return reconcile.Result{}, err
	}
	key := types.NamespacedName{Namespace: namespace, Name: TrustConfigMap}
	var cm corev1.ConfigMap
	err := r.APIReader.Get(ctx, key, &cm)
	exists := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	if len(pods.Items) == 0 {
		// No proxy pods left: remove what the operator created.
		if exists && cm.Labels["app.kubernetes.io/managed-by"] == "inkwall-operator" {
			return reconcile.Result{}, client.IgnoreNotFound(r.Client.Delete(ctx, &cm))
		}
		return reconcile.Result{}, nil
	}

	var certs, keys corev1.Secret
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.CertSecret}, &certs); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: bundle.SigningKeySecret}, &keys); err != nil {
		// The bundle builder creates the key; the Secret watch brings us
		// back.
		return reconcile.Result{RequeueAfter: 5 * time.Second}, client.IgnoreNotFound(err)
	}
	ca, pub, trusted := certs.Data["ca.crt"], keys.Data[bundle.PublicKeyKey], keys.Data[bundle.TrustedKeysKey]
	if len(trusted) == 0 {
		// Written by an operator older than key rotation: one key.
		trusted = pub
	}
	if len(ca) == 0 || len(pub) == 0 {
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	data := map[string]string{"ca.crt": string(ca)}
	// ed25519.pub, the active key, for engines older than key rotation;
	// trusted-keys.pub, every key engines must accept now.
	binary := map[string][]byte{bundle.PublicKeyKey: pub, bundle.TrustedKeysKey: trusted}
	if !exists {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: TrustConfigMap, Labels: managed()},
			Data:       data, BinaryData: binary,
		}
		if err := r.Client.Create(ctx, &cm); err != nil {
			return reconcile.Result{}, err
		}
		log.FromContext(ctx).Info("trust ConfigMap created", "namespace", namespace)
		return reconcile.Result{RequeueAfter: resync}, nil
	}
	if maps.Equal(cm.Data, data) && maps.EqualFunc(cm.BinaryData, binary, bytes.Equal) {
		return reconcile.Result{RequeueAfter: resync}, nil
	}
	cm.Data, cm.BinaryData = data, binary
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	maps.Copy(cm.Labels, managed())
	return reconcile.Result{RequeueAfter: resync}, r.Client.Update(ctx, &cm)
}

// reconcileGrant keeps one Role and RoleBinding in the operator's namespace
// that let every proxy pod's ServiceAccount get the bundle Secret.
func (r *Reconciler) reconcileGrant(ctx context.Context) error {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: r.Pods}); err != nil {
		return err
	}
	subjects := map[string]rbacv1.Subject{}
	for _, p := range pods.Items {
		sa := cmp.Or(p.Spec.ServiceAccountName, "default")
		subjects[p.Namespace+"/"+sa] = rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: p.Namespace, Name: sa}
	}
	sorted := slices.SortedFunc(maps.Values(subjects), func(a, b rbacv1.Subject) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.Namespace, Name: GrantName, Labels: managed()},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"},
			ResourceNames: []string{bundle.BundleSecret}, Verbs: []string{"get"},
		}},
	}
	if err := r.apply(ctx, role, func(cur client.Object) bool {
		c := cur.(*rbacv1.Role)
		if apiequality.Semantic.DeepEqual(c.Rules, role.Rules) {
			return false
		}
		c.Rules = role.Rules
		return true
	}); err != nil {
		return fmt.Errorf("role %s: %w", GrantName, err)
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.Namespace, Name: GrantName, Labels: managed()},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: GrantName},
		Subjects:   sorted,
	}
	return r.apply(ctx, binding, func(cur client.Object) bool {
		c := cur.(*rbacv1.RoleBinding)
		if apiequality.Semantic.DeepEqual(c.Subjects, binding.Subjects) {
			return false
		}
		c.Subjects = binding.Subjects
		return true
	})
}

// apply creates obj, or updates the existing one with update, which
// reports whether it changed anything.
func (r *Reconciler) apply(ctx context.Context, obj client.Object, update func(client.Object) bool) error {
	cur := obj.DeepCopyObject().(client.Object)
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(obj), cur)
	if apierrors.IsNotFound(err) {
		return r.Client.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	if !update(cur) {
		return nil
	}
	return r.Client.Update(ctx, cur)
}
