// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// Unwire runs at uninstall (the chart's pre-delete hook): it stops the
// operator, lets proxy pods start without the Pod webhook, and undoes the
// wiring, so the routes keep working, uninspected, once Inkwall is gone.
// WAFPolicy objects are kept, without the operator's finalizer, so deleting
// them (or their namespace) doesn't wait for an operator that is gone. Last,
// it deletes what the operator created for itself and the engines outside
// the chart: the trust ConfigMaps in the proxy namespaces, the bundle grant,
// the engine reports and the leader Lease. The bundle Secrets are kept.
func Unwire(ctx context.Context, c client.Client, namespace, deployment string, logger *slog.Logger) error {
	// 1. Stop the operator: running, it would wire the routes again. A
	// draining replica still runs its controllers, so wait for its pods.
	var d appsv1.Deployment
	switch err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: deployment}, &d); {
	case apierrors.IsNotFound(err):
	case err != nil:
		return fmt.Errorf("get Deployment %s/%s: %w", namespace, deployment, err)
	default:
		patch := client.MergeFrom(d.DeepCopy())
		zero := int32(0)
		d.Spec.Replicas = &zero
		if err := c.Patch(ctx, &d, patch); err != nil {
			return fmt.Errorf("scale %s/%s to 0: %w", namespace, deployment, err)
		}
		sel, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
		if err != nil {
			return err
		}
		for {
			var pods corev1.PodList
			if err := c.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
				return fmt.Errorf("list the operator's pods: %w", err)
			}
			if len(pods.Items) == 0 {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("the operator's pods didn't stop: %w", ctx.Err())
			case <-time.After(time.Second):
			}
		}
		logger.Info("operator stopped", slog.String("deployment", namespace+"/"+deployment))
	}

	// 2. Proxy pods must be able to start until the chart deletes the Pod
	// webhook, which no replica answers any more; and the WAFPolicy
	// webhook mustn't refuse removing their finalizer.
	if err := ignorePodWebhook(ctx, c); err != nil {
		return err
	}
	if err := ignorePolicyWebhook(ctx, c); err != nil {
		return err
	}

	// 3. The routes stop going through the engine, and the policies are
	// released.
	n, err := wiring.Unwire(ctx, c)
	if err != nil {
		return err
	}
	attrs := []any{slog.Int("policies", n.Policies)}
	for _, kind := range slices.Sorted(maps.Keys(n.Objects)) {
		key := strings.ToLower(kind) + "s" // ingressroutes
		if strings.HasSuffix(kind, "s") {
			key = strings.ToLower(kind) + "es" // ingresses
		}
		attrs = append(attrs, slog.Int(key, n.Objects[kind]))
	}
	logger.Info("routes unwired", attrs...)
	for _, name := range n.Forbidden {
		logger.Warn("integration not unwired: the operator may not change its objects (its ClusterRole isn't granted)", slog.String("integration", name))
	}

	// 4. What the operator created besides: running engines keep their
	// files and their last bundle, and proxy pods started now don't get the
	// engine, so nothing reads these any more.
	return cleanUp(ctx, c, namespace, logger)
}

// managedBy labels what the operator creates.
var managedBy = client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}

// cleanUp deletes the trust ConfigMaps (the operator's, labelled, in any
// namespace: a user's own is kept), the engine reports, the bundle grant
// and the leader Lease.
func cleanUp(ctx context.Context, c client.Client, namespace string, logger *slog.Logger) error {
	var cms corev1.ConfigMapList
	if err := c.List(ctx, &cms, managedBy); err != nil {
		return fmt.Errorf("list the operator's ConfigMaps: %w", err)
	}
	trust := 0
	for i := range cms.Items {
		cm := &cms.Items[i]
		_, report := cm.Labels[distribution.EnginesLabel]
		switch {
		case cm.Name == injection.TrustConfigMap:
			trust++
		case report && cm.Namespace == namespace:
		default:
			continue
		}
		if err := c.Delete(ctx, cm); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete ConfigMap %s/%s: %w", cm.Namespace, cm.Name, err)
		}
	}
	for _, o := range []struct {
		kind string
		obj  client.Object
	}{
		{"RoleBinding", &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: injection.GrantName}}},
		{"Role", &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: injection.GrantName}}},
		{"Lease", &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: leaderElectionID}}},
	} {
		// The chart's hook Role grants deleting the grant; without it (a
		// chart of its own), a leftover mustn't stop the uninstall.
		switch err := c.Delete(ctx, o.obj); {
		case apierrors.IsForbidden(err):
			logger.Warn("not deleted: the operator may not delete it", slog.String("kind", o.kind),
				slog.String("name", namespace+"/"+o.obj.GetName()))
		case client.IgnoreNotFound(err) != nil:
			return fmt.Errorf("delete %s %s/%s: %w", o.kind, namespace, o.obj.GetName(), err)
		}
	}
	logger.Info("the operator's objects deleted", slog.Int("trustConfigMaps", trust),
		slog.String("grant", namespace+"/"+injection.GrantName), slog.String("lease", namespace+"/"+leaderElectionID))
	return nil
}

func ignorePodWebhook(ctx context.Context, c client.Client) error {
	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	switch err := c.Get(ctx, types.NamespacedName{Name: webhook.MutatingConfigName}, &cfg); {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get the Pod webhook: %w", err)
	}
	patch := client.MergeFrom(cfg.DeepCopy())
	for i := range cfg.Webhooks {
		if cfg.Webhooks[i].Name == webhook.PodWebhookName {
			cfg.Webhooks[i].FailurePolicy = ptr.To(admissionregistrationv1.Ignore)
		}
	}
	if err := c.Patch(ctx, &cfg, patch); err != nil {
		return fmt.Errorf("set the Pod webhook to Ignore: %w", err)
	}
	return nil
}

func ignorePolicyWebhook(ctx context.Context, c client.Client) error {
	var cfg admissionregistrationv1.ValidatingWebhookConfiguration
	switch err := c.Get(ctx, types.NamespacedName{Name: webhook.ValidatingConfigName}, &cfg); {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get the WAFPolicy webhook: %w", err)
	}
	patch := client.MergeFrom(cfg.DeepCopy())
	for i := range cfg.Webhooks {
		if cfg.Webhooks[i].Name == webhook.PolicyWebhookName {
			cfg.Webhooks[i].FailurePolicy = ptr.To(admissionregistrationv1.Ignore)
		}
	}
	if err := c.Patch(ctx, &cfg, patch); err != nil {
		return fmt.Errorf("set the WAFPolicy webhook to Ignore: %w", err)
	}
	return nil
}
