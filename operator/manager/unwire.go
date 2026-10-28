// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// Unwire runs at uninstall (the chart's pre-delete hook): it stops the
// operator, lets proxy pods start without the Pod webhook, and undoes the
// wiring, so the routes keep working, uninspected, once Inkwall is gone.
// WAFPolicy objects are kept, without the operator's finalizer, so deleting
// them (or their namespace) doesn't wait for an operator that is gone.
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
	logger.Info("routes unwired", slog.Int("ingresses", n.Ingresses), slog.Int("ingressroutes", n.IngressRoutes),
		slog.Int("middlewares", n.Middlewares), slog.Int("policies", n.Policies))
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
