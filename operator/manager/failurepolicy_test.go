// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// testFailurePolicy checks that the Pod webhook fails closed exactly while
// a policy is in block mode, and that a reset (a Helm upgrade) is undone.
func testFailurePolicy(ctx context.Context, t *testing.T, c client.Client) {
	podWebhook := func() (*admissionregistrationv1.MutatingWebhookConfiguration, *admissionregistrationv1.MutatingWebhook) {
		var cfg admissionregistrationv1.MutatingWebhookConfiguration
		if err := c.Get(ctx, types.NamespacedName{Name: webhook.MutatingConfigName}, &cfg); err != nil {
			t.Fatal(err)
		}
		for i := range cfg.Webhooks {
			if cfg.Webhooks[i].Name == webhook.PodWebhookName {
				return &cfg, &cfg.Webhooks[i]
			}
		}
		t.Fatalf("no webhook %s", webhook.PodWebhookName)
		return nil, nil
	}
	wantPolicy := func(what string, want admissionregistrationv1.FailurePolicyType) {
		t.Helper()
		eventually(t, what, func() string {
			_, wh := podWebhook()
			if wh.FailurePolicy == nil || *wh.FailurePolicy != want {
				return "failurePolicy is " + string(*wh.FailurePolicy)
			}
			return ""
		})
	}
	setModes := func(from, to wafv1alpha1.PolicyMode) []wafv1alpha1.WAFPolicy {
		var list wafv1alpha1.WAFPolicyList
		if err := c.List(ctx, &list); err != nil {
			t.Fatal(err)
		}
		var changed []wafv1alpha1.WAFPolicy
		for i := range list.Items {
			p := &list.Items[i]
			if p.Spec.Mode != from {
				continue
			}
			update(ctx, t, c, p, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = to })
			changed = append(changed, *p)
		}
		return changed
	}

	// The earlier checks left web/web in block mode.
	wantPolicy("Fail with a policy in block mode", admissionregistrationv1.Fail)

	// Reset as a Helm upgrade would: set back to Fail.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cfg, wh := podWebhook()
		ignore := admissionregistrationv1.Ignore
		wh.FailurePolicy = &ignore
		return c.Update(ctx, cfg)
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy("Fail again after a reset", admissionregistrationv1.Fail)

	blocking := setModes(wafv1alpha1.PolicyBlock, wafv1alpha1.PolicyDetect)
	if len(blocking) == 0 {
		t.Fatal("no policy in block mode")
	}
	wantPolicy("Ignore with every policy in detect mode", admissionregistrationv1.Ignore)
	setModes(wafv1alpha1.PolicyDetect, wafv1alpha1.PolicyBlock)
	wantPolicy("Fail once a policy blocks again", admissionregistrationv1.Fail)

	// The CA bundle survives the changes, and the selector keeps the way
	// out: pods labeled waf.inkwall.dev/inject: "false" skip the webhook.
	_, wh := podWebhook()
	if len(wh.ClientConfig.CABundle) == 0 {
		t.Error("the CA bundle was lost")
	}
	sel, err := metav1.LabelSelectorAsSelector(wh.ObjectSelector)
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Matches(labels.Set{"app.kubernetes.io/name": "traefik"}) ||
		sel.Matches(labels.Set{"app.kubernetes.io/name": "traefik", injection.InjectLabel: "false"}) {
		t.Errorf("objectSelector %s", sel)
	}
}
