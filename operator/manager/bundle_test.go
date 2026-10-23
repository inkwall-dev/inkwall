// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/resolver"
)

// eventually retries cond until it returns "" or 20s pass.
func eventually(t *testing.T, what string, cond func() string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		msg := cond()
		if msg == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s", what, msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// current reads and verifies the published bundle.
func current(ctx context.Context, t *testing.T, c client.Client) *bundlev1.Bundle {
	t.Helper()
	var s corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
		return nil
	}
	signed, err := bundle.Decode(s.Data[bundle.BundleKey])
	if err != nil {
		t.Fatalf("bundle Secret: %v", err)
	}
	var key corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &key); err != nil {
		t.Fatalf("signing key Secret: %v", err)
	}
	pub := ed25519.PublicKey(key.Data[bundle.PublicKeyKey])
	if !ed25519.Verify(pub, signed.GetBundle(), signed.GetSignature()) {
		t.Fatal("the published bundle doesn't verify with the cluster's key")
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func findPolicy(b *bundlev1.Bundle, id string) *bundlev1.Policy {
	for _, p := range b.GetPolicies() {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

// testBundles follows a policy from creation to the bundle, through edits,
// a broken edit, the emergency switch and a deleted bundle Secret.
func testBundles(ctx context.Context, t *testing.T, c client.Client) {
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}); err != nil {
		t.Fatal(err)
	}
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "shop"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "shop.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "shop", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	rules := &wafv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "custom"},
		Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100001,phase:1,deny,status:403"`}},
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "shop"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "shop"}},
			Mode:       wafv1alpha1.PolicyBlock,
			RuleSets:   []wafv1alpha1.RuleSetBinding{{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "custom"}}},
		},
	}
	for _, o := range []client.Object{ing, rules, pol} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// The policy is published, with its route and rule set, and reports it.
	var v1 uint64
	eventually(t, "policy published", func() string {
		b := current(ctx, t, c)
		p := findPolicy(b, "shop/shop")
		if p == nil {
			return "not in the bundle"
		}
		if p.GetMode() != bundlev1.Mode_MODE_BLOCK || len(p.GetRoutes()) != 1 || p.GetRoutes()[0].GetHost() != "shop.example.com" {
			return "unexpected policy: " + p.String()
		}
		if len(b.GetRuleSets()) == 0 || b.GetClusterId() == "" {
			return "no rule sets or cluster ID"
		}
		v1 = b.GetVersion()
		return ""
	})
	wantPolicyStatus := func(what string, accepted metav1.ConditionStatus, reason string, version uint64) {
		t.Helper()
		eventually(t, what, func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &got); err != nil {
				return err.Error()
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionAccepted)
			switch {
			case cond == nil:
				return "no Accepted condition"
			case cond.Status != accepted || cond.Reason != reason:
				return "Accepted " + string(cond.Status) + " " + cond.Reason + ": " + cond.Message
			case got.Status.ObservedGeneration != got.Generation:
				return "observedGeneration not current"
			case uint64(got.Status.BundleVersion) != version: // #nosec G115
				return fmt.Sprintf("bundleVersion %d, want %d", got.Status.BundleVersion, version)
			}
			return ""
		})
	}
	wantPolicyStatus("accepted", metav1.ConditionTrue, resolver.ReasonAccepted, v1)

	// An edit publishes a new version.
	if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Mode = wafv1alpha1.PolicyDetect
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	var v2 uint64
	eventually(t, "edit published", func() string {
		b := current(ctx, t, c)
		if findPolicy(b, "shop/shop").GetMode() != bundlev1.Mode_MODE_DETECT {
			return "still in block mode"
		}
		v2 = b.GetVersion()
		return ""
	})
	if v2 <= v1 {
		t.Fatalf("version went from %d to %d", v1, v2)
	}
	wantPolicyStatus("edit reported", metav1.ConditionTrue, resolver.ReasonAccepted, v2)

	// A label change is not a new policy.
	if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
		t.Fatal(err)
	}
	pol.Labels = map[string]string{"team": "shop"}
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if v := current(ctx, t, c).GetVersion(); v != v2 {
		t.Fatalf("a label change published version %d", v)
	}

	// A broken edit (a missing rule set) leaves the previous version in
	// force.
	if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Mode = wafv1alpha1.PolicyBlock
	pol.Spec.RuleSets = append(pol.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "missing"}})
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	wantPolicyStatus("broken edit reported", metav1.ConditionFalse, resolver.ReasonInvalidRef, v2)
	if p := findPolicy(current(ctx, t, c), "shop/shop"); p.GetMode() != bundlev1.Mode_MODE_DETECT {
		t.Fatalf("the broken edit took effect: %v", p)
	}

	// Rules from a ConfigMap: reported until the ConfigMap is labeled.
	cmRules := &wafv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "from-configmap"},
		Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{ConfigMapRef: &wafv1alpha1.ConfigMapKeyRef{Name: "rules", Key: "rules.conf"}}},
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "rules"}, Data: map[string]string{"rules.conf": "SecRuleEngine Off"}}
	for _, o := range []client.Object{cm, cmRules} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	wantRuleSetReason := func(what, reason, msg string) {
		t.Helper()
		eventually(t, what, func() string {
			var got wafv1alpha1.WAFRuleSet
			if err := c.Get(ctx, client.ObjectKeyFromObject(cmRules), &got); err != nil {
				return err.Error()
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionAccepted)
			if cond == nil || cond.Reason != reason || !strings.Contains(cond.Message, msg) {
				return "condition " + func() string {
					if cond == nil {
						return "missing"
					}
					return cond.Reason + ": " + cond.Message
				}()
			}
			return ""
		})
	}
	wantRuleSetReason("unlabeled ConfigMap", resolver.ReasonInvalidRef, "not labeled "+resolver.RulesLabel)
	cm.Labels = map[string]string{resolver.RulesLabel: "true"}
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	wantRuleSetReason("ConfigMap rules checked", resolver.ReasonRuleCompileError, `directive "secruleengine" is not allowed`)

	// The emergency switch.
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wafv1alpha1.InkwallConfigSpec{Suspend: true}}
	if err := c.Create(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	eventually(t, "suspended", func() string {
		if !current(ctx, t, c).GetSuspended() {
			return "not suspended"
		}
		return ""
	})

	// A deleted bundle Secret is recreated, and the version sequence goes on.
	before := current(ctx, t, c).GetVersion()
	if err := c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: bundle.BundleSecret}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bundle Secret recreated", func() string {
		b := current(ctx, t, c)
		if b == nil {
			return "missing"
		}
		if b.GetVersion() <= before {
			return "version did not go on"
		}
		return ""
	})
}
