// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// testBundleChunks publishes a bundle too large for one Secret: it is split
// into chunks, a new engine reads them from the API server with the grant
// injection gives, and once the bundle fits again the chunks are deleted.
func testBundleChunks(ctx context.Context, t *testing.T, c client.Client) {
	// Rule sets of random comments: about 190 KiB each, compressed.
	const ruleSets = 6
	var objs []client.Object
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: "big"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "big"}},
			Mode:       wafv1alpha1.PolicyDetect,
		},
	}
	for i := range ruleSets {
		name := fmt.Sprintf("noise-%d", i)
		objs = append(objs, &wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: noiseRules(t, 250<<10)}},
		})
		pol.Spec.RuleSets = append(pol.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
	}
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: "big"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "big.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "big", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	objs = append([]client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "big"}}, ing}, append(objs, pol)...)
	for _, o := range objs {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	var version uint64
	eventually(t, "the bundle published in chunks", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		if s.Data[bundle.ManifestKey] == nil || s.Data[bundle.BundleKey] != nil {
			return "not in chunks"
		}
		b := current(ctx, t, c)
		if findPolicy(b, "big/big") == nil {
			return "big/big not in the bundle"
		}
		version = b.GetVersion()
		return ""
	})
	if n := len(chunkSecrets(ctx, t, c)); n < 2 {
		t.Fatalf("%d chunk Secrets, want 2 or more", n)
	}

	// A new engine, the operator unreachable, reads the chunks with what
	// injection grants (the inkwall-bundle-reader Role).
	for _, o := range []client.Object{
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "chunk-reader"},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
				ResourceNames: append([]string{bundle.BundleSecret}, bundlesecret.ChunkNames(bundle.BundleSecret)...)}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "chunk-reader"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "chunk-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "edge", Name: "traefik"}},
		},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var keys corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"ed25519.pub": keys.Data[bundle.PublicKeyKey],
		"kube-token":  []byte(apiToken(ctx, t, "edge", "traefik")),
		"kube-ca.crt": env.Config.CAData,
		"ca.crt":      env.Config.CAData,
		"token":       []byte("unused"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	holder := &policy.Holder{}
	adm := pipeline.NewAdmission(4)
	a, err := agent.New(agent.Config{
		Addr:          "127.0.0.1:1",
		CAFile:        filepath.Join(dir, "ca.crt"),
		TokenFile:     filepath.Join(dir, "token"),
		PublicKeyFile: filepath.Join(dir, "ed25519.pub"),
		Secret: &agent.SecretSource{Namespace: "default", Name: bundle.BundleSecret, APIServer: env.Config.Host,
			CAFile: filepath.Join(dir, "kube-ca.crt"), TokenFile: filepath.Join(dir, "kube-token")},
		EngineID: "cold-engine",
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			return policy.Compile(b, policy.Options{Admission: adm, BodyLimit: 65536})
		},
		Holder:    holder,
		Admission: adm,
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(actx); close(done) }()
	eventually(t, "the engine applies the chunked bundle", func() string {
		if v := a.Version(); v != version {
			return fmt.Sprintf("version %d, want %d", v, version)
		}
		return ""
	})
	cancel()
	<-done

	// A deleted chunk: the bundle is published again, as a new version.
	chunks := chunkSecrets(ctx, t, c)
	if err := c.Delete(ctx, &chunks[len(chunks)-1]); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the bundle published again", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		signed, err := bundle.Read(ctx, c, &s)
		if err != nil {
			return err.Error()
		}
		var b bundlev1.Bundle
		if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil || b.GetVersion() <= version || findPolicy(&b, "big/big") == nil {
			return fmt.Sprintf("version %d, %v", b.GetVersion(), err)
		}
		return ""
	})

	// Small again: one Secret, the chunks deleted.
	for _, o := range objs[1:] {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the chunks deleted", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		if s.Data[bundle.BundleKey] == nil {
			return "not in one Secret"
		}
		if n := len(chunkSecrets(ctx, t, c)); n != 0 {
			return fmt.Sprintf("%d chunk Secrets left", n)
		}
		return ""
	})
}

// noiseRules returns SecLang comments of n random bytes, which don't
// compress.
func noiseRules(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n*3/4)
	_, _ = rand.Read(raw)
	enc := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	for len(enc) > 0 {
		k := min(len(enc), 100)
		b.WriteString("# " + enc[:k] + "\n")
		enc = enc[k:]
	}
	return b.String()[:min(b.Len(), n)]
}

func chunkSecrets(ctx context.Context, t *testing.T, c client.Client) []corev1.Secret {
	t.Helper()
	var l corev1.SecretList
	if err := c.List(ctx, &l, client.InNamespace("default"), client.MatchingLabels{bundle.ChunkLabel: bundle.BundleSecret}); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

// apiToken issues a ServiceAccount token for the API server, as the
// engine's second projected token.
func apiToken(ctx context.Context, t *testing.T, namespace, sa string) string {
	t.Helper()
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return tr.Status.Token
}

// testBundleTooLarge grows a policy until the bundle no longer fits its
// Secrets: the bundle isn't published, and the policy says so instead of
// keeping the status of the spec engines still run (#264). Shrunk, it is
// published and Accepted again.
func testBundleTooLarge(ctx context.Context, t *testing.T, c client.Client) {
	// Rule sets of random comments, about 195 KiB compressed each: 4
	// policies of 8 fit (in chunks), a fifth's 8 more don't.
	const (
		perPolicy = 8
		fillers   = 4
	)
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "huge"}}); err != nil {
		t.Fatal(err)
	}
	// Small again before the next test, even if this one fails half way
	// (#304): its engines would get this bundle, megabytes of rules, tests
	// that count chunks would see these, and a bundle left too large would
	// keep every later policy change from being published.
	t.Cleanup(func() {
		cfg := &wafv1alpha1.InkwallConfig{}
		if err := c.Get(ctx, client.ObjectKey{Name: "default"}, cfg); err == nil && cfg.Spec.Suspend {
			update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) { cfg.Spec.Suspend = false })
		}
		for _, o := range []client.Object{&wafv1alpha1.WAFPolicy{}, &wafv1alpha1.WAFRuleSet{}, &networkingv1.Ingress{}} {
			if err := c.DeleteAllOf(ctx, o, client.InNamespace("huge")); err != nil {
				t.Fatal(err)
			}
		}
		eventually(t, "the bundle small again", func() string {
			var s corev1.Secret
			if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
				return err.Error()
			}
			if s.Data[bundle.BundleKey] == nil {
				return "not in one Secret"
			}
			if n := len(chunkSecrets(ctx, t, c)); n != 0 {
				return fmt.Sprintf("%d chunk Secrets left", n)
			}
			return ""
		})
	})
	prefix := networkingv1.PathTypePrefix
	ruleSets := func(p *wafv1alpha1.WAFPolicy, from int) {
		p.Spec.RuleSets = nil
		for i := range perPolicy {
			name := fmt.Sprintf("noise-%d", from+i)
			p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
		}
	}
	newPolicy := func(name string) *wafv1alpha1.WAFPolicy {
		ing := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "huge", Name: name},
			Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
				Host: name + ".example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
					Path: "/", PathType: &prefix,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}}},
				}}}},
			}}},
		}
		if err := c.Create(ctx, ing); err != nil {
			t.Fatal(err)
		}
		return &wafv1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "huge", Name: name},
			Spec: wafv1alpha1.WAFPolicySpec{
				TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: name}},
				Mode:       wafv1alpha1.PolicyDetect,
			},
		}
	}
	for i := range (fillers + 1) * perPolicy {
		rs := &wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "huge", Name: fmt.Sprintf("noise-%d", i)},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: noiseRules(t, 256<<10)}},
		}
		if err := c.Create(ctx, rs); err != nil {
			t.Fatal(err)
		}
	}
	for i := range fillers {
		p := newPolicy(fmt.Sprintf("filler-%d", i))
		ruleSets(p, i*perPolicy)
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	grown := newPolicy("grown")
	if err := c.Create(ctx, grown); err != nil {
		t.Fatal(err)
	}
	// Ready has Accepted's reason, unless inspection is suspended.
	wantConditions := func(what, name string, st metav1.ConditionStatus, reason, ready string) {
		t.Helper()
		eventually(t, what, func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, types.NamespacedName{Namespace: "huge", Name: name}, &got); err != nil {
				return err.Error()
			}
			for _, typ := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionReady} {
				cond := meta.FindStatusCondition(got.Status.Conditions, typ)
				want, wantReason := st, reason
				if typ == wafv1alpha1.ConditionReady {
					if ready == "" {
						continue // no engine: never Ready
					}
					want, wantReason = metav1.ConditionFalse, ready
				}
				if cond == nil || cond.Status != want || cond.Reason != wantReason || cond.ObservedGeneration != got.Generation {
					return fmt.Sprintf("generation %d: %s %+v, want %s %s", got.Generation, typ, cond, want, wantReason)
				}
			}
			return ""
		})
	}
	wantAccepted := func(what, name string, st metav1.ConditionStatus, reason string) {
		t.Helper()
		ready := ""
		if st != metav1.ConditionTrue {
			ready = reason
		}
		wantConditions(what, name, st, reason, ready)
	}
	wantAccepted("the policy published", "grown", metav1.ConditionTrue, "Accepted")
	var before uint64
	eventually(t, "the fillers published", func() string {
		b := current(ctx, t, c)
		for i := range fillers {
			if findPolicy(b, fmt.Sprintf("huge/filler-%d", i)) == nil {
				return fmt.Sprintf("huge/filler-%d not in bundle %d", i, b.GetVersion())
			}
		}
		before = b.GetVersion()
		return ""
	})

	// Grown past the limit: not published, and reported.
	update(ctx, t, c, grown, func(p *wafv1alpha1.WAFPolicy) { ruleSets(p, fillers*perPolicy) })
	wantAccepted("the grown policy", "grown", metav1.ConditionFalse, "BundleTooLarge")
	if b := current(ctx, t, c); b.GetVersion() != before || len(findPolicy(b, "huge/grown").GetRuleSets()) != 0 {
		t.Fatalf("bundle %d published, want %d without the grown policy's rule sets", b.GetVersion(), before)
	}
	// The other policies run as they are: their status stays.
	wantAccepted("a filler, unchanged", "filler-0", metav1.ConditionTrue, "Accepted")

	// Suspended, the switch works all the same (#291): the bundle in force
	// is published again with inspection suspended, and fits as it did;
	// suspension is Ready's reason. Resumed, the bundle in force runs
	// again, without the grown policy's change, which is still not
	// Accepted.
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); apierrors.IsNotFound(err) {
		if err := c.Create(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	wantSuspended := func(what string, st metav1.ConditionStatus) {
		t.Helper()
		eventually(t, what, func() string {
			b := current(ctx, t, c)
			if b.GetSuspended() != (st == metav1.ConditionTrue) || b.GetVersion() <= before {
				return fmt.Sprintf("bundle %d: suspended %t", b.GetVersion(), b.GetSuspended())
			}
			if len(findPolicy(b, "huge/grown").GetRuleSets()) != 0 || len(findPolicy(b, "huge/filler-0").GetRuleSets()) != perPolicy {
				return fmt.Sprintf("bundle %d isn't the one in force", b.GetVersion())
			}
			var got wafv1alpha1.InkwallConfig
			if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), &got); err != nil {
				return err.Error()
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionSuspended)
			if cond == nil || cond.Status != st || cond.ObservedGeneration != got.Generation || strings.Contains(cond.Message, "couldn't be published") {
				return fmt.Sprintf("InkwallConfig Suspended condition %+v, want %s", cond, st)
			}
			before = b.GetVersion()
			return ""
		})
	}
	update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) { cfg.Spec.Suspend = true })
	wantSuspended("suspended", metav1.ConditionTrue)
	wantConditions("the grown policy, suspended", "grown", metav1.ConditionFalse, "BundleTooLarge", "Suspended")
	wantConditions("a filler, suspended", "filler-0", metav1.ConditionTrue, "Accepted", "Suspended")
	update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) { cfg.Spec.Suspend = false })
	wantSuspended("resumed", metav1.ConditionFalse)
	wantAccepted("the grown policy, resumed", "grown", metav1.ConditionFalse, "BundleTooLarge")
	wantAccepted("a filler, resumed", "filler-0", metav1.ConditionTrue, "Accepted")

	// Shrunk: published again.
	update(ctx, t, c, grown, func(p *wafv1alpha1.WAFPolicy) { p.Spec.RuleSets = p.Spec.RuleSets[:1] })
	wantAccepted("the shrunk policy", "grown", metav1.ConditionTrue, "Accepted")
	eventually(t, "the shrunk policy published", func() string {
		if n := len(findPolicy(current(ctx, t, c), "huge/grown").GetRuleSets()); n != 1 {
			return fmt.Sprintf("%d rule sets", n)
		}
		return ""
	})

}
