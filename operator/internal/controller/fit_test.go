// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

// noise is n bytes of SecLang comments that don't compress much: random
// hex digits, which gzip compresses at a steady ratio (about 0.55)
// wherever they are in the bundle. Base64 text's ratio, alone or next to
// more of it, differs by tens of KiB (Go's deflate), more than the margins
// of a small test.
func noise(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n/2)
	_, _ = rand.Read(raw)
	enc := hex.EncodeToString(raw)
	var b strings.Builder
	for len(enc) > 0 {
		k := min(len(enc), 100)
		b.WriteString("# " + enc[:k] + "\n")
		enc = enc[k:]
	}
	return b.String()[:min(b.Len(), n)]
}

type fitCluster struct {
	t   *testing.T
	ctx context.Context
	c   client.Client
	r   *BundleReconciler
	// lim are the limits the builder fits the bundle to: the Secrets',
	// divided by scale.
	lim   fitLimits
	scale int
}

// newFitCluster is a cluster whose bundle is fitted to the Secrets' limits,
// divided by scale.
func newFitCluster(t *testing.T, scale int) *fitCluster {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}).
		WithStatusSubresource(&wafv1alpha1.WAFPolicy{}, &wafv1alpha1.WAFRuleSet{}, &wafv1alpha1.ClusterWAFRuleSet{},
			&wafv1alpha1.WAFIPList{}, &wafv1alpha1.InkwallConfig{}).Build()
	now := time.Unix(1_800_000_000, 0)
	r := &BundleReconciler{Client: c, APIReader: c, Namespace: "inkwall-system", Now: func() time.Time { return now },
		checked: map[[sha256.Size]byte]error{}}
	lim := fitLimits{raw: secretLimits.raw / scale, gz: secretLimits.gz / scale, slack: secretLimits.slack / scale}
	r.fitOptions.limits = lim
	f := &fitCluster{t: t, ctx: context.Background(), c: c, r: r, lim: lim, scale: scale}
	held := f
	t.Cleanup(func() {
		if t.Failed() {
			// What the sizes were, for a failure that a size off by a few
			// percent explains (review 8, B).
			t.Logf("noise ratio %.4f; the published bundle takes %d bytes compressed of %d (%d free, %d%%)", noiseRatio.r,
				held.r.current.Size(), held.lim.gz, held.head(), 100*held.head()/held.lim.gz)
		}
		// The testing package keeps the cleanups it ran: don't keep the
		// cluster with them.
		held = nil
	})
	// Without the cluster reserve, so that the scenarios fill the bundle
	// to their limits; those of the reserve set it (f.reserve).
	f.reserve(new(int32))
	return f
}

// sz is n bytes at the cluster's scale.
func (f *fitCluster) sz(n int) int { return n / f.scale }

// smallScale divides the limits, and the sizes, of a bundle size test's
// small run.
const smallScale = 16

// sizeTest runs a bundle size scenario twice: small, with the limits and
// the sizes in it (f.sz) a smallScale-th of the Secrets', always; and at
// full size, but not with -short or the race detector, under which the
// full size tests take minutes. raw: the full run builds a 64 MiB bundle.
func sizeTest(t *testing.T, raw bool, scenario func(t *testing.T, f *fitCluster)) {
	t.Helper()
	t.Parallel()
	for _, scale := range []int{smallScale, 1} {
		name := "small"
		if scale == 1 {
			name = "full"
		}
		t.Run(name, func(t *testing.T) {
			if scale == 1 && (testing.Short() || raceDetector) {
				t.Skip("full size: run without -short and -race")
			}
			if raw && scale == 1 {
				parallelRaw(t)
			} else {
				parallel(t)
			}
			scenario(t, newFitCluster(t, scale))
		})
	}
}

// tenant adds an Ingress and a policy on it in namespace ns.
func (f *fitCluster) tenant(ns, name string, ruleSets ...string) {
	f.t.Helper()
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: name + "." + ns + ".example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 1},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: name}},
			Mode:       wafv1alpha1.PolicyDetect,
		},
	}
	for _, rs := range ruleSets {
		ref := wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: rs}
		if name, ok := strings.CutPrefix(rs, "cluster:"); ok {
			ref = wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: name}
		}
		p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: ref})
	}
	for _, o := range []client.Object{ing, p} {
		if err := f.c.Create(f.ctx, o); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fitCluster) ruleSet(ns, name, rules string) {
	f.t.Helper()
	rs := &wafv1alpha1.WAFRuleSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	err := f.c.Get(f.ctx, client.ObjectKeyFromObject(rs), rs)
	rs.Spec.Source = wafv1alpha1.RuleSetSource{SecLang: rules}
	rs.Generation++
	if err == nil {
		err = f.c.Update(f.ctx, rs)
	} else {
		err = f.c.Create(f.ctx, rs)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fitCluster) clusterRuleSet(name, rules string) {
	f.t.Helper()
	rs := &wafv1alpha1.ClusterWAFRuleSet{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := f.c.Get(f.ctx, client.ObjectKeyFromObject(rs), rs)
	rs.Spec.Source = wafv1alpha1.ClusterRuleSetSource{SecLang: rules}
	rs.Generation++
	if err == nil {
		err = f.c.Update(f.ctx, rs)
	} else {
		err = f.c.Create(f.ctx, rs)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

// ruleSetAccepted is the Accepted condition of a WAFRuleSet, or of a
// ClusterWAFRuleSet when ns is "".
func (f *fitCluster) ruleSetAccepted(ns, name string) *metav1.Condition {
	f.t.Helper()
	var obj client.Object = &wafv1alpha1.WAFRuleSet{}
	if ns == "" {
		obj = &wafv1alpha1.ClusterWAFRuleSet{}
	}
	if err := f.c.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		f.t.Fatal(err)
	}
	var conds []metav1.Condition
	switch rs := obj.(type) {
	case *wafv1alpha1.WAFRuleSet:
		conds = rs.Status.Conditions
	case *wafv1alpha1.ClusterWAFRuleSet:
		conds = rs.Status.Conditions
	}
	cond := meta.FindStatusCondition(conds, wafv1alpha1.ConditionAccepted)
	if cond == nil || cond.ObservedGeneration != obj.GetGeneration() {
		f.t.Fatalf("rule set %s/%s: Accepted %+v, not for generation %d", ns, name, cond, obj.GetGeneration())
	}
	return cond
}

func (f *fitCluster) ruleSetHeld(ns, name string) bool {
	f.t.Helper()
	cond := f.ruleSetAccepted(ns, name)
	return cond.Status == metav1.ConditionFalse && cond.Reason == ReasonBundleTooLarge
}

func (f *fitCluster) wantRuleSetHeld(ns, name, msg string) {
	f.t.Helper()
	if cond := f.ruleSetAccepted(ns, name); !f.ruleSetHeld(ns, name) || !strings.Contains(cond.Message, msg) {
		f.t.Errorf("rule set %s/%s: Accepted %+v, want False, BundleTooLarge, with %q", ns, name, cond, msg)
	}
}

func (f *fitCluster) wantRuleSetAccepted(ns, name string) {
	f.t.Helper()
	if cond := f.ruleSetAccepted(ns, name); cond.Status != metav1.ConditionTrue {
		f.t.Errorf("rule set %s/%s: Accepted %+v, want True", ns, name, cond)
	}
}

// head is the room left in the published bundle, compressed: measured as
// stored, since gzip's output for random text moves by tens of kilobytes
// in 7 MiB with a few bytes more. The tests leave margins well over that.
func (f *fitCluster) head() int { return f.lim.gz - f.r.current.Size() }

// topUp adds noise to ns's rule set name, rules as published, building
// after each, until the published bundle leaves head bytes free, within
// tol bytes over, and returns the rules: a size test aims by what it
// measures, not by the noise ratio alone (review 8, B: once, every size of
// a test binary came out about 5% short).
func (f *fitCluster) topUp(ns, name, rules string, head int) string {
	f.t.Helper()
	tol := f.sz(64 << 10)
	for range 4 {
		h := f.head()
		if h < head-tol {
			f.t.Fatalf("the bundle leaves %d bytes free, want %d: aimed over (noise ratio %.4f)", h, head, noiseRatio.r)
		}
		if h <= head+tol {
			return rules
		}
		rules += noiseFor(f.t, h-head)
		f.ruleSet(ns, name, rules)
		f.build()
	}
	f.t.Fatalf("the bundle leaves %d bytes free after 4 top-ups, want %d (noise ratio %.4f)", f.head(), head, noiseRatio.r)
	return ""
}

// noiseFor is noise that adds about n bytes compressed: noise compresses
// at a steady ratio, measured once.
func noiseFor(t *testing.T, n int) string {
	t.Helper()
	noiseRatio.Do(func() {
		s := noise(t, 1<<20)
		noiseRatio.r = float64(gzSize(&bundlev1.RuleSet{Source: &bundlev1.RuleSet_Seclang{Seclang: s}})) / float64(len(s))
	})
	return noise(t, int(float64(n)/noiseRatio.r))
}

var noiseRatio struct {
	sync.Once
	r float64
}

// edit changes a policy's spec, as a new generation.
func (f *fitCluster) edit(ns, name string, mutate func(*wafv1alpha1.WAFPolicy)) {
	f.t.Helper()
	var p wafv1alpha1.WAFPolicy
	if err := f.c.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		f.t.Fatal(err)
	}
	mutate(&p)
	p.Generation++
	if err := f.c.Update(f.ctx, &p); err != nil {
		f.t.Fatal(err)
	}
}

// build runs a build and returns the published bundle.
func (f *fitCluster) build() *bundlev1.Bundle {
	f.t.Helper()
	if _, err := f.r.Reconcile(f.ctx, reconcile.Request{}); err != nil {
		f.t.Fatal(err)
	}
	b, _, err := bundle.Load(f.ctx, f.c, f.r.Namespace)
	if err != nil || b == nil {
		f.t.Fatalf("published bundle: %v %v", b, err)
	}
	return b
}

func (f *fitCluster) accepted(ns, name string) *metav1.Condition {
	f.t.Helper()
	var p wafv1alpha1.WAFPolicy
	if err := f.c.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		f.t.Fatal(err)
	}
	cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionAccepted)
	if cond == nil || cond.ObservedGeneration != p.Generation {
		f.t.Fatalf("%s/%s: Accepted %+v, not for generation %d", ns, name, cond, p.Generation)
	}
	return cond
}

func (f *fitCluster) wantAccepted(ns, name string) {
	f.t.Helper()
	if cond := f.accepted(ns, name); cond.Status != metav1.ConditionTrue {
		f.t.Errorf("%s/%s: Accepted %+v, want True", ns, name, cond)
	}
}

func (f *fitCluster) wantHeld(ns, name, msg string) {
	f.t.Helper()
	cond := f.accepted(ns, name)
	if cond.Status != metav1.ConditionFalse || cond.Reason != ReasonBundleTooLarge || !strings.Contains(cond.Message, msg) {
		f.t.Errorf("%s/%s: Accepted %+v, want False, BundleTooLarge, with %q", ns, name, cond, msg)
	}
}

func bundlePolicy(b *bundlev1.Bundle, id string) *bundlev1.Policy {
	for _, p := range b.GetPolicies() {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

func bundleRuleSet(b *bundlev1.Bundle, id string) *bundlev1.RuleSet {
	for _, rs := range b.GetRuleSets() {
		if rs.GetId() == id {
			return rs
		}
	}
	return nil
}

// fitSlots bounds the bundle size tests that run at once: each holds
// megabytes of rules at full size, and the race detector multiplies that,
// but under it only the small runs run (sizeTest), so more of them can;
// rawSlot lets one of those that build 64 MiB bundles run at a time.
var fitSlots, rawSlot = make(chan struct{}, 3+3*btoi(raceDetector)), make(chan struct{}, 1)

// parallel runs a bundle size test's run in parallel with the others, at
// most cap(fitSlots) at once.
func parallel(t *testing.T) {
	t.Helper()
	t.Parallel()
	fitSlots <- struct{}{}
	t.Cleanup(func() { <-fitSlots })
}

// parallelRaw is parallel for a test that builds a 64 MiB bundle.
func parallelRaw(t *testing.T) {
	t.Helper()
	parallel(t)
	rawSlot <- struct{}{}
	t.Cleanup(func() { <-rawSlot })
}

// gzSize is m's size marshaled and compressed.
func gzSize(m proto.Message) int {
	raw, _ := proto.Marshal(m)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return b.Len()
}

// share sets the InkwallConfig's spec.bundle.namespaceShare.
func (f *fitCluster) share(pct int32) {
	f.t.Helper()
	f.config(func(b *wafv1alpha1.BundleSpec) { b.NamespaceShare = pct })
}

// reserve sets the InkwallConfig's spec.bundle.clusterReserve; nil: its
// default.
func (f *fitCluster) reserve(pct *int32) {
	f.t.Helper()
	f.config(func(b *wafv1alpha1.BundleSpec) { b.ClusterReserve = pct })
}

// config changes the InkwallConfig's spec.bundle.
func (f *fitCluster) config(mutate func(*wafv1alpha1.BundleSpec)) {
	f.t.Helper()
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	err := f.c.Get(f.ctx, client.ObjectKeyFromObject(cfg), cfg)
	mutate(&cfg.Spec.Bundle)
	cfg.Generation++
	if err == nil {
		err = f.c.Update(f.ctx, cfg)
	} else {
		err = f.c.Create(f.ctx, cfg)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

// flat is about n bytes of SecLang comments that compress to almost
// nothing.
func flat(n int) string {
	line := "# " + strings.Repeat("a", 97) + "\n"
	return strings.Repeat(line, n/len(line))
}

// fillSpread fills the published bundle to about head bytes under its
// limit with n namespaces, prefix0 on, each within its share.
func (f *fitCluster) fillSpread(prefix string, n, head int) *bundlev1.Bundle {
	f.t.Helper()
	f.build()
	// Aimed under, then topped up: a size may be off by a few percent
	// either way (review 8, B), and over would leave a filler out.
	each := (f.head() - head) * 95 / 100 / n
	for i := range n {
		ns := fmt.Sprintf("%s%d", prefix, i)
		f.ruleSet(ns, "fill", noiseFor(f.t, each))
		f.tenant(ns, "fill", "fill")
	}
	b := f.build()
	for i := range n {
		f.wantAccepted(fmt.Sprintf("%s%d", prefix, i), "fill")
	}
	// gzip doesn't add up: top it up.
	if h := f.head(); h > head+f.sz(64<<10) {
		f.ruleSet(prefix+"top", "fill", noiseFor(f.t, h-head))
		f.tenant(prefix+"top", "fill", "fill")
		b = f.build()
		f.wantAccepted(prefix+"top", "fill")
	}
	if h := f.head(); h > head*2+f.sz(128<<10) || h < 0 {
		f.t.Fatalf("filled to %d bytes under the limit, want about %d", h, head)
	}
	return b
}

// wantFits fails if the published bundle is over a limit.
func (f *fitCluster) wantFits(b *bundlev1.Bundle) {
	f.t.Helper()
	if f.head() < 0 {
		f.t.Errorf("bundle %d: %d bytes compressed, over the limit", b.GetVersion(), f.r.current.Size())
	}
	if n := proto.Size(b); n > f.lim.raw {
		f.t.Errorf("bundle %d: %d bytes raw, over the limit", b.GetVersion(), n)
	}
}

// One namespace's rule set grows the bundle past its limit: its changes
// are held (over its share), the rule set ships as it was, BundleTooLarge,
// and the other namespace's changes made after still reach the published
// bundle.
func TestBundleTooLargeOtherTenants(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.ruleSet("tenant-a", "rules", "SecMarker SMALL")
		f.tenant("tenant-a", "web", "rules")
		f.tenant("tenant-b", "web")
		first := f.build()
		f.wantAccepted("tenant-a", "web")
		f.wantAccepted("tenant-b", "web")

		// Over the limit by itself: over 7,200 KiB compressed.
		big := noiseFor(t, f.lim.gz*11/10)
		f.ruleSet("tenant-a", "rules", big)
		b := f.build()
		f.wantRuleSetHeld("tenant-a", "rules", "namespace tenant-a is over its share of the bundle")
		f.wantRuleSetHeld("tenant-a", "rules", "its previous version stays in force")
		f.wantAccepted("tenant-a", "web")
		if cond := f.accepted("tenant-a", "web"); !strings.Contains(cond.Message, "WAFRuleSet rules is held back at its previous version") {
			t.Errorf("tenant-a/web doesn't say its rule set is held: %q", cond.Message)
		}
		f.wantAccepted("tenant-b", "web")
		if b.GetVersion() != first.GetVersion() {
			t.Errorf("bundle %d published, want %d: nothing else changed", b.GetVersion(), first.GetVersion())
		}

		// Tenant B's changes after: published. A's new policies are its
		// namespace's changes too: held, and left out, as new.
		f.edit("tenant-b", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		f.tenant("tenant-b", "api")
		f.tenant("tenant-a", "more", "rules")
		f.ruleSet("tenant-a", "rules2", noiseFor(t, f.lim.gz*11/10))
		f.tenant("tenant-a", "more2", "rules2")
		b = f.build()
		if b.GetVersion() <= first.GetVersion() {
			t.Fatalf("bundle %d: tenant B's changes not published", b.GetVersion())
		}
		if p := bundlePolicy(b, "tenant-b/web"); p.GetMode() != bundlev1.Mode_MODE_BLOCK {
			t.Errorf("tenant-b/web in bundle %d: %v, want its new mode", b.GetVersion(), p)
		}
		if bundlePolicy(b, "tenant-b/api") == nil {
			t.Errorf("tenant-b/api not in bundle %d", b.GetVersion())
		}
		if rs := bundleRuleSet(b, "WAFRuleSet/tenant-a/rules"); rs.GetSeclang() != "SecMarker SMALL" {
			t.Errorf("tenant A's rule set in the bundle isn't its previous version: %d bytes", len(rs.GetSeclang()))
		}
		if bundlePolicy(b, "tenant-a/web") == nil {
			t.Error("tenant-a/web left out: it keeps its previous version")
		}
		f.wantAccepted("tenant-b", "web")
		f.wantAccepted("tenant-b", "api")
		f.wantRuleSetHeld("tenant-a", "rules", "")
		f.wantHeld("tenant-a", "more", "it has no previous version, so it is left out")
		f.wantHeld("tenant-a", "more2", "it has no previous version, so it is left out")
		if bundlePolicy(b, "tenant-a/more2") != nil || bundleRuleSet(b, "WAFRuleSet/tenant-a/rules2") != nil {
			t.Error("tenant-a/more2, new and over the limit, or its rule set, is in the bundle")
		}
		var cfgB wafv1alpha1.WAFPolicy
		_ = f.c.Get(f.ctx, types.NamespacedName{Namespace: "tenant-b", Name: "web"}, &cfgB)
		if cfgB.Status.BundleVersion != int64(b.GetVersion()) {
			t.Errorf("tenant-b/web: bundleVersion %d, want %d", cfgB.Status.BundleVersion, b.GetVersion())
		}

		// The same cluster gives the same bundle.
		if again := f.build(); again.GetVersion() != b.GetVersion() {
			t.Errorf("bundle %d published again from the same cluster, as %d", b.GetVersion(), again.GetVersion())
		}

		// Suspended, the switch works (#291), and the hold stays.
		cfg := &wafv1alpha1.InkwallConfig{}
		if err := f.c.Get(f.ctx, types.NamespacedName{Name: "default"}, cfg); err != nil {
			t.Fatal(err)
		}
		cfg.Spec.Suspend = true
		cfg.Generation++
		if err := f.c.Update(f.ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if s := f.build(); !s.GetSuspended() || bundleRuleSet(s, "WAFRuleSet/tenant-a/rules").GetSeclang() != "SecMarker SMALL" {
			t.Errorf("suspended: bundle %d suspended %t", s.GetVersion(), s.GetSuspended())
		}
		f.wantRuleSetHeld("tenant-a", "rules", "")

		// Shrunk, without the large new policy: everything published.
		var more2 wafv1alpha1.WAFPolicy
		if err := f.c.Get(f.ctx, types.NamespacedName{Namespace: "tenant-a", Name: "more2"}, &more2); err != nil {
			t.Fatal(err)
		}
		if err := f.c.Delete(f.ctx, &more2); err != nil {
			t.Fatal(err)
		}
		f.ruleSet("tenant-a", "rules", "SecMarker MEDIUM")
		b = f.build()
		if bundleRuleSet(b, "WAFRuleSet/tenant-a/rules").GetSeclang() != "SecMarker MEDIUM" {
			t.Error("tenant A's shrunk change not published")
		}
		f.wantRuleSetAccepted("tenant-a", "rules")
		f.wantAccepted("tenant-a", "web")
		f.wantAccepted("tenant-a", "more")
	})
}

// Review 1, finding 1B: a change that shrinks the bundle compressed takes
// it over its raw limit. It is held, over its namespace's share, and
// another namespace's change published.
func TestBundleTooLargeRaw(t *testing.T) {
	sizeTest(t, true, func(t *testing.T, f *fitCluster) {
		// The namespace's content predates the budget.
		f.share(100)
		line := "# " + strings.Repeat("a", 97) + "\n"
		const sets, perPolicy = 240, 16
		for p := range sets / perPolicy {
			var names []string
			for i := range perPolicy {
				name := fmt.Sprintf("r%03d", p*perPolicy+i)
				f.ruleSet("z", name, flat(f.sz(256<<10)))
				names = append(names, name)
			}
			if p == 0 {
				f.ruleSet("z", "swap", noise(t, f.sz(1<<20)))
				names = append(names, "swap")
			}
			f.tenant("z", fmt.Sprintf("web%02d", p), names...)
		}
		f.tenant("b", "web")
		b1 := f.build()
		raw := proto.Size(b1)
		if raw > f.lim.raw {
			t.Fatalf("the bundle is %d bytes raw before the change: the test needs it under %d", raw, f.lim.raw)
		}
		f.share(25)
		b1 = f.build()
		// Random rules become flat ones, enough to go over the raw limit.
		f.ruleSet("z", "swap", strings.Repeat(line, (f.sz(1<<20)+f.lim.raw-raw+f.sz(64<<10))/len(line)))
		f.edit("b", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		b2 := f.build()
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatalf("frozen: the victim's change isn't published; b/web Accepted: %+v", f.accepted("b", "web"))
		}
		if p := bundlePolicy(b2, "b/web"); p.GetMode() != bundlev1.Mode_MODE_BLOCK {
			t.Errorf("b/web in bundle %d: %v, want its new mode", b2.GetVersion(), p)
		}
		f.wantAccepted("b", "web")
		f.wantRuleSetHeld("z", "swap", "namespace z is over its share of the bundle")
		f.wantRuleSetHeld("z", "swap", "raw")
		f.wantFits(b2)
	})
}

// A namespace fills the 64 MiB raw limit with rules that compress to
// almost nothing: held, over its share, without compressing a bundle over
// the limit, and a victim's growing fix and a new app's policy are
// published.
func TestBundleTooLargeRawFill(t *testing.T) {
	sizeTest(t, true, func(t *testing.T, f *fitCluster) {
		for i := range 4 {
			ns := fmt.Sprintf("f%d", i)
			f.ruleSet(ns, "rules", flat(f.sz(11<<20)))
			f.tenant(ns, "web", "rules")
		}
		fix := noise(t, f.sz(8<<10))
		f.ruleSet("victim", "rules", fix)
		f.tenant("victim", "web", "rules")
		b1 := f.build()

		f.ruleSet("z", "fill", flat(f.sz(22<<20)))
		f.tenant("z", "web", "fill")
		fix += noise(t, f.sz(100<<10))
		f.ruleSet("victim", "rules", fix)
		f.tenant("app", "web")
		var encodes []int
		f.r.fitOptions.observe = func(h fitted) { encodes = append(encodes, h.encodes) }
		b2 := f.build()
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatal("frozen: nothing published")
		}
		f.wantHeld("z", "web", "namespace z is over its share of the bundle")
		f.wantHeld("z", "web", "raw")
		if bundleRuleSet(b2, "WAFRuleSet/victim/rules").GetSeclang() != fix {
			t.Error("the victim's fix isn't published")
		}
		if bundlePolicy(b2, "app/web") == nil {
			t.Error("the new app's policy isn't published")
		}
		f.wantAccepted("victim", "web")
		f.wantAccepted("app", "web")
		f.wantFits(b2)
		// The bundle with every change is over the raw limit: never
		// compressed. Only the bundle with z's change held is.
		if len(encodes) != 1 || encodes[0] != 1 {
			t.Errorf("encodes to fit: %v, want [1]", encodes)
		}
	})
}

// Review 2, finding 3: a namespace fills the bundle, with nothing else
// pending: its change is held, over its share, and a victim's growing fix
// and a new app's policy are published after it. Within its share, it is
// published.
func TestBundleTooLargeFill(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.clusterRuleSet("crs", "SecMarker CRS")
		fix := noise(t, f.sz(8<<10))
		f.ruleSet("victim", "rules", fix)
		f.tenant("victim", "web", "rules", "cluster:crs")
		// 68% of the limit, at rest.
		for i := range 4 {
			f.ruleSet(fmt.Sprintf("tenant%d", i), "rules", noiseFor(t, f.lim.gz*17/100))
			f.tenant(fmt.Sprintf("tenant%d", i), "web", "rules")
		}
		b1 := f.build()

		f.ruleSet("z", "fill", noiseFor(t, f.lim.gz*30/100))
		f.tenant("z", "web", "fill", "cluster:crs")
		if b := f.build(); b.GetVersion() != b1.GetVersion() {
			t.Errorf("bundle %d published, want %d: only z's change is pending, and it is held", b.GetVersion(), b1.GetVersion())
		}
		f.wantHeld("z", "web", "namespace z is over its share of the bundle")
		f.wantHeld("z", "web", "over spec.bundle.namespaceShare (25%)")

		fix += noiseFor(t, f.sz(500<<10))
		f.ruleSet("victim", "rules", fix)
		f.tenant("app", "web", "cluster:crs")
		crs := "SecMarker CRS\n" + noiseFor(t, f.sz(64<<10))
		f.clusterRuleSet("crs", crs)
		b2 := f.build()
		if bundleRuleSet(b2, "WAFRuleSet/victim/rules").GetSeclang() != fix {
			t.Error("the victim's fix isn't published")
		}
		if bundlePolicy(b2, "app/web") == nil {
			t.Error("the new app's policy isn't published")
		}
		if bundleRuleSet(b2, "ClusterWAFRuleSet/crs").GetSeclang() != crs {
			t.Error("the CRS upgrade isn't published")
		}
		f.wantRuleSetAccepted("victim", "rules")
		f.wantAccepted("victim", "web")
		f.wantAccepted("app", "web")
		f.wantHeld("z", "web", "namespace z is over its share of the bundle")
		f.wantFits(b2)

		// Within its share, z's fill is published.
		f.ruleSet("z", "fill", noiseFor(t, f.lim.gz*15/100))
		b3 := f.build()
		f.wantAccepted("z", "web")
		if bundlePolicy(b3, "z/web") == nil {
			t.Error("z's fill, within its share, isn't published")
		}
		f.wantFits(b3)
	})
}

// Review 3, finding 2 (TestN1FillTo75), under the headroom gate: one
// namespace fills 72% of the bundle at once while the bundle with every
// change leaves more than its share (25%) free: the budget doesn't apply,
// and it is published. Past that, the bundle would leave less free, and
// its growth is held, over its share. Other tenants' growth within their
// share is published. What z published stays: a CRS upgrade larger than
// the room left is held (z, with no change, is never held), and published
// once z shrinks.
func TestN1FillTo75(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.clusterRuleSet("crs", "SecMarker CRS")
		f.tenant("app", "web", "cluster:crs")
		f.build()
		fill := noiseFor(t, f.lim.gz*66/100)
		f.ruleSet("z", "fill", fill)
		f.tenant("z", "web", "fill")
		f.build()
		// 28% free, measured: more than its share.
		fill = f.topUp("z", "fill", fill, f.lim.gz*28/100)
		b := f.build()
		f.wantAccepted("z", "web")
		if bundlePolicy(b, "z/web") == nil {
			t.Fatal("z's fill, leaving more than its share free, isn't published")
		}
		f.ruleSet("z", "fill", fill+noiseFor(t, f.lim.gz*6/100))
		b = f.build()
		f.wantRuleSetHeld("z", "fill", "namespace z is over its share of the bundle")
		if bundleRuleSet(b, "WAFRuleSet/z/fill").GetSeclang() != fill {
			t.Error("z's fill in the bundle isn't the one published before")
		}
		f.ruleSet("z", "fill", fill)
		for i := range 2 {
			f.ruleSet(fmt.Sprintf("legit%d", i), "rules", noiseFor(t, f.lim.gz*8/100))
			f.tenant(fmt.Sprintf("legit%d", i), "web", "rules")
		}
		f.build()
		for i := range 2 {
			f.wantAccepted(fmt.Sprintf("legit%d", i), "web")
		}
		crs := "SecMarker CRS\n" + noiseFor(t, f.head()+f.sz(64<<10))
		f.clusterRuleSet("crs", crs)
		b = f.build()
		f.wantRuleSetHeld("", "crs", "even with every namespace's changes held it doesn't fit")
		f.wantAccepted("z", "web")
		f.wantFits(b)
		f.ruleSet("z", "fill", fill[:len(fill)/2])
		b = f.build()
		if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != crs {
			t.Errorf("the CRS upgrade is held: %s", f.ruleSetAccepted("", "crs").Message)
		}
		f.wantFits(b)
	})
}

// Review 1, finding 3: a tenant spreads its growth over several
// namespaces, each within its share. Only the tenant's namespaces are
// held, and no more of them than needed.
func TestBundleTooLargeSpread(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.ruleSet("victim", "rules", noiseFor(t, f.sz(200<<10)))
		f.tenant("victim", "web", "rules")
		const spread = 4
		fills := make([]string, spread)
		for i := range fills {
			fills[i] = noiseFor(t, f.sz(1<<20))
			f.ruleSet(fmt.Sprintf("z%d", i), "fill", fills[i])
			f.tenant(fmt.Sprintf("z%d", i), "web", "fill")
		}
		b1 := f.fillSpread("filler", 3, f.sz(800<<10))
		head := f.head()
		for i := range fills {
			f.wantRuleSetAccepted(fmt.Sprintf("z%d", i), "fill")
			// Together, 5/3 of the room left: one held isn't enough, two are.
			f.ruleSet(fmt.Sprintf("z%d", i), "fill", fills[i]+noiseFor(t, head*5/3/spread))
		}
		f.edit("victim", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		b2 := f.build()
		if p := bundlePolicy(b2, "victim/web"); b2.GetVersion() == b1.GetVersion() || p.GetMode() != bundlev1.Mode_MODE_BLOCK {
			t.Fatalf("the victim's change isn't published: %v", p)
		}
		f.wantAccepted("victim", "web")
		held := 0
		for i := range fills {
			if f.ruleSetHeld(fmt.Sprintf("z%d", i), "fill") {
				held++
			} else if bundleRuleSet(b2, fmt.Sprintf("WAFRuleSet/z%d/fill", i)).GetSeclang() == fills[i] {
				t.Errorf("z%d's change, not held, isn't published", i)
			}
		}
		if held != 2 {
			t.Errorf("%d of the tenant's namespaces held, want 2 (room %d, now %d)", held, head, f.head())
		}
		f.wantFits(b2)
	})
}

// Review 1, finding 3: holding is minimal. The namespace with the largest
// share grows the bundle a little, another a lot, and the CRS is upgraded:
// holding the other alone fits, so neither the first nor the upgrade is
// held (the first is released after the prefix that fits holds both).
func TestBundleTooLargeMinimal(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.clusterRuleSet("crs", "SecMarker CRS")
		big := noiseFor(t, f.sz(1300<<10))
		f.ruleSet("big", "rules", big)
		f.tenant("big", "web", "rules", "cluster:crs")
		rules := noiseFor(t, f.sz(300<<10))
		f.ruleSet("z", "fill", rules)
		f.tenant("z", "web", "fill", "cluster:crs")
		f.fillSpread("filler", 4, f.sz(600<<10))
		head := f.head()

		big += noiseFor(t, head/4)
		f.ruleSet("big", "rules", big)
		f.ruleSet("z", "fill", rules+noiseFor(t, head*3/2))
		crs := "SecMarker CRS\n" + noiseFor(t, head/20)
		f.clusterRuleSet("crs", crs)
		b2 := f.build()
		if bundleRuleSet(b2, "WAFRuleSet/big/rules").GetSeclang() != big {
			t.Error("the change of the namespace with the largest share is held, though holding z's alone fits")
		}
		if bundleRuleSet(b2, "ClusterWAFRuleSet/crs").GetSeclang() != crs {
			t.Error("the CRS upgrade is held, though holding z's change alone fits")
		}
		f.wantRuleSetAccepted("big", "rules")
		f.wantRuleSetAccepted("", "crs")
		f.wantRuleSetHeld("z", "fill", "namespace z's content takes")
		f.wantFits(b2)
	})
}

// A change that fits the limits alone adopts the cluster rule sets' changes
// though the bundle with every namespace's change held, and theirs, is over
// a limit: it doesn't grow that bundle (the property test, seed 1026).
func TestAdoptsNoneOverALimit(t *testing.T) {
	f := &fitter{lim: fitLimits{raw: 1000, gz: 1000}, reserveRaw: 400, reserveGz: 400}
	tooLarge := sizes{raw: 700, gz: 1010, gzKnown: true, err: bundle.ErrTooLarge}
	for _, c := range []struct {
		s, none sizes
		want    bool
	}{
		{sizes{raw: 700, gz: 990, gzKnown: true}, tooLarge, true},
		{sizes{raw: 710, gz: 1020, gzKnown: true, err: bundle.ErrTooLarge}, tooLarge, false},
		{sizes{raw: 700, gz: 990, gzKnown: true}, sizes{raw: 1100}, false},
		{sizes{raw: 700, gz: 990, gzKnown: true}, sizes{raw: 700, gz: 900, gzKnown: true}, false},
		{sizes{raw: 700, gz: 900, gzKnown: true}, sizes{raw: 700, gz: 900, gzKnown: true}, true},
	} {
		if got := f.adopts(c.s, c.none, f.adoptRaw, f.adoptGz); got != c.want {
			t.Errorf("adopts(%+v, %+v) = %t, want %t", c.s, c.none, got, c.want)
		}
	}
}

// A try that fits the limits is within its reserve base though the base is
// over the compressed limit, as a change it holds shrinks the bundle (the
// property test, seed 1392); not when the try is larger, nor against a base
// over the raw limit, which isn't compressed.
func TestWithinBaseOverALimit(t *testing.T) {
	over := sizes{raw: 900, gz: 1100, gzKnown: true, err: bundle.ErrTooLarge}
	for _, c := range []struct {
		s, base sizes
		want    bool
	}{
		{sizes{raw: 800, gz: 990, gzKnown: true}, over, true},
		{sizes{raw: 950, gz: 990, gzKnown: true}, over, false},
		{sizes{raw: 800, gz: 990, gzKnown: true}, sizes{raw: 1100, err: bundle.ErrTooLarge}, false},
		{sizes{raw: 800, gz: 1050, gzKnown: true, err: bundle.ErrTooLarge}, over, false},
		{sizes{raw: 800, gz: 990, gzKnown: true}, sizes{raw: 800, gz: 980, gzKnown: true}, false},
	} {
		if got := c.s.within(c.base); got != c.want {
			t.Errorf("%+v within %+v = %t, want %t", c.s, c.base, got, c.want)
		}
	}
}

// The order: the largest share first (of the limit it takes most of; a
// share not measured compressed counts as its raw one, and a negative one,
// from gzip, as 0), ties to the namespace created last, then by name; a
// namespace whose holding leaves out a published policy by its share too
// (review 5, finding 3: it doesn't jump the queue), unless its change fits
// alone and grows its share by at most adoptionCap (prior, reviews 6 and
// 7): those are released first, the smallest growth first (measured, or not
// measured, as estimated: its content's growth compressed alone); cluster rule sets
// last, and namespaces held over their share not in it.
func TestHoldOrder(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	g := func(ns string, raw, gz int, known bool, created time.Time) *holdGroup {
		return &holdGroup{namespace: ns, raw: raw, gz: gz, gzKnown: known, created: created}
	}
	over := g("over", 0, 6000<<10, true, t0)
	over.budget = "over"
	last := g("last", 6<<20, 5000<<10, true, t0)
	last.last = true
	lastSmall := g("last-small", 100, 50, true, t0)
	lastSmall.last = true
	prior := func(ns string, growRaw, growGz int, known bool) *holdGroup {
		p := g(ns, 100, 100, true, t0)
		p.last, p.prior, p.protected, p.growRaw, p.aloneKnown = true, true, true, growRaw, known
		if known {
			p.growGz = growGz
		} else {
			p.estGz = growGz
		}
		return p
	}
	f := &fitter{lim: secretLimits, groups: []*holdGroup{
		over,
		last,
		g("small", 100, 100, true, t0),
		g("b-old", 900, 500<<10, true, t0),
		g("a-new", 900, 500<<10, true, t0.Add(time.Minute)),
		g("c-same", 900, 500<<10, true, t0),
		g("largest", 5<<20, 4000<<10, true, t0),
		g("raw", 40<<20, 100<<10, true, t0),
		g("unmeasured", 3000<<10, 0, false, t0),
		lastSmall,
		prior("prior-small", 10<<10, 20<<10, true),
		prior("prior-unmeasured", 30<<10, 30<<10, false),
		prior("prior-raw-neutral", 0, 40<<10, true),
		prior("prior-large", 1<<20, 200<<10, true),
		g("negative", 0, -20<<10, true, t0),
	}, cluster: g("", 0, 9000<<10, true, t0)}
	var got []string
	for _, g := range f.order() {
		got = append(got, g.namespace)
	}
	want := []string{"last", "raw", "largest", "unmeasured", "a-new", "b-old", "c-same", "small", "last-small", "negative",
		"prior-large", "prior-raw-neutral", "prior-unmeasured", "prior-small", ""}
	if !slices.Equal(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
}

// The budget's boundary: a namespace's growth is published up to its
// share (spec.bundle.namespaceShare) and held past it.
func TestBundleTooLargeBudget(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.share(40)
		for i := range 2 {
			f.ruleSet(fmt.Sprintf("tenant%d", i), "rules", noiseFor(t, f.lim.gz*20/100))
			f.tenant(fmt.Sprintf("tenant%d", i), "web", "rules")
		}
		f.build()
		rules := noiseFor(t, f.lim.gz*37/100)
		f.ruleSet("z", "rules", rules)
		f.tenant("z", "web", "rules")
		f.build()
		f.wantAccepted("z", "web")
		f.ruleSet("z", "rules", rules+noiseFor(t, f.lim.gz*6/100))
		f.build()
		f.wantRuleSetHeld("z", "rules", "over spec.bundle.namespaceShare (40%)")
		f.wantRuleSetHeld("z", "rules", "compressed")
	})
}

// A namespace over its share before the budget (spec.bundle.namespaceShare
// lowered, or an operator upgraded) keeps what it has, and may shrink, not
// grow.
func TestBundleTooLargeBudgetGrandfathered(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.share(100)
		for i := range 2 {
			f.ruleSet(fmt.Sprintf("tenant%d", i), "rules", noiseFor(t, f.lim.gz*20/100))
			f.tenant(fmt.Sprintf("tenant%d", i), "web", "rules")
		}
		grown := noiseFor(t, f.lim.gz*43/100)
		f.ruleSet("z", "rules", grown)
		f.tenant("z", "web", "rules")
		f.build()
		f.wantAccepted("z", "web")
		f.share(40)
		shrunk := grown[:len(grown)-len(grown)/43]
		f.ruleSet("z", "rules", shrunk)
		b := f.build()
		f.wantRuleSetAccepted("z", "rules")
		if bundleRuleSet(b, "WAFRuleSet/z/rules").GetSeclang() != shrunk {
			t.Error("z's shrinking change, over its share, isn't published")
		}
		f.ruleSet("z", "rules", grown+noiseFor(t, f.lim.gz/100))
		f.build()
		f.wantRuleSetHeld("z", "rules", "namespace z is over its share of the bundle")
	})
}

// The budget's gate (review 4, finding 2): a first bundle that fits is
// published, whatever a namespace's share; while the bundle with every
// change leaves a share of each limit free, a namespace may grow past its
// share; once it wouldn't, a namespace's growth past its share is held,
// and it may still shrink.
func TestBundleTooLargeBudgetHeadroom(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		rules := noiseFor(t, f.lim.gz*40/100)
		f.ruleSet("z", "rules", rules)
		f.tenant("z", "web", "rules")
		f.tenant("app", "web")
		b := f.build()
		f.wantAccepted("z", "web")
		if bundlePolicy(b, "z/web") == nil || bundlePolicy(b, "app/web") == nil {
			t.Fatalf("first bundle %d: z/web or app/web isn't in it", b.GetVersion())
		}
		rules += noiseFor(t, f.lim.gz*20/100)
		f.ruleSet("z", "rules", rules)
		b = f.build()
		f.wantRuleSetAccepted("z", "rules")
		if bundleRuleSet(b, "WAFRuleSet/z/rules").GetSeclang() != rules {
			t.Error("z's growth, the bundle leaving more than its share free, isn't published")
		}
		f.ruleSet("z", "rules", rules+noiseFor(t, f.lim.gz*20/100))
		b = f.build()
		f.wantRuleSetHeld("z", "rules", "namespace z is over its share of the bundle")
		if bundleRuleSet(b, "WAFRuleSet/z/rules").GetSeclang() != rules {
			t.Error("z's held growth is in the bundle")
		}
		shrunk := rules[:len(rules)*9/10]
		f.ruleSet("z", "rules", shrunk)
		b = f.build()
		f.wantRuleSetAccepted("z", "rules")
		if bundleRuleSet(b, "WAFRuleSet/z/rules").GetSeclang() != shrunk {
			t.Error("z's shrinking change isn't published")
		}
	})
}

// The budget's boundary in raw bytes: rules that compress to almost
// nothing take a namespace past its share of the 64 MiB.
func TestBundleTooLargeBudgetRaw(t *testing.T) {
	sizeTest(t, true, func(t *testing.T, f *fitCluster) {
		for i := range 3 {
			f.ruleSet(fmt.Sprintf("tenant%d", i), "rules", flat(f.sz(11<<20)))
			f.tenant(fmt.Sprintf("tenant%d", i), "web", "rules")
		}
		f.build()
		// 48.5 MiB raw: z's share is 16 MiB.
		f.ruleSet("z", "rules", flat(f.sz(31<<19)))
		f.tenant("z", "web", "rules")
		f.build()
		f.wantAccepted("z", "web")
		f.ruleSet("z", "rules", flat(f.sz(33<<19)))
		f.build()
		f.wantRuleSetHeld("z", "rules", "over spec.bundle.namespaceShare (25%)")
		f.wantRuleSetHeld("z", "rules", "raw")
	})
}

// Review 2, finding 1: many namespaces share gzip back-references (the
// same rule set, next to each other in the bundle), so each one's share
// is tiny, then each becomes fresh noise: together they grow the bundle
// past its limit. A victim's smaller fix is published, and enough of them
// held.
func TestBundleTooLargeGzipShared(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.ruleSet("victim", "rules", noise(t, f.sz(2<<10)))
		f.tenant("victim", "web", "rules")
		const k = 8
		x := noise(t, f.sz(30<<10))
		ns := func(i int) string { return fmt.Sprintf("z%c", 'a'+i) }
		for i := range k {
			f.ruleSet(ns(i), "x", x)
			f.tenant(ns(i), "web", "x")
		}
		b1 := f.fillSpread("filler", 5, f.sz(64<<10))
		// Each grows well past gzip's alignment noise (tens of KiB), so
		// the order is the shares'.
		for i := range k {
			f.ruleSet(ns(i), "x", noise(t, f.sz(160<<10)))
		}
		fix := noise(t, f.sz(2<<10)) + noiseFor(t, f.sz(10<<10))
		f.ruleSet("victim", "rules", fix)
		b2 := f.build()
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatal("frozen: nothing published")
		}
		if f.ruleSetHeld("victim", "rules") || bundleRuleSet(b2, "WAFRuleSet/victim/rules").GetSeclang() != fix {
			t.Errorf("the victim's fix, with a smaller share than each of the namespaces that grow the bundle, is held: %+v",
				f.ruleSetAccepted("victim", "rules"))
		}
		held := 0
		for i := range k {
			if f.ruleSetHeld(ns(i), "x") {
				held++
			}
		}
		if held == 0 {
			t.Errorf("none of the %d namespaces held", k)
		}
		f.wantFits(b2)
	})
}

// The encodes of a build are capped (here at 12, not 64): with more
// namespaces changed than the cap measures, the bundle still fits, and the
// namespaces not tried for release stay held.
func TestBundleTooLargeEncodeCap(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.ruleSet("victim", "rules", "SecMarker SMALL")
		f.tenant("victim", "web", "rules")
		const n = 20
		ns := func(i int) string { return fmt.Sprintf("n%02d", i) }
		for i := range n {
			f.ruleSet(ns(i), "rules", noise(t, f.sz(2<<10)))
			f.tenant(ns(i), "web", "rules")
		}
		b1 := f.fillSpread("filler", 5, f.sz(300<<10))
		f.r.fitOptions.maxEncodes = 12
		for i := range n {
			f.ruleSet(ns(i), "rules", noise(t, f.sz(2<<10))+noiseFor(t, f.sz(30<<10)))
		}
		f.edit("victim", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		var encodes []int
		f.r.fitOptions.observe = func(h fitted) { encodes = append(encodes, h.encodes) }
		b2 := f.build()
		if len(encodes) != 1 || encodes[0] > 12 {
			t.Errorf("encodes to fit: %v, want one build of at most 12", encodes)
		}
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatal("frozen: nothing published")
		}
		if p := bundlePolicy(b2, "victim/web"); p.GetMode() != bundlev1.Mode_MODE_BLOCK {
			t.Errorf("the victim's change, the smallest, isn't published: %v", p)
		}
		held := 0
		for i := range n {
			if f.ruleSetHeld(ns(i), "rules") {
				held++
			}
		}
		if held == 0 || held == n {
			t.Errorf("%d of %d namespaces held, want some", held, n)
		}
		t.Logf("%d encodes, %d of %d namespaces held", encodes[0], held, n)
		f.wantFits(b2)
	})
}

// Review 2's PoC 1 (TestPoC2Misclassify, review 3's TestOrigR2Misclassify):
// legitimate tenants fill the bundle, then a chain of rule sets shared
// across namespaces za..zf becomes noise, each not growing it on the
// margin, while the victim's fix grows it. Together they don't fit. The
// victim's namespace has the largest share, so its fix is held, and the
// six namespaces' changes, each a smaller share, are published: a tenant
// with several namespaces outranks a larger one with one (residual (a),
// documented under BundleTooLarge). The bundle fits, and nothing else is
// held.
func TestPoC2Misclassify(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.ruleSet("victim", "rules", noise(t, f.sz(8<<10)))
		f.tenant("victim", "web", "rules")
		const k = 6
		x := noise(t, f.sz(30<<10))
		ns := func(i int) string { return fmt.Sprintf("z%c", 'a'+i) }
		for i := range k {
			f.ruleSet(ns(i), "x", x)
			f.tenant(ns(i), "web", "x")
		}
		b1 := f.fillSpread("filler", 5, f.sz(300<<10))
		head := f.head()
		grown := make([]string, k)
		for i := range k {
			grown[i] = noise(t, f.sz(29<<10))
			f.ruleSet(ns(i), "x", grown[i])
		}
		// 90% of the room: it fits alone, not with the z's growth (a
		// quarter of the room or more), wide of how far a size may be off
		// (review 8, B).
		fix := noise(t, f.sz(8<<10)) + noiseFor(t, head*9/10)
		f.ruleSet("victim", "rules", fix)
		b2 := f.build()
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatal("frozen: nothing published")
		}
		f.wantRuleSetHeld("victim", "rules", "namespace victim's content takes")
		if bundlePolicy(b2, "victim/web") == nil {
			t.Error("victim/web, its rule set held, is left out")
		}
		f.wantAccepted("victim", "web")
		for i := range k {
			f.wantRuleSetAccepted(ns(i), "x")
			if bundleRuleSet(b2, fmt.Sprintf("WAFRuleSet/%s/x", ns(i))).GetSeclang() != grown[i] {
				t.Errorf("%s's change isn't published", ns(i))
			}
		}
		f.wantFits(b2)
	})
}

// Review 2's PoC 2 (TestPoC3PinCRS): the attacker's rule set pre-uses a
// rule id the next CRS adds. During the admin's CRS upgrade, the attacker
// makes a change over the limit by itself: it is held, and its previous
// version, which doesn't compile with the new CRS, is left out, saying
// so. The CRS is never held for it.
func TestPoC3PinCRS(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		f.ruleSet("z", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`)
		f.tenant("z", "web", "own", "cluster:crs")
		f.tenant("victim", "web", "cluster:crs")
		b1 := f.build()
		f.wantAccepted("z", "web")

		f.clusterRuleSet("crs", newCRS) // the admin's upgrade
		var names []string
		for i := range 40 {
			n := fmt.Sprintf("big%02d", i)
			f.ruleSet("z", n, noiseFor(t, f.lim.gz/36))
			names = append(names, n)
		}
		f.edit("z", "web", func(p *wafv1alpha1.WAFPolicy) {
			p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}}}
			for _, n := range names {
				p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: n}})
			}
		})
		for round := range 3 {
			b := f.build()
			if b.GetVersion() == b1.GetVersion() {
				t.Fatalf("round %d: frozen", round)
			}
			if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
				t.Errorf("round %d: pinned: the CRS upgrade is held by z's change, %+v", round, f.ruleSetAccepted("", "crs"))
			}
			f.wantRuleSetAccepted("", "crs")
			f.wantHeld("z", "web", "namespace z is over its share of the bundle")
			if round == 0 {
				f.wantHeld("z", "web", "doesn't compile with ClusterWAFRuleSet crs as it is now")
			} else {
				f.wantHeld("z", "web", "it has no previous version, so it is left out")
			}
			if bundlePolicy(b, "z/web") != nil {
				t.Errorf("round %d: z/web, incompatible with the CRS as it is now, is in the bundle", round)
			}
			if p := bundlePolicy(b, "victim/web"); round > 0 && p.GetMode() != bundlev1.Mode_MODE_BLOCK {
				t.Errorf("round %d: the victim's change isn't published: %v", round, p)
			}
			f.wantFits(b)
			f.edit("victim", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		}
	})
}

// Review 3, finding 1 (TestN2LeftOutLieInWait): the bundle is near full.
// z keeps a change pending that doesn't fit, within its share. The admin
// upgrades the CRS and the victim, with a larger share, ships its
// exclusion fix for it in the same sync. Holding the victim would leave
// its policy out (its rule set as it was doesn't compile with the new
// CRS), so z, next in the order, is held instead: the victim's policy
// stays published, in every round, and z's change waits.
func TestN2LeftOutLieInWait(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		ballast := noiseFor(t, f.sz(600<<10))
		f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`+"\n"+ballast)
		f.tenant("victim", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		zr := noise(t, f.sz(2<<10))
		f.ruleSet("z", "fill", zr)
		f.tenant("z", "web", "fill")
		f.fillSpread("filler", 5, f.sz(150<<10))
		head := f.head()
		f.wantAccepted("victim", "web")

		// z's pending change: the room left and more; its share is smaller
		// than the victim's.
		zr2 := zr + noiseFor(t, head+f.sz(80<<10))
		f.ruleSet("z", "fill", zr2)
		f.build()
		f.wantRuleSetHeld("z", "fill", "")

		// The upgrade, and the victim's fix for it (the rule id moved).
		f.clusterRuleSet("crs", newCRS)
		fix := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + ballast
		f.ruleSet("victim", "own", fix)
		for round := range 3 {
			b := f.build()
			if bundlePolicy(b, "victim/web") == nil {
				t.Errorf("round %d: victim/web is left out; z's change published: %v", round,
					bundleRuleSet(b, "WAFRuleSet/z/fill").GetSeclang() == zr2)
			}
			if c := f.accepted("victim", "web"); c.Reason == resolver.ReasonRuleSetsIncompatible {
				t.Errorf("round %d: victim/web: %s: %s", round, c.Reason, c.Message)
			}
			if rs := bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang(); rs != fix {
				t.Errorf("round %d: the victim's fix isn't published", round)
			}
			f.wantRuleSetAccepted("victim", "own")
			f.wantAccepted("victim", "web")
			f.wantRuleSetHeld("z", "fill", "namespace z's content takes")
			if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
				t.Errorf("round %d: the CRS upgrade isn't published", round)
			}
			f.wantFits(b)
		}
	})
}

// Rule R (review 5): the CRS is upgraded while a namespace's own change
// is pending, and its rule set as it was doesn't compile with the new CRS.
//
// Its change doesn't fit even alone on the bundle in force (nor once its
// policy is out): holding it leaves its published policy out, saying
// BundleTooLarge and counted as held, and the CRS upgrade is published.
// Once its change fits, it is published.
func TestBundleTooLargeLeftOutStatus(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		ballast := noiseFor(t, f.sz(300<<10))
		old := `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"` + "\n" + ballast
		f.ruleSet("z", "own", old)
		f.tenant("z", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.sz(150<<10))
		head := f.head()

		f.clusterRuleSet("crs", newCRS)
		fixed := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + ballast
		f.ruleSet("z", "own", fixed+noiseFor(t, head+f.sz(500<<10)))
		var held []int
		f.r.fitOptions.observe = func(h fitted) { held = append(held, heldCount(h)) }
		for round := range 2 {
			held = nil
			b := f.build()
			if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
				t.Errorf("round %d: the CRS upgrade isn't published: %+v", round, f.ruleSetAccepted("", "crs"))
			}
			f.wantRuleSetAccepted("", "crs")
			if p := bundlePolicy(b, "z/web"); p != nil {
				t.Errorf("round %d: z/web, whose previous version doesn't compile with the new CRS, is in the bundle", round)
			}
			// z's rule set and its policy left out; then z/web, new to the
			// bundle in force, with its rule set.
			if round == 0 {
				f.wantRuleSetHeld("z", "own", "its change doesn't fit even alone")
				f.wantHeld("z", "web", "WAFRuleSet own is held back")
			} else {
				f.wantHeld("z", "web", "it has no previous version, so it is left out")
			}
			if want := []int{2 - round}; !slices.Equal(held, want) {
				t.Errorf("round %d: held %v, want %v", round, held, want)
			}
			f.wantFits(b)
		}
		f.ruleSet("z", "own", fixed)
		b := f.build()
		if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS || bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() != fixed {
			t.Error("z's fix, which fits, isn't published")
		}
		f.wantAccepted("z", "web")
		f.wantRuleSetAccepted("", "crs")
	})
}

// Rule R (b), with the cluster reserve: a namespace's change fits the
// limits alone with the CRS upgrade, though not within the reserve. Its
// change adopts the upgrade and grows its share by less than adoptionCap,
// so it may use that much of the reserve: both are published in the same
// build, nothing is held, and the CRS doesn't wait.
func TestBundleTooLargeClusterAdoptedWithReserve(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.reserve(nil) // its default, 10%
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		f.clusterRuleSet("crs", oldCRS)
		old := `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`
		f.ruleSet("z", "own", old)
		f.tenant("z", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*27/100)
		// The upgrade leaves 10% free, measured, and z's fix 7%.
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"` + "\n" +
			noiseFor(t, f.head()-f.lim.gz*10/100)

		f.clusterRuleSet("crs", newCRS)
		fixed := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + noiseFor(t, f.lim.gz*3/100)
		f.ruleSet("z", "own", fixed)
		var held []int
		f.r.fitOptions.observe = func(h fitted) { held = append(held, heldCount(h)) }
		b := f.build()
		if bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() != fixed || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
			t.Errorf("z's change, which fits alone with the CRS upgrade, or the upgrade isn't published: %+v, %+v",
				f.ruleSetAccepted("z", "own"), f.ruleSetAccepted("", "crs"))
		}
		f.wantRuleSetAccepted("", "crs")
		f.wantAccepted("z", "web")
		if slices.ContainsFunc(held, func(n int) bool { return n != 0 }) {
			t.Errorf("held %v, want none", held)
		}
		if free := f.head() * 100 / f.lim.gz; free >= 10 {
			t.Errorf("the bundle leaves %d%% free: the scenario doesn't use the reserve", free)
		}
		f.wantFits(b)
	})
}

// Rule R (b): the cluster rule sets' changes wait one build at most, for
// the namespaces whose change fits alone. victim and squat both bind the
// CRS, and their rule sets use the rule id its upgrade adds; each ships its
// fix with the upgrade, and each fix fits alone, but not both. The one
// with the smaller change alone, the victim's (with the larger share), is
// published against the CRS as it was, and the CRS waits a build, measured
// with the upgrade so that it fits next build; squat's change is held, and
// so is y's, a namespace that doesn't bind the CRS, while squat is: the
// namespaces whose change the CRS waits for are released first. Next
// build the CRS upgrade is published, squat's change no longer fits alone
// (the victim took the room), so squat/web is left out, and y's change is
// published. The same with the waited cluster rule sets forgotten before
// every build (an operator restart, a new leader): the victim's change
// took the room, so the CRS doesn't wait again.
func TestBundleTooLargeClusterWaitsAtMostOneBuild(t *testing.T) {
	t.Parallel()
	for _, restart := range []bool{false, true} {
		if restart && raceDetector {
			continue // not under the race detector
		}
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				vBase := noiseFor(t, f.lim.gz*8/100)
				f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`+"\n"+vBase)
				f.tenant("victim", "web", "own", "cluster:crs")
				sBase := noiseFor(t, f.lim.gz*3/100)
				f.ruleSet("squat", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+sBase)
				f.tenant("squat", "web", "own", "cluster:crs")
				yWas := noiseFor(t, f.lim.gz*2/100)
				f.ruleSet("y", "own", yWas)
				f.tenant("y", "web", "own")
				f.tenant("other", "web", "cluster:crs")
				// Each fix grows its share by less than adoptionCap.
				f.fillSpread("filler", 5, f.lim.gz*5/100)
				head := f.head()

				f.clusterRuleSet("crs", newCRS)
				vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + vBase + noiseFor(t, head*5/10)
				f.ruleSet("victim", "own", vFix)
				sFix := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + sBase + noiseFor(t, head*6/10)
				f.ruleSet("squat", "own", sFix)
				yNow := yWas + noiseFor(t, head/10)
				f.ruleSet("y", "own", yNow)
				var held []int
				f.r.fitOptions.observe = func(h fitted) { held = append(held, heldCount(h)) }
				build := func() *bundlev1.Bundle {
					if restart {
						f.r.waited, f.r.carried = nil, nil
					}
					held = nil
					return f.build()
				}
				b := build()
				if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vFix {
					t.Errorf("round 0: the victim's change, the smaller alone, isn't published: %+v", f.ruleSetAccepted("victim", "own"))
				}
				if bundleRuleSet(b, "WAFRuleSet/squat/own").GetSeclang() == sFix || bundleRuleSet(b, "WAFRuleSet/y/own").GetSeclang() == yNow {
					t.Error("round 0: squat's change, or y's while squat's is held, is published")
				}
				if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != oldCRS {
					t.Error("round 0: the CRS upgrade is published, so squat/web, whose change fits alone, is left out")
				}
				f.wantRuleSetHeld("", "crs", "waits one build")
				f.wantRuleSetHeld("y", "own", "the other namespaces' changes wait too")
				f.wantRuleSetHeld("squat", "own", "that cluster rule set's change waits with it")
				f.wantAccepted("victim", "web")
				f.wantAccepted("squat", "web")
				if want := []int{3}; !slices.Equal(held, want) {
					t.Errorf("round 0: held %v, want %v", held, want)
				}
				f.wantFits(b)

				b = build()
				if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
					t.Errorf("round 1: the CRS upgrade waits a second build: %+v", f.ruleSetAccepted("", "crs"))
				}
				f.wantRuleSetAccepted("", "crs")
				f.wantAccepted("victim", "web")
				f.wantRuleSetHeld("squat", "own", "doesn't fit even alone")
				f.wantHeld("squat", "web", "")
				if bundlePolicy(b, "squat/web") != nil {
					t.Error("round 1: squat/web, whose previous version doesn't compile with the new CRS, is in the bundle")
				}
				if bundleRuleSet(b, "WAFRuleSet/y/own").GetSeclang() != yNow {
					t.Errorf("round 1: y's change isn't published: %+v", f.ruleSetAccepted("y", "own"))
				}
				f.wantFits(b)
			})
		})
	}
}

// A squatter can't outrank a small fix: the victim binds the CRS, its rule
// set uses the rule id the upgrade adds, and it ships a fix that takes half
// of the room the changes that adopt the upgrade have (above the reserve
// line, and adoptionCap of the reserve) with it; squat does the same (it
// squats the id) with a change sized to take the room, both within
// adoptionCap. The changes that adopt the upgrade are released the
// smallest alone first, so a squatter's change that comes before the
// victim's is smaller, and both fit: one that doesn't leave the victim's
// fix room comes after it, and waits a build; held then while protected,
// it has a part of the reserve of its own in the build after the wait
// (review 8, finding 1), and is published with the upgrade: the adopting
// changes take at most 2 x adoptionCap of the reserve. The victim's fix is
// published in the first build and stays in every round, and the CRS
// upgrade waits one build at most.
func TestP6SquatterCantOutrankSmallFix(t *testing.T) {
	t.Parallel()
	for _, squatPct := range []int{30, 70} {
		if squatPct == 30 && raceDetector {
			continue // the smaller squat: not under the race detector
		}
		t.Run(fmt.Sprintf("squat=%d%%", squatPct), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(nil) // its default, 10%
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				vBase := noiseFor(t, f.lim.gz*8/100)
				f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
				f.tenant("victim", "web", "own", "cluster:crs")
				sBase := noiseFor(t, f.lim.gz*3/100)
				f.ruleSet("squat", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+sBase)
				f.tenant("squat", "web", "own", "cluster:crs")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 5, f.lim.gz*11/100)
				// The room above the reserve line, and adoptionCap of the reserve.
				head := f.head() - f.lim.gz/100*(defaultClusterReserve-adoptionCap)

				f.clusterRuleSet("crs", newCRS)
				vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + noiseFor(t, head/2)
				f.ruleSet("victim", "own", vFix)
				sFix := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + sBase + noiseFor(t, head*squatPct/100)
				f.ruleSet("squat", "own", sFix)
				for round := range 3 - btoi(raceDetector) {
					b := f.build()
					if bundlePolicy(b, "victim/web") == nil || bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vFix {
						c := f.accepted("victim", "web")
						t.Errorf("round %d: the victim's fix, or victim/web, isn't published (%s: %.250s)", round, c.Reason, c.Message)
					}
					f.wantAccepted("victim", "web")
					crs := bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS
					squat := bundleRuleSet(b, "WAFRuleSet/squat/own").GetSeclang() == sFix
					switch {
					case squatPct == 30 && (!crs || !squat):
						t.Errorf("round %d: the smaller squat's change (%t) or the CRS upgrade (%t) isn't published", round, squat, crs)
					case squatPct == 70 && round == 0 && (crs || squat):
						t.Errorf("round %d: the CRS upgrade (%t) doesn't wait for squat, or squat's change (%t) is published", round, crs, squat)
					case squatPct == 70 && round > 0 && (!crs || !squat || bundlePolicy(b, "squat/web") == nil):
						t.Errorf("round %d: the CRS upgrade waits a second build (%t), or squat's change (%t) or squat/web isn't "+
							"published", round, !crs, squat)
					}
					if free := 100 * f.head() / f.lim.gz; free < 10-2*adoptionCap {
						t.Errorf("round %d: the bundle leaves %d%% free: the adopting changes took more than 2 x adoptionCap of the "+
							"reserve", round, free)
					}
					f.wantFits(b)
				}
			})
		})
	}
}

// A squatter doesn't draw down the reserve with ballast (review 7, finding
// 2): squat binds the CRS and squats the rule id its upgrade adds; the
// bundle leaves 12% free, and at the upgrade squat ships a change that
// grows it by 9%, into the reserve. From 20% of the bundle, that takes it
// past its share (25%): it is held over its share, squat/web is left out,
// and the CRS upgrade is published in the same build. From 10%, within its
// share, its change grows its share by more than adoptionCap, so it isn't
// prior and may not grow the bundle into the reserve: it is held, the CRS
// upgrade waits one build for it, then is published and squat/web is left
// out. Either way the reserve stays free.
func TestP6SquatterReserveWithinShare(t *testing.T) {
	t.Parallel()
	for _, basePct := range []int{20, 10} {
		if basePct == 10 && raceDetector {
			continue // within its share: not under the race detector
		}
		t.Run(fmt.Sprintf("base=%d%%", basePct), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(nil) // its default, 10%
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				sBase := noiseFor(t, f.lim.gz*basePct/100)
				f.ruleSet("squat", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+sBase)
				f.tenant("squat", "web", "own", "cluster:crs")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 6, f.lim.gz*12/100)

				f.clusterRuleSet("crs", newCRS)
				sFix := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + sBase + noiseFor(t, f.lim.gz*9/100)
				f.ruleSet("squat", "own", sFix)
				var over, prior []bool
				f.r.fitOptions.observe = func(h fitted) { over, prior = append(over, h.over["squat"]), append(prior, h.prior["squat"]) }
				for round := range 2 {
					b := f.build()
					crs := bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS
					if want := basePct == 20 || round > 0; crs != want {
						t.Errorf("round %d: the CRS upgrade published %t, want %t: %+v", round, crs, want, f.ruleSetAccepted("", "crs"))
					}
					if bundleRuleSet(b, "WAFRuleSet/squat/own").GetSeclang() == sFix {
						t.Errorf("round %d: squat's change, which grows it by 9%%, into the reserve, is published", round)
					}
					if crs && bundlePolicy(b, "squat/web") != nil {
						t.Errorf("round %d: squat/web, whose previous version doesn't compile with the new CRS, is published", round)
					}
					if free := f.head() * 100 / f.lim.gz; free < 10 {
						t.Errorf("round %d: the bundle leaves %d%% free: squat's change drew down the reserve", round, free)
					}
					f.wantFits(b)
				}
				if slices.Contains(prior, true) || basePct == 20 && !slices.Equal(over, []bool{true, true}) {
					t.Errorf("squat prior %v, over its share %v", prior, over)
				}
			})
		})
	}
}

// A squatter can't pin the CRS with its own adoption: z squats the rule id
// of a CRS upgrade to come, and at the upgrade ships a change that drops
// it and that fits the limits without the upgrade (the room and the
// reserve), but not with it. Its change doesn't fit alone, so it isn't
// released first and the CRS doesn't wait for it: the upgrade is published
// in every round and z/web is left out, while y's small change is
// published. Measured with the CRS held, z's change would fit alone, be
// published against the CRS as it was, and leave the upgrade no room
// (without the cluster reserve). With the reserve and without it.
func TestBundleTooLargeSquatterCantPinWithAdoption(t *testing.T) {
	t.Parallel()
	for _, reserve := range []*int32{nil, new(int32)} {
		if reserve != nil && raceDetector {
			continue // without the reserve: not under the race detector
		}
		t.Run(fmt.Sprintf("reserve%v", reserve == nil), func(t *testing.T) { squatterCantPin(t, reserve) })
	}
}

func squatterCantPin(t *testing.T, reserve *int32) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.reserve(reserve)
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"` + "\n" + noiseFor(t, f.lim.gz*8/100)
		f.clusterRuleSet("crs", oldCRS)
		zBase := noiseFor(t, f.lim.gz*3/100)
		f.ruleSet("z", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+zBase)
		f.tenant("z", "web", "own", "cluster:crs")
		yWas := noiseFor(t, f.lim.gz*2/100)
		f.ruleSet("y", "own", yWas)
		f.tenant("y", "web", "own")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*20/100)
		head := f.head()

		f.clusterRuleSet("crs", newCRS)
		zFix := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + zBase + noiseFor(t, head*85/100)
		f.ruleSet("z", "own", zFix)
		yNow := yWas + noiseFor(t, f.lim.gz/100)
		f.ruleSet("y", "own", yNow)
		for round := range 3 - btoi(raceDetector) {
			b := f.build()
			if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
				t.Errorf("round %d: the CRS upgrade isn't published: %+v", round, f.ruleSetAccepted("", "crs"))
			}
			f.wantRuleSetAccepted("", "crs")
			if bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() == zFix || bundlePolicy(b, "z/web") != nil {
				t.Errorf("round %d: z's change, which doesn't fit with the CRS upgrade, or z/web is published", round)
			}
			if bundleRuleSet(b, "WAFRuleSet/y/own").GetSeclang() != yNow {
				t.Errorf("round %d: y's change isn't published: %+v", round, f.ruleSetAccepted("y", "own"))
			}
			f.wantFits(b)
		}
	})
}

// Review 6, finding 1 (TestP6ProtectedLeftOut): v binds the CRS, its rule
// set uses the rule id the upgrade adds, and it ships its fix with the
// upgrade; the fix fits alone and grows its share by less than
// adoptionCap. a, smaller and without the CRS, makes a change sized to
// take the room v's fix needs. v's change, which adopts the upgrade, is
// released before a's: v's fix and the CRS upgrade are published in the
// first build, and v/web stays published in every round, while a's change,
// which no longer fits, is held. With the cluster reserve and without it.
// (A fix that grows its share by more is ranked by share, like a's change:
// TestP5LastJumpsQueue.)
func TestP6ProtectedLeftOut(t *testing.T) {
	t.Parallel()
	for _, reserve := range []int32{0, 10} {
		if reserve == 0 && raceDetector {
			continue // without the reserve: not under the race detector
		}
		t.Run(fmt.Sprintf("reserve=%d", reserve), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(&reserve)
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				vBase := noiseFor(t, f.lim.gz*8/100)
				f.ruleSet("v", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
				f.tenant("v", "web", "own", "cluster:crs")
				aBase := noiseFor(t, f.lim.gz*2/100)
				f.ruleSet("a", "own", aBase)
				f.tenant("a", "web", "own")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 5, f.lim.gz*(int(reserve)+5)/100)
				head := f.head() - f.lim.gz*int(reserve)/100

				f.clusterRuleSet("crs", newCRS)
				vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + noiseFor(t, head*6/10)
				f.ruleSet("v", "own", vFix)
				aNow := aBase + noiseFor(t, head*6/10)
				f.ruleSet("a", "own", aNow)
				for round := range 4 - 2*btoi(raceDetector) {
					if round == 2 {
						aNow += noiseFor(t, f.lim.gz/100) // a grows again, within its share
						f.ruleSet("a", "own", aNow)
					}
					b := f.build()
					if bundlePolicy(b, "v/web") == nil {
						c := f.accepted("v", "web")
						t.Errorf("round %d: v/web, within its share and whose fix fits alone, is left out (%s: %.250s)", round, c.Reason, c.Message)
					}
					if bundleRuleSet(b, "WAFRuleSet/v/own").GetSeclang() != vFix || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
						t.Errorf("round %d: v's fix or the CRS upgrade isn't published", round)
					}
					f.wantAccepted("v", "web")
					if bundleRuleSet(b, "WAFRuleSet/a/own").GetSeclang() == aNow {
						t.Errorf("round %d: a's change, which doesn't fit after v's, is published", round)
					}
					f.wantFits(b)
				}
			})
		})
	}
}

// Review 6, finding 2 (TestP6ReserveLeavesOut): the bundle sits just
// above the reserve line (12% free); v binds the CRS, its rule set uses
// the rule id the upgrade adds, and it ships a 3% fix with the upgrade,
// which fits the limits. "Fits alone" is measured against the limits only,
// and v's change, which adopts the upgrade, may use the reserve: v's fix
// and the upgrade are published in the first build, and v/web stays in
// every round. With the cluster reserve and without it.
func TestP6ReserveLeavesOut(t *testing.T) {
	t.Parallel()
	for _, reserve := range []int32{0, 10} {
		if reserve == 0 && raceDetector {
			continue // without the reserve: not under the race detector
		}
		t.Run(fmt.Sprintf("reserve=%d", reserve), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(&reserve)
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				vBase := noiseFor(t, f.lim.gz*8/100)
				f.ruleSet("v", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
				f.tenant("v", "web", "own", "cluster:crs")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 6, f.lim.gz*12/100)

				f.clusterRuleSet("crs", newCRS)
				vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + noiseFor(t, f.lim.gz*3/100)
				f.ruleSet("v", "own", vFix)
				for round := range 3 - btoi(raceDetector) {
					b := f.build()
					if bundlePolicy(b, "v/web") == nil {
						c := f.accepted("v", "web")
						t.Errorf("round %d: v/web, within its share and whose fix fits the limits, is left out (%s: %.250s)", round, c.Reason, c.Message)
					}
					if bundleRuleSet(b, "WAFRuleSet/v/own").GetSeclang() != vFix || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
						t.Errorf("round %d: v's fix or the CRS upgrade isn't published", round)
					}
					f.wantAccepted("v", "web")
					f.wantRuleSetAccepted("", "crs")
					f.wantFits(b)
				}
			})
		})
	}
}

// Review 1's PoC and finding 1A (TestPoCWindowFreeze): pairs of identical
// rule sets, the second copy almost free compressed (gzip refers back
// across them); each second copy becomes noise, smaller alone but growing
// the whole bundle, while the bundle is full. They are held, and the
// victim's fix published: no freeze.
func TestPoCWindowFreeze(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		const pairs = 8
		var names []string
		for i := range pairs {
			r := noise(t, f.sz(30<<10))
			f.ruleSet("z", fmt.Sprintf("p%02da", i), r)
			f.ruleSet("z", fmt.Sprintf("p%02db", i), r)
			names = append(names, fmt.Sprintf("p%02da", i), fmt.Sprintf("p%02db", i))
		}
		f.tenant("z", "web", names...)
		f.tenant("b", "web")
		b1 := f.fillSpread("filler", 5, f.sz(60<<10))
		for i := range pairs {
			f.ruleSet("z", fmt.Sprintf("p%02db", i), noise(t, f.sz(26<<10)))
		}
		f.edit("b", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
		b2 := f.build()
		if b2.GetVersion() == b1.GetVersion() {
			t.Fatalf("frozen: the victim's change isn't published; b/web Accepted: %+v", f.accepted("b", "web"))
		}
		if p := bundlePolicy(b2, "b/web"); p.GetMode() != bundlev1.Mode_MODE_BLOCK {
			t.Errorf("b/web in bundle %d: %v, want its new mode", b2.GetVersion(), p)
		}
		f.wantAccepted("b", "web")
		for i := range pairs {
			f.wantRuleSetHeld("z", fmt.Sprintf("p%02db", i), "namespace z's content takes")
		}
		f.wantFits(b2)
	})
}

// Review 4's PoCs (poc4_test.go), with the fixed behaviour.

// P4-A (review 4, finding 1): make a victim look over its share without
// growing it. The 16
// compressed-share measurements (maxMeasured) go to the namespaces with the
// largest raw shares. The attacker has 16 namespaces of flat rules (raw
// larger than the victim's, compressing to nothing), each with a tiny change
// in the same sync. The victim's raw share is over the compressed budget
// less slack but its compressed share is tiny; unmeasured, it counts as
// over (fit.go:547) because its raw share didn't shrink. Combined with a CRS
// upgrade its old version doesn't compile with, its policy is left out.
func TestP4UnmeasuredVictim(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		gzBudget := f.lim.gz / 100 * 25
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		ballast := flat(gzBudget)
		f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`+"\n"+ballast)
		f.tenant("victim", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.build()
		f.wantAccepted("victim", "web")
		const k = 16
		for i := range k {
			f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10)))
			f.tenant(fmt.Sprintf("atk%02d", i), "web", "fill")
		}
		b := f.build()
		f.wantAccepted("victim", "web")
		t.Logf("before: bundle %d bytes compressed (%d%%), victim published=%v", f.lim.gz-f.head(), 100*(f.lim.gz-f.head())/f.lim.gz,
			bundlePolicy(b, "victim/web") != nil)

		// Same sync: admin upgrades the CRS, victim ships its fix, attacker
		// touches each of its 16 namespaces.
		f.clusterRuleSet("crs", newCRS)
		fix := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + ballast
		f.ruleSet("victim", "own", fix)
		for round := range 3 {
			for i := range k {
				f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10))+fmt.Sprintf("# r%d\n", round))
			}
			b := f.build()
			c := f.accepted("victim", "web")
			t.Logf("round %d: bundle %d%% compressed; victim/web in bundle=%v; %s/%s: %.300s", round, 100*(f.lim.gz-f.head())/f.lim.gz,
				bundlePolicy(b, "victim/web") != nil, c.Status, c.Reason, c.Message)
			t.Logf("round %d: new CRS published=%v", round, bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS)
			if bundlePolicy(b, "victim/web") == nil {
				t.Errorf("round %d: FAIL-OPEN: victim/web left out of the bundle", round)
			}
			if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != fix {
				t.Errorf("round %d: victim's fix held", round)
			}
			f.wantFits(b)
		}
	})
}

// P4-A without the CRS: just the victim's fix held indefinitely while
// the attacker churns (a fix-DoS, not fail-open).
func TestP4UnmeasuredVictimFixHeld(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		gzBudget := f.lim.gz / 100 * 25
		f.ruleSet("victim", "own", flat(gzBudget))
		f.tenant("victim", "web", "own")
		f.build()
		f.wantAccepted("victim", "web")
		const k = 16
		for i := range k {
			f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10)))
			f.tenant(fmt.Sprintf("atk%02d", i), "web", "fill")
		}
		f.build()
		fix := flat(gzBudget) + `SecRule ARGS "@contains evil" "id:100009,phase:1,deny,status:403"`
		f.ruleSet("victim", "own", fix)
		for i := range k {
			f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10))+"# x\n")
		}
		b := f.build()
		if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != fix {
			t.Errorf("victim's fix held: %.300s", f.ruleSetAccepted("victim", "own").Message)
		}
	})
}

// P4-B: shared cluster content. Attacker and victim both bind a big
// ClusterWAFRuleSet; the attacker unbinds it in the sync the victim makes
// a change, so the cluster rule set moves into the victim's share.
func TestP4SharedClusterMovesToVictim(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		big := noiseFor(t, f.lim.gz*20/100)
		f.clusterRuleSet("big", big)
		f.ruleSet("victim", "own", noiseFor(t, f.lim.gz*8/100))
		f.tenant("victim", "web", "own", "cluster:big")
		f.tenant("atk", "web", "cluster:big")
		f.build()
		f.wantAccepted("victim", "web")
		f.edit("atk", "web", func(p *wafv1alpha1.WAFPolicy) { p.Spec.RuleSets = nil })
		fix := noiseFor(t, f.lim.gz*8/100) + "\n" + `SecRule ARGS "@contains evil" "id:100009,phase:1,deny,status:403"`
		f.ruleSet("victim", "own", fix)
		b := f.build()
		if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != fix {
			t.Errorf("victim's fix held: %.300s", f.ruleSetAccepted("victim", "own").Message)
		}
	})
}

// P4-C: single tenant, first install, every policy in one namespace taking
// 30% of the compressed limit (fits easily). Upstream publishes it.
func TestP4SingleTenantFirstInstall(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		for i := range 6 {
			f.ruleSet("prod", fmt.Sprintf("rs%d", i), noiseFor(t, f.lim.gz*5/100))
			f.tenant("prod", fmt.Sprintf("web%d", i), fmt.Sprintf("rs%d", i))
		}
		b := f.build()
		t.Logf("bundle %d bytes, %d%% of the compressed limit, %d policies", f.lim.gz-f.head(), 100*(f.lim.gz-f.head())/f.lim.gz, len(b.GetPolicies()))
		for i := range 6 {
			if bundlePolicy(b, fmt.Sprintf("prod/web%d", i)) == nil {
				t.Errorf("REGRESSION: prod/web%d not published: %.200s", i, f.accepted("prod", fmt.Sprintf("web%d", i)).Message)
			}
		}
	})
}

// P4-D: single tenant already at 30% (installed with a share of 100, then
// back to the default, as after an upgrade from an unfixed release) adds
// one small policy.
func TestP4SingleTenantGrowth(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.share(100)
		for i := range 6 {
			f.ruleSet("prod", fmt.Sprintf("rs%d", i), noiseFor(t, f.lim.gz*5/100))
			f.tenant("prod", fmt.Sprintf("web%d", i), fmt.Sprintf("rs%d", i))
		}
		f.build()
		f.share(0)
		f.build()
		f.ruleSet("prod", "new", noiseFor(t, f.sz(4<<10)))
		f.tenant("prod", "new", "new")
		b := f.build()
		if bundlePolicy(b, "prod/new") == nil {
			t.Errorf("REGRESSION: prod/new (4 KiB, bundle at %d%%) not published: %.250s", 100*(f.lim.gz-f.head())/f.lim.gz,
				f.accepted("prod", "new").Message)
		}
	})
}

// P4-A with the budget's gate on: the bundle is near full, so the budget
// applies. The victim, whose holding would leave out its policy, is
// measured first, and is within its share; with an encode cap that
// measures nobody, it isn't measured, and so is within its share too.
// Either way its fix and the CRS upgrade are published, and its policy
// stays.
func TestP4UnmeasuredVictimGated(t *testing.T) {
	t.Parallel()
	for _, maxEncodes := range []int{0, 8} {
		t.Run(fmt.Sprintf("maxEncodes%d", maxEncodes), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				gzBudget := f.lim.gz / 100 * 25
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				ballast := flat(gzBudget)
				f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`+"\n"+ballast)
				f.tenant("victim", "web", "own", "cluster:crs")
				const k = 16
				for i := range k {
					f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10)))
					f.tenant(fmt.Sprintf("atk%02d", i), "web", "fill")
				}
				f.fillSpread("filler", 5, f.sz(300<<10))
				f.wantAccepted("victim", "web")
				f.r.fitOptions.maxEncodes = maxEncodes
				var gated []bool
				f.r.fitOptions.observe = func(h fitted) { gated = append(gated, h.gated) }

				f.clusterRuleSet("crs", newCRS)
				fix := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + ballast
				f.ruleSet("victim", "own", fix)
				for i := range k {
					f.ruleSet(fmt.Sprintf("atk%02d", i), "fill", flat(gzBudget+f.sz(64<<10))+"# x\n")
				}
				b := f.build()
				if !slices.Equal(gated, []bool{true}) {
					t.Fatalf("gated %v, want [true]: the test needs the budget to apply", gated)
				}
				if bundlePolicy(b, "victim/web") == nil {
					t.Error("victim/web is left out")
				}
				if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != fix {
					t.Errorf("the victim's fix is held: %s", f.ruleSetAccepted("victim", "own").Message)
				}
				if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
					t.Error("the CRS upgrade is held")
				}
				f.wantAccepted("victim", "web")
				f.wantFits(b)
			})
		})
	}
}

// Review 5, finding 1 (TestP5PinCRS): z, one namespace with edit rights,
// squats rule id 100001, which the next CRS adds. When the admin upgrades,
// z keeps a change pending, refreshed every round, that drops the id and
// adds ballast under its share but larger than the room left. z's change
// doesn't fit even alone, so z/web is left out (rule R (a)), and the CRS
// upgrade and every other tenant's fix are published in every round; the
// CRS never says Accepted while it isn't published (6 rounds, 3 under the
// race detector). With the cluster reserve, and without it (not under the
// race detector).
func TestP5PinCRS(t *testing.T) {
	t.Parallel()
	for _, reserve := range []*int32{nil, new(int32)} {
		if reserve != nil && raceDetector {
			continue // without the reserve: not under the race detector
		}
		t.Run(fmt.Sprintf("reserve%v", reserve == nil), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(reserve)
				gzBudget := f.lim.gz / 100 * defaultNamespaceShare
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				f.ruleSet("z", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`)
				f.tenant("z", "web", "own", "cluster:crs")
				f.ruleSet("victim", "own", `SecRule ARGS "@contains v" "id:200000,phase:1,pass,nolog"`)
				f.tenant("victim", "web", "own", "cluster:crs")
				f.ruleSet("nocrs", "own", `SecRule ARGS "@contains n" "id:300000,phase:1,pass,nolog"`)
				f.tenant("nocrs", "web", "own")
				// Legit tenants fill the bundle to 15% free.
				f.fillSpread("filler", 5, f.lim.gz*15/100)

				f.clusterRuleSet("crs", newCRS)
				rounds := 6
				if raceDetector {
					rounds = 3
				}
				for round := range rounds {
					pending := `SecRule ARGS "@contains x" "id:100777,phase:1,pass,nolog"` + "\n" +
						noiseFor(t, min(gzBudget-f.sz(96<<10), f.head()+f.sz(200<<10))) + fmt.Sprintf("# r%d\n", round)
					f.ruleSet("z", "own", pending)
					vfix := fmt.Sprintf(`SecRule ARGS "@contains v%d" "id:4100%02d,phase:1,deny,status:403"`, round, round)
					f.ruleSet("victim", "own", vfix)
					nfix := fmt.Sprintf(`SecRule ARGS "@contains n%d" "id:5100%02d,phase:1,deny,status:403"`, round, round)
					f.ruleSet("nocrs", "own", nfix)
					b := f.build()
					if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
						t.Errorf("round %d: the CRS upgrade isn't published: %+v", round, f.ruleSetAccepted("", "crs"))
					}
					f.wantRuleSetAccepted("", "crs")
					if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vfix || bundleRuleSet(b, "WAFRuleSet/nocrs/own").GetSeclang() != nfix {
						t.Errorf("round %d: a tenant's small fix isn't published", round)
					}
					if round == 0 {
						f.wantRuleSetHeld("z", "own", "its change doesn't fit even alone")
					}
					f.wantHeld("z", "web", "")
					if bundlePolicy(b, "z/web") != nil {
						t.Errorf("round %d: z/web, whose rules don't compile with the new CRS, is in the bundle", round)
					}
					f.wantFits(b)
				}
			})
		})
	}
}

// Review 5, finding 2 (TestP5SVictimLeftOut): against "the largest raw
// growth first". The victim's fix for the CRS upgrade grows its raw content
// by a few bytes; the attacker also squats the CRS's new id, and its change
// swaps flat comments for noise of the same raw length: no raw growth,
// compressed growth larger than the room. Ranked by share, the attacker is
// held, and left out (its change doesn't fit alone); the victim's fix and
// the CRS upgrade are published.
func TestP5SVictimLeftOut(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		ballast := noiseFor(t, f.lim.gz*12/100)
		f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,pass,nolog"`+"\n"+ballast)
		f.tenant("victim", "web", "own", "cluster:crs")
		flatPart := flat(f.lim.gz * 8 / 100)
		f.ruleSet("atk", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+flatPart)
		f.tenant("atk", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*3/100)

		f.clusterRuleSet("crs", newCRS)
		fix := `SecRule ARGS "@contains x" "id:100005,phase:1,pass,nolog"` + "\n" + ballast + "# fixed for the new CRS\n"
		f.ruleSet("victim", "own", fix)
		f.ruleSet("atk", "own", rawNeutral(t, `SecRule ARGS "@contains q" "id:100777,phase:1,pass,nolog"`,
			`SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+flatPart))
		b := f.build()
		if bundlePolicy(b, "victim/web") == nil {
			c := f.accepted("victim", "web")
			t.Errorf("victim/web left out (%s: %.250s)", c.Reason, c.Message)
		}
		if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != fix || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
			t.Error("the victim's fix or the CRS upgrade isn't published")
		}
		f.wantAccepted("victim", "web")
		f.wantRuleSetHeld("atk", "own", "")
		f.wantFits(b)
	})
}

// rawNeutral is rules that start with head, then noise, padded with
// comments to the raw length of was: no raw growth, compressed growth.
func rawNeutral(t *testing.T, head, was string) string {
	t.Helper()
	out := head + "\n" + noise(t, len(was)-len(head)-200)
	return out + strings.Repeat("#", max(0, len(was)-len(out)-1)) + "\n"
}

// Review 5, finding 2 (TestP5SPinRawNeutral): an attacker that squats the
// CRS's new id makes a change that doesn't grow its raw content, only its
// compressed one, larger than the room. Its change doesn't fit alone, so
// it is left out and the CRS upgrade is published, in every round.
func TestP5SPinRawNeutral(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		was := `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"` + "\n" + flat(f.lim.gz*15/100)
		f.ruleSet("atk", "own", was)
		f.tenant("atk", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*5/100)
		f.clusterRuleSet("crs", newCRS)
		for round := range 3 - btoi(raceDetector) {
			f.ruleSet("atk", "own", rawNeutral(t, `SecRule ARGS "@contains q" "id:100777,phase:1,pass,nolog"`, was))
			b := f.build()
			if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
				t.Errorf("round %d: the CRS upgrade isn't published: %+v", round, f.ruleSetAccepted("", "crs"))
			}
			if bundlePolicy(b, "atk/web") != nil {
				t.Errorf("round %d: atk/web, whose rules don't compile with the new CRS, is in the bundle", round)
			}
			f.wantFits(b)
		}
	})
}

// Review 5, finding 3 (TestP5LastJumpsQueue), and review 7, finding 2: z
// binds the CRS and its rule set uses a rule id, which the CRS upgrade
// adds (z squats it) or not; the victim (smaller share, no CRS binding)
// and z each want about 60% of the room in the same sync. Squatting, z's
// change drops the id and adds ballast: it grows its share by more than
// adoptionCap, so it isn't prior and doesn't jump the queue. The victim's
// change, with the smaller share, is published; z's is held, the CRS
// upgrade waits a build for it, and next build the upgrade is published and
// z/web is left out (z's change no longer fits alone). Without the squat,
// the victim is released first and the upgrade published in the first
// build. Adopting (z's change only drops the id, and grows within
// adoptionCap, the victim's takes the room), z's change is released first:
// it is published with the upgrade and the victim's waits; that priority
// lasts one build, and when both change again (each to take about 60% of
// the room left), the victim, with the smaller share, is released.
func TestP5LastJumpsQueue(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"squat", "adopt", "control"} {
		if kind != "squat" && raceDetector {
			continue // the adoption and the control: not under the race detector
		}
		t.Run(kind, func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				id := "100001"
				if kind == "control" {
					id = "100009"
				}
				zBase := noiseFor(t, f.lim.gz*6/100)
				zWas := `SecRule ARGS "@contains x" "id:` + id + `,phase:1,pass,nolog"` + "\n" + zBase
				f.ruleSet("z", "own", zWas)
				f.tenant("z", "web", "own", "cluster:crs")
				vWas := noiseFor(t, f.lim.gz*2/100)
				f.ruleSet("victim", "own", vWas)
				f.tenant("victim", "web", "own")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 5, f.lim.gz*10/100)
				head := f.head()
				f.clusterRuleSet("crs", newCRS)
				zGrow, vGrow := head*6/10, head*6/10
				if kind == "adopt" {
					// Both don't fit, by 15% of the room: wide of how far a
					// size may be off (review 8, B).
					zGrow, vGrow = head*3/10, head*85/100
				}
				zNow := `SecRule ARGS "@contains x" "id:100777,phase:1,pass,nolog"` + "\n" + zBase + noiseFor(t, zGrow)
				f.ruleSet("z", "own", zNow)
				vfix := vWas + noiseFor(t, vGrow)
				f.ruleSet("victim", "own", vfix)
				var prior []bool
				f.r.fitOptions.observe = func(h fitted) { prior = append(prior, h.prior["z"]) }
				b := f.build()
				zPublished, vPublished := bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() == zNow,
					bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() == vfix
				crs := bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS
				switch kind {
				case "squat":
					if zPublished || !vPublished || crs || !slices.Equal(prior, []bool{false}) {
						t.Errorf("build 0: z's ballast jumps the queue (published %t, prior %v), the victim's change (smaller share) is "+
							"held (%t), or the CRS upgrade doesn't wait for z (%t): %s", zPublished, prior, !vPublished, crs,
							f.ruleSetAccepted("victim", "own").Message)
					}
					f.wantRuleSetHeld("z", "own", "isn't released before the other namespaces' changes")
				case "adopt":
					if !zPublished || vPublished || !crs {
						t.Errorf("build 0: z's change, which adopts the CRS upgrade, isn't released first (%t, %t) or the upgrade isn't "+
							"published (%t): %s", zPublished, vPublished, crs, f.ruleSetAccepted("z", "own").Message)
					}
					f.wantRuleSetHeld("victim", "own", "are released before the others")
				default:
					if zPublished || !vPublished || !crs {
						t.Errorf("build 0: the victim's change (smaller share) is held, or the CRS upgrade isn't published: %s",
							f.ruleSetAccepted("victim", "own").Message)
					}
				}
				f.wantFits(b)
				switch kind {
				case "squat":
					b = f.build()
					if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS || bundlePolicy(b, "z/web") != nil ||
						bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vfix {
						t.Errorf("build 1: the CRS upgrade waits a second build, z/web (its change no longer fits) is in, or the " +
							"victim's change isn't")
					}
					f.wantFits(b)
				case "adopt":
					// No priority any more: by share.
					head = f.head()
					zNext := zNow + noiseFor(t, head*6/10)
					f.ruleSet("z", "own", zNext)
					vNext := vWas + noiseFor(t, head*6/10)
					f.ruleSet("victim", "own", vNext)
					b = f.build()
					if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vNext || bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() != zNow {
						t.Errorf("build 1: the victim's change (smaller share) is held, or z's is published: %s", f.ruleSetAccepted("victim", "own").Message)
					}
					f.wantFits(b)
				}
			})
		})
	}
}

// The cluster reserve (spec.bundle.clusterReserve, here 20%): a
// namespace's change that would grow the bundle into it is held, saying
// so, and counted as held, while another namespace's shrinking change is
// published; a CRS change may use the reserve. Without the reserve, the
// namespace's change is published.
func TestBundleTooLargeReserve(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		reserve := int32(20)
		f.reserve(&reserve)
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		f.clusterRuleSet("crs", oldCRS)
		aWas := noiseFor(t, f.lim.gz*5/100)
		f.ruleSet("a", "own", aWas)
		f.tenant("a", "web", "own", "cluster:crs")
		f.ruleSet("b", "own", noiseFor(t, f.lim.gz*5/100))
		f.tenant("b", "web", "own", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*25/100)

		aNow := aWas + noiseFor(t, f.lim.gz*12/100)
		f.ruleSet("a", "own", aNow)
		bNow := noiseFor(t, f.lim.gz*2/100)
		f.ruleSet("b", "own", bNow)
		var held []int
		var reserved []bool
		f.r.fitOptions.observe = func(h fitted) { held, reserved = append(held, heldCount(h)), append(reserved, h.reserved) }
		b := f.build()
		if bundleRuleSet(b, "WAFRuleSet/b/own").GetSeclang() != bNow || bundleRuleSet(b, "WAFRuleSet/a/own").GetSeclang() != aWas {
			t.Error("b's shrinking change isn't published, or a's change into the reserve is")
		}
		f.wantRuleSetHeld("a", "own", "spec.bundle.clusterReserve free (20%)")
		f.wantAccepted("a", "web")
		if !slices.Equal(held, []int{1}) || !slices.Equal(reserved, []bool{true}) {
			t.Errorf("held %v, reserved %v, want [1] [true]", held, reserved)
		}
		if free := f.head() * 100 / f.lim.gz; free < 20 {
			t.Errorf("the published bundle leaves %d%% free, under the reserve", free)
		}

		// A CRS upgrade uses the reserve; a's change still waits.
		newCRS := oldCRS + "\n" + noiseFor(t, f.lim.gz*6/100)
		f.clusterRuleSet("crs", newCRS)
		b = f.build()
		if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
			t.Errorf("the CRS upgrade, which may use the reserve, isn't published: %+v", f.ruleSetAccepted("", "crs"))
		}
		f.wantRuleSetAccepted("", "crs")
		f.wantRuleSetHeld("a", "own", "spec.bundle.clusterReserve")
		f.wantFits(b)

		// Without the reserve, a's change fits.
		f.reserve(new(int32))
		b = f.build()
		if bundleRuleSet(b, "WAFRuleSet/a/own").GetSeclang() != aNow {
			t.Errorf("a's change, which fits, isn't published without the reserve: %+v", f.ruleSetAccepted("a", "own"))
		}
		f.wantFits(b)
	})
}

// The cluster reserve never applies to a single tenant, nor to a first
// bundle: a bundle that fits is published as before the reserve.
func TestBundleTooLargeReserveExempt(t *testing.T) {
	t.Parallel()
	t.Run("single tenant", func(t *testing.T) { sizeTest(t, false, reserveSingleTenant) })
	t.Run("first bundle", func(t *testing.T) { sizeTest(t, false, reserveFirstBundle) })
}

func reserveSingleTenant(t *testing.T, f *fitCluster) {
	{
		f.reserve(nil)
		for i := range 17 {
			f.ruleSet("prod", fmt.Sprintf("rs%d", i), noiseFor(t, f.lim.gz*5/100))
			f.tenant("prod", fmt.Sprintf("web%d", i), fmt.Sprintf("rs%d", i))
		}
		// 10% free, measured, then 7%: into the reserve.
		f.ruleSet("prod", "top", "# top\n")
		f.tenant("prod", "top", "top")
		f.build()
		f.topUp("prod", "top", "# top\n", f.lim.gz*10/100)
		f.ruleSet("prod", "new", noiseFor(t, f.lim.gz*3/100))
		f.tenant("prod", "new", "new")
		b := f.build()
		if bundlePolicy(b, "prod/new") == nil || f.head() > f.lim.gz*10/100 {
			t.Errorf("a single tenant's policy isn't published, or the bundle leaves %d of %d free", f.head(), f.lim.gz)
		}
		f.wantAccepted("prod", "new")
		f.wantFits(b)
	}
}

func reserveFirstBundle(t *testing.T, f *fitCluster) {
	{
		f.reserve(nil)
		// 95% of the limit: the first 18 measured, the last sized to the
		// rest (a first bundle can't be topped up: review 8, B).
		total := 0
		for i := range 19 {
			ns := fmt.Sprintf("t%02d", i)
			rules := noiseFor(t, f.lim.gz*5/100)
			if i == 18 {
				rules = noiseFor(t, f.lim.gz*95/100-total)
			}
			total += gzSize(&bundlev1.RuleSet{Source: &bundlev1.RuleSet_Seclang{Seclang: rules}})
			f.ruleSet(ns, "rs", rules)
			f.tenant(ns, "web", "rs")
		}
		b := f.build()
		for i := range 19 {
			f.wantAccepted(fmt.Sprintf("t%02d", i), "web")
		}
		if f.head() > f.lim.gz*10/100 {
			t.Errorf("the first bundle leaves %d of %d free, the reserve", f.head(), f.lim.gz)
		}
		f.wantFits(b)
	}
}

// A namespace over its share at rest, and only such a namespace, is
// reported (inkwall_operator_bundle_namespace_share_percent): published
// with a share of 100%, then measured with the default.
func TestBundleNamespaceShareMetric(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.share(100)
		f.ruleSet("big", "rs", noiseFor(t, f.lim.gz*40/100))
		f.tenant("big", "web", "rs")
		f.ruleSet("small", "rs", noiseFor(t, f.lim.gz*5/100))
		f.tenant("small", "web", "rs")
		b := f.build()
		signer, err := bundle.GenerateSigner()
		if err != nil {
			t.Fatal(err)
		}
		over, err := overShares(b, signer, f.lim, 100)
		if err != nil || len(over) > 0 {
			t.Errorf("over a share of 100%%: %v %v", over, err)
		}
		over, err = overShares(b, signer, f.lim, defaultNamespaceShare)
		if err != nil || len(over) != 1 || over["big"] < 35 || over["big"] > 45 {
			t.Errorf("over a share of %d%%: %v %v, want big at about 40", defaultNamespaceShare, over, err)
		}
	})
}

// Review 7, finding 2 (TestP7SquatterDrainsReserve): z binds the CRS and
// squats the rule id its upgrade adds (or not: the control); the bundle
// leaves 11% free, over the default reserve (10%). At the upgrade z drops
// the id and adds ballast unrelated to it that would leave 1% free,
// within its share. That grows z's share by more than adoptionCap, so its
// change isn't prior: it isn't released first, may not grow the bundle
// into the reserve, and the reserve stays free. Then y's growth (1%) is
// published in every round, and so is the admin's next CRS change (2%).
// Squatting, the CRS upgrade waits one build for z at most.
func TestP7SquatterDrainsReserve(t *testing.T) {
	t.Parallel()
	for _, squat := range []bool{true, false} {
		if !squat && raceDetector {
			continue // the control: not under the race detector
		}
		t.Run(fmt.Sprintf("squat=%v", squat), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(nil) // its default, 10%
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				id := "100009"
				if squat {
					id = "100001"
				}
				zBase := noiseFor(t, f.lim.gz*5/100)
				f.ruleSet("z", "own", `SecRule ARGS "@contains q" "id:`+id+`,phase:1,pass,nolog"`+"\n"+zBase)
				f.tenant("z", "web", "own", "cluster:crs")
				yWas := noiseFor(t, f.lim.gz*2/100)
				f.ruleSet("y", "own", yWas)
				f.tenant("y", "web", "own")
				f.tenant("other", "web", "cluster:crs")
				f.fillSpread("filler", 5, f.lim.gz*12/100)

				f.clusterRuleSet("crs", newCRS)
				zFix := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + zBase + noiseFor(t, f.head()-f.lim.gz*15/1000)
				f.ruleSet("z", "own", zFix)
				var prior []bool
				f.r.fitOptions.observe = func(h fitted) { prior = append(prior, h.prior["z"]) }
				b := f.build()
				if bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() == zFix {
					t.Error("round 0: z's ballast, past the reserve line, is published")
				}
				if free := 100 * f.head() / f.lim.gz; free < 10 {
					t.Errorf("round 0: the bundle leaves %d%% free: z's change took the reserve", free)
				}
				crsHeld := btoi(bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS)
				f.wantFits(b)
				for round := 1; round <= 3; round++ {
					yNow := yWas + noiseFor(t, f.lim.gz/100)
					f.ruleSet("y", "own", yNow)
					b = f.build()
					if bundleRuleSet(b, "WAFRuleSet/y/own").GetSeclang() != yNow {
						t.Errorf("round %d: y's 1%% growth is held: %.250s", round, f.ruleSetAccepted("y", "own").Message)
					}
					if round == 1 && bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
						t.Errorf("round 1: the CRS upgrade waits a second build: %+v", f.ruleSetAccepted("", "crs"))
					}
					f.wantFits(b)
				}
				if slices.Contains(prior, true) || crsHeld > btoi(squat) {
					t.Errorf("z prior %v; the CRS upgrade held in round 0 %d, want at most %d", prior, crsHeld, btoi(squat))
				}
				crs3 := newCRS + "\n" + `SecRule ARGS "@contains w" "id:100003,phase:1,deny,status:403"` + "\n" + noiseFor(t, f.lim.gz*2/100)
				f.clusterRuleSet("crs", crs3)
				for round := 4; round <= 5; round++ {
					b = f.build()
					if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != crs3 {
						t.Errorf("round %d: the next CRS change (2%%) is held: %+v", round, f.ruleSetAccepted("", "crs"))
					}
					f.wantFits(b)
				}
			})
		})
	}
}

// Review 7, finding 1 (TestP7CapLeavesOutVictim): n namespaces a00.. (one
// tenant, each within its share) bind the CRS and squat the rule id its
// upgrade adds, which the victim vic, sorted after them, uses. At the
// upgrade each squatter ships a change that fits alone (40% of the room),
// so together they don't fit, and vic ships a few bytes' fix. With 40
// squatters the encode cap can't measure every one alone. vic's change,
// the smallest, is measured first, is prior and released first: vic/web is
// published in every round, with its fix, and the CRS upgrade waits one
// build at most. With 31 squatters too.
func TestP7CapLeavesOutVictim(t *testing.T) {
	t.Parallel()
	for _, n := range []int{40, 31} {
		if n == 31 && raceDetector {
			continue // 31: not under the race detector
		}
		t.Run(fmt.Sprintf("squatters=%d", n), func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) { capLeavesOutVictim(t, f, n) })
		})
	}
}

func capLeavesOutVictim(t *testing.T, f *fitCluster, n int) {
	oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
	newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
	f.clusterRuleSet("crs", oldCRS)
	aBase := make([]string, n)
	for i := range n {
		ns := fmt.Sprintf("a%02d", i)
		aBase[i] = noiseFor(t, f.lim.gz*3/1000)
		f.ruleSet(ns, "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+aBase[i])
		f.tenant(ns, "web", "own", "cluster:crs")
	}
	vBase := noiseFor(t, f.lim.gz*3/100)
	f.ruleSet("vic", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
	f.tenant("vic", "web", "own", "cluster:crs")
	yWas := noiseFor(t, f.lim.gz/100)
	f.ruleSet("y", "own", yWas)
	f.tenant("y", "web", "own")
	f.fillSpread("filler", 5, f.lim.gz*12/100)
	head := f.head()

	f.clusterRuleSet("crs", newCRS)
	for i := range n {
		ns := fmt.Sprintf("a%02d", i)
		f.ruleSet(ns, "own", `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"`+"\n"+aBase[i]+noiseFor(t, head*4/10))
	}
	vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + "# fix\n"
	f.ruleSet("vic", "own", vFix)
	f.ruleSet("y", "own", yWas+"# small\n")
	crsHeld := 0
	for round := range 3 - btoi(raceDetector) {
		f.r.fitOptions.observe = func(h fitted) {
			t.Logf("round %d fit: %d encodes, %d held, vic prior %t, guarded %t, measured %t, repaired %t; prior %d, guarded %d",
				round, h.encodes, heldCount(h), h.prior["vic"], h.guarded["vic"], h.alone["vic"], h.repaired, len(h.prior), len(h.guarded))
		}
		b := f.build()
		if bundlePolicy(b, "vic/web") == nil || bundleRuleSet(b, "WAFRuleSet/vic/own").GetSeclang() != vFix {
			c := f.accepted("vic", "web")
			t.Errorf("round %d: vic/web, within its share, whose few bytes' fix fits, or its fix isn't published (%s: %.250s)",
				round, c.Reason, c.Message)
		}
		f.wantAccepted("vic", "web")
		if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
			crsHeld++
		}
		f.wantFits(b)
	}
	if crsHeld > 1 {
		t.Errorf("the CRS upgrade is held %d builds", crsHeld)
	}
}

// The encode cap can't leave out a published policy untried (review 7,
// finding 1): with the cap at one encode, six namespaces bind the CRS and
// use the rule id its upgrade adds, and each ships a fix with it; four of
// the fixes fit together, not five. Past the cap (repair), the fixes are
// tried: in the first build the CRS waits and four of them are published,
// against the CRS as it was; in the next build the CRS is published and
// the two others are left out, which then don't fit even alone.
func TestBundleTooLargeCapRepair(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		const n = 6
		base := make([]string, n)
		for i := range n {
			ns := fmt.Sprintf("v%d", i)
			base[i] = noiseFor(t, f.lim.gz*2/100)
			f.ruleSet(ns, "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+base[i])
			f.tenant(ns, "web", "own", "cluster:crs")
		}
		f.fillSpread("filler", 5, f.lim.gz*6/100)
		head := f.head()

		f.clusterRuleSet("crs", newCRS)
		fix := make([]string, n)
		for i := range n {
			fix[i] = `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + base[i] + noiseFor(t, head*9/(10*(n-2)))
			f.ruleSet(fmt.Sprintf("v%d", i), "own", fix[i])
		}
		f.r.fitOptions.maxEncodes = 1
		var repaired []bool
		var encodes []int
		f.r.fitOptions.observe = func(h fitted) { repaired, encodes = append(repaired, h.repaired), append(encodes, h.encodes) }
		count := func(b *bundlev1.Bundle) (published, in int) {
			for i := range n {
				published += btoi(bundleRuleSet(b, fmt.Sprintf("WAFRuleSet/v%d/own", i)).GetSeclang() == fix[i])
				in += btoi(bundlePolicy(b, fmt.Sprintf("v%d/web", i)) != nil)
			}
			return published, in
		}
		b := f.build()
		if published, in := count(b); published != n-2 || in != n || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != oldCRS {
			t.Errorf("round 0: %d fixes published, %d policies in, want %d, %d, and the CRS waiting", published, in, n-2, n)
		}
		f.wantFits(b)
		b = f.build()
		if published, in := count(b); published != n-2 || in != n-2 || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != newCRS {
			t.Errorf("round 1: %d fixes published, %d policies in, want %d, %d, and the CRS published", published, in, n-2, n-2)
		}
		f.wantFits(b)
		if !slices.Equal(repaired, []bool{true, true}) || slices.ContainsFunc(encodes, func(e int) bool { return e < 2 }) {
			t.Errorf("repaired %v, encodes %v: the cap came first and repair should run past it", repaired, encodes)
		}
	})
}

// What adoptionCap leaves a squatter (review 7): z binds the CRS, squats
// the rule id its upgrade adds, and the bundle leaves 11% free, over the
// default reserve (10%). At the upgrade z drops the id and adds ballast
// just under adoptionCap (3%): that counts as adopting the upgrade, so it is
// released first and published with the upgrade, into the reserve, but
// it takes at most adoptionCap of it. At the next upgrade, which z squats
// again with the same ballast, and which another adopter, w, needs too, w's
// smaller fix goes first; z's ballast takes what is left of the part, and
// in the build after the wait it has none: the reserve keeps 10% - 2 x
// adoptionCap at least, and the admin's next CRS change (2%) is published.
func TestP7SquatterUnderCap(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.reserve(nil) // its default, 10%
		rules := func(ids ...string) string {
			out := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
			for _, id := range ids {
				out += "\n" + `SecRule ARGS "@contains c` + id + `" "id:` + id + `,phase:1,deny,status:403"`
			}
			return out
		}
		f.clusterRuleSet("crs", rules())
		zBase := noiseFor(t, f.lim.gz*5/100)
		f.ruleSet("z", "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+
			`SecRule ARGS "@contains r" "id:100003,phase:1,pass,nolog"`+"\n"+zBase)
		f.tenant("z", "web", "own", "cluster:crs")
		wBase := noiseFor(t, f.lim.gz*3/100)
		f.ruleSet("w", "own", `SecRule ARGS "@contains x" "id:100003,phase:1,pass,nolog"`+"\n"+wBase)
		f.tenant("w", "web", "own", "cluster:crs")
		f.tenant("other", "web", "cluster:crs")
		f.fillSpread("filler", 5, f.lim.gz*11/100)

		f.clusterRuleSet("crs", rules("100001"))
		zNow := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" +
			`SecRule ARGS "@contains r" "id:100003,phase:1,pass,nolog"` + "\n" + zBase + noiseFor(t, f.lim.gz*3/100)
		f.ruleSet("z", "own", zNow)
		var prior []bool
		f.r.fitOptions.observe = func(h fitted) { prior = append(prior, h.prior["z"]) }
		b := f.build()
		if bundleRuleSet(b, "WAFRuleSet/z/own").GetSeclang() != zNow || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != rules("100001") {
			t.Errorf("upgrade 1: z's change, under adoptionCap, or the upgrade isn't published (prior %v): %.300s", prior,
				f.ruleSetAccepted("z", "own").Message)
		}
		if free := 100 * f.head() / f.lim.gz; free < 10-adoptionCap {
			t.Errorf("upgrade 1: the bundle leaves %d%% free: z took more than adoptionCap of the reserve", free)
		}
		f.wantFits(b)

		// The next upgrade adds the id z's and w's rules use; z adds the
		// same ballast again, w a smaller fix.
		f.clusterRuleSet("crs", rules("100001", "100003"))
		zNext := `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" +
			`SecRule ARGS "@contains r" "id:100007,phase:1,pass,nolog"` + "\n" + zBase + noiseFor(t, f.lim.gz*3/100) + noiseFor(t, f.lim.gz*3/100)
		f.ruleSet("z", "own", zNext)
		wFix := `SecRule ARGS "@contains x" "id:100008,phase:1,pass,nolog"` + "\n" + wBase + noiseFor(t, f.lim.gz/100)
		f.ruleSet("w", "own", wFix)
		for round := range 2 {
			b = f.build()
			if bundleRuleSet(b, "WAFRuleSet/w/own").GetSeclang() != wFix {
				t.Errorf("upgrade 2, round %d: w's fix, smaller than z's ballast, isn't published: %.300s", round, f.ruleSetAccepted("w", "own").Message)
			}
			if free := 100 * f.head() / f.lim.gz; free < 10-2*adoptionCap {
				t.Errorf("upgrade 2, round %d: the bundle leaves %d%% free: adopting changes took more than adoptionCap of the "+
					"reserve per upgrade", round, free)
			}
			f.wantFits(b)
		}
		if bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != rules("100001", "100003") {
			t.Errorf("upgrade 2: the CRS upgrade waits a second build: %+v", f.ruleSetAccepted("", "crs"))
		}
		crs3 := rules("100001", "100003") + "\n" + noiseFor(t, f.lim.gz*2/100)
		f.clusterRuleSet("crs", crs3)
		if b = f.build(); bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() != crs3 {
			t.Errorf("the admin's next CRS change (2%%) is held: %+v", f.ruleSetAccepted("", "crs"))
		}
		f.wantFits(b)
	})
}

// Adopting changes share adoptionCap (review 7): the bundle leaves 11%
// free, over the default reserve (10%); the CRS upgrade adds the rule id
// that the victim's rules and three squatters' use. The victim ships a
// small fix, each squatter a change that grows it by 2%. Together they
// take 1% above the reserve line and 4% (adoptionCap) of the reserve at
// most: the victim's fix, the smallest, and two squatters' changes are
// published, against the CRS as it was, and the CRS waits a build for the
// third; next build it is published, with the third squatter's change,
// which the wait held while protected: it has a part of the reserve of its
// own then (review 8, finding 1). The reserve keeps 10% - adoptionCap in
// the wait, 10% - 2 x adoptionCap after.
func TestP7AdoptersShareCap(t *testing.T) {
	sizeTest(t, false, func(t *testing.T, f *fitCluster) {
		f.reserve(nil) // its default, 10%
		oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
		newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
		f.clusterRuleSet("crs", oldCRS)
		vBase := noiseFor(t, f.lim.gz*4/100)
		f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
		f.tenant("victim", "web", "own", "cluster:crs")
		const squatters = 3
		base := make([]string, squatters)
		for i := range squatters {
			ns := fmt.Sprintf("a%d", i)
			base[i] = noiseFor(t, f.lim.gz/100)
			f.ruleSet(ns, "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+base[i])
			f.tenant(ns, "web", "own", "cluster:crs")
		}
		f.fillSpread("filler", 5, f.lim.gz*11/100)

		f.clusterRuleSet("crs", newCRS)
		vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + noiseFor(t, f.lim.gz/200)
		f.ruleSet("victim", "own", vFix)
		sFix := make([]string, squatters)
		for i := range squatters {
			sFix[i] = `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"` + "\n" + base[i] + noiseFor(t, f.lim.gz*2/100)
			f.ruleSet(fmt.Sprintf("a%d", i), "own", sFix[i])
		}
		count := func(b *bundlev1.Bundle) (published, in int) {
			for i := range squatters {
				published += btoi(bundleRuleSet(b, fmt.Sprintf("WAFRuleSet/a%d/own", i)).GetSeclang() == sFix[i])
				in += btoi(bundlePolicy(b, fmt.Sprintf("a%d/web", i)) != nil)
			}
			return published, in
		}
		for round := range 2 {
			b := f.build()
			if bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() != vFix || bundlePolicy(b, "victim/web") == nil {
				t.Errorf("round %d: the victim's fix, the smallest, isn't published: %.300s", round, f.ruleSetAccepted("victim", "own").Message)
			}
			published, in := count(b)
			crs := bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS
			if published != squatters-1+round || in != squatters || crs != (round > 0) {
				t.Errorf("round %d: %d squatters' changes published, %d of their policies in, the CRS published %t; want %d, %d, %t",
					round, published, in, crs, squatters-1+round, squatters, round > 0)
			}
			if free := 100 * f.head() / f.lim.gz; free < 10-(1+round)*adoptionCap {
				t.Errorf("round %d: the bundle leaves %d%% free: the adopting changes took more than %d x adoptionCap of the reserve",
					round, free, 1+round)
			}
			f.wantFits(b)
		}
	})
}

// Review 8, finding 1: squatters smaller than a real adopter's fix can't
// starve it of the adoption part of the reserve. The bundle leaves 11%
// free (reserve 10%, default); the CRS upgrade adds the rule id that the
// victim's rules use and the squatters' squat. The victim ships a fix
// under adoptionCap (prior, protected); each squatter a change that grows
// it by less, but together by more than the room the prior namespaces get
// (about 1% above the reserve line and adoptionCap, measured): released
// first, the smallest first, they take it, and the victim's fix is held in
// the wait build, while the CRS waits. In the due build, the victim, held
// while protected, is carried: it has a part of the reserve of its own, so
// its fix is published with the upgrade and victim/web is never left out.
// The adopting changes take at most 2 x adoptionCap of the reserve. The
// shapes, as parts of a room of about 5%: 1 squatter x 2.5% against a 3%
// fix, 3 x 1.5% against a 2% fix, and the control, 3 x 2.5% against a 2%
// fix (the victim's is released first).
func TestP8ReleasedSquattersCantStarveAdopter(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name      string
		squatters int
		grow, fix int // per mille of the room: about 1% above the reserve line and adoptionCap
	}{
		{"1x2.5%<3%", 1, 500, 600},
		{"3x1.5%<2%", 3, 300, 400},
		{"control:3x2.5%>2%", 3, 500, 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			sizeTest(t, false, func(t *testing.T, f *fitCluster) {
				f.reserve(nil) // its default, 10%
				oldCRS := `SecRule ARGS "@contains y" "id:100002,phase:1,pass,nolog"`
				newCRS := oldCRS + "\n" + `SecRule ARGS "@contains z" "id:100001,phase:1,deny,status:403"`
				f.clusterRuleSet("crs", oldCRS)
				vBase := noiseFor(t, f.lim.gz*4/100)
				f.ruleSet("victim", "own", `SecRule ARGS "@contains x" "id:100001,phase:1,deny,status:403"`+"\n"+vBase)
				f.tenant("victim", "web", "own", "cluster:crs")
				base := make([]string, c.squatters)
				for i := range c.squatters {
					ns := fmt.Sprintf("a%d", i)
					base[i] = noiseFor(t, f.lim.gz/100)
					f.ruleSet(ns, "own", `SecRule ARGS "@contains q" "id:100001,phase:1,pass,nolog"`+"\n"+base[i])
					f.tenant(ns, "web", "own", "cluster:crs")
				}
				f.fillSpread("filler", 5, f.lim.gz*11/100)
				free := 100 * f.head() / f.lim.gz
				// The room the prior namespaces have, measured: sized by it,
				// the shapes hold however far a size is off (review 8, B).
				room := f.head() - f.lim.gz/100*(defaultClusterReserve-adoptionCap)

				f.clusterRuleSet("crs", newCRS)
				vFix := `SecRule ARGS "@contains x" "id:100005,phase:1,deny,status:403"` + "\n" + vBase + noiseFor(t, room*c.fix/1000)
				f.ruleSet("victim", "own", vFix)
				for i := range c.squatters {
					f.ruleSet(fmt.Sprintf("a%d", i), "own", `SecRule ARGS "@contains q" "id:100006,phase:1,pass,nolog"`+"\n"+base[i]+
						noiseFor(t, room*c.grow/1000))
				}
				var log []string
				f.r.fitOptions.observe = func(h fitted) {
					log = append(log, fmt.Sprintf("held %v, prior %v, protected %v, carried %v, carry %v, encodes %d", heldNames(h),
						slices.Sorted(maps.Keys(h.prior)), slices.Sorted(maps.Keys(h.protected)), slices.Sorted(maps.Keys(h.carried)),
						slices.Sorted(maps.Keys(h.carry)), h.encodes))
				}
				fixed, upgraded := false, false
				for round := range 3 {
					b := f.build()
					if bundlePolicy(b, "victim/web") == nil {
						t.Errorf("round %d: victim/web, within its share, whose fix is under adoptionCap, is left out: %.300s", round,
							f.accepted("victim", "web").Message)
					}
					if round == 0 && c.grow < c.fix {
						// Held in the wait: told that victim/web is left out
						// next build unless its change fits then.
						f.wantRuleSetHeld("victim", "own", "If its change doesn't fit next build, when that change no longer waits, "+
							"that policy is left out")
					}
					fixed = fixed || bundleRuleSet(b, "WAFRuleSet/victim/own").GetSeclang() == vFix
					upgraded = upgraded || bundleRuleSet(b, "ClusterWAFRuleSet/crs").GetSeclang() == newCRS
					if round == 1 && (!fixed || !upgraded) {
						t.Errorf("round 1: the victim's fix (%t) or the CRS upgrade (%t) isn't published: %.300s", fixed, upgraded,
							f.ruleSetAccepted("victim", "own").Message)
					}
					if left := 100 * f.head() / f.lim.gz; left < 10-2*adoptionCap {
						t.Errorf("round %d: the bundle leaves %d%% free: the adopting changes took more than 2 x adoptionCap of the "+
							"reserve", round, left)
					}
					f.wantFits(b)
				}
				if t.Failed() {
					t.Logf("free before the upgrade %d%% (room %d), noise ratio %.4f; fits: %v", free, room, noiseRatio.r, log)
				}
			})
		})
	}
}

// gzAlone counts a namespace's gRPC schemas as its share does (review 8,
// finding 3): a schema that only its policies name is in its estimate, so
// a schema-heavy change isn't taken for an adoption's few bytes; one that
// another namespace's policy names too, or that none of its policies
// names, isn't.
func TestGzAloneSchemas(t *testing.T) {
	pol := func(id, schema string) *bundlev1.Policy {
		return &bundlev1.Policy{Id: id, Body: &bundlev1.BodyConfig{GrpcSchemaId: schema}}
	}
	b := &bundlev1.Bundle{Policies: []*bundlev1.Policy{pol("a/web", "s1"), pol("a/api", "s3"), pol("b/web", "s3"), pol("b/api", "s2")}}
	sizes := func(s1, s2, s3 int) (gz, raw int) {
		t.Helper()
		b.GrpcSchemas = nil
		for i, n := range []int{s1, s2, s3} {
			b.GrpcSchemas = append(b.GrpcSchemas, &bundlev1.GRPCSchema{Id: fmt.Sprintf("s%d", i+1), Source: noise(t, n)})
		}
		gz, err := gzAlone(b, "a")
		if err != nil {
			t.Fatal(err)
		}
		return gz, rawShare(b, "a")
	}
	gz, raw := sizes(100, 100, 100)
	if gzGrown, rawGrown := sizes(100<<10, 100, 100); gzGrown-gz < 40<<10 || rawGrown-raw < 100<<10-100 {
		t.Errorf("a's own schema grows by 100 KiB: its estimate by %d bytes compressed, its share by %d raw, want over 40 KiB and "+
			"about 100 KiB", gzGrown-gz, rawGrown-raw)
	}
	if gzOther, rawOther := sizes(100, 100<<10, 100<<10); gzOther-gz > 1<<10 || rawOther != raw {
		t.Errorf("schemas a doesn't alone name grow by 100 KiB each: its estimate by %d bytes compressed, its share by %d raw, "+
			"want neither", gzOther-gz, rawOther-raw)
	}
}
