// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"cmp"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

// TestBundleFitProperties checks the invariants of fitting a bundle on
// random scenarios, at the small scale (the limits a smallScale-th of the
// Secrets'), resolved and fitted as the builder does, without a cluster: 2
// to 20 namespaces with policies and rule sets of random sizes near the
// limits, compressible or not, cluster rule sets they share, and the CRS;
// a namespace share and a cluster reserve, random; then rounds of random
// changes (growth, shrinking, new policies, deletions, bindings changed,
// CRS upgrades, some that a namespace's rules as they were don't compile
// with, and every CRS binder changing at once), and rounds with no change.
// In half the scenarios an attacker squats a rule id of a CRS upgrade to
// come and, at the upgrade, keeps one change pending: ballast just under
// its share, more than the room left, or its flat comments swapped for
// noise of the same raw length; or, small and without a squat, it grows by
// the room a victim's fix for the upgrade needs, in the same build; or
// many small namespaces squat the id a victim uses, more than the encode
// cap measures alone, and grow by part of the room, by part of
// adoptionCap, or by a swap, while the victim ships a few bytes' fix (or,
// with part of adoptionCap, one that grows by part of it too).
// After every build, measured by encoding here, not with the builder's
// sizes:
//
//	(i) if the bundle with every change fits, the budget's gate is off and
//	    the namespaces' changes don't grow it into the reserve, everything
//	    is published and nothing is held;
//	(ii) a policy the bundle in force and the bundle with every change
//	    have is published, unless the last resort ran, or its namespace is
//	    held over its share (measured again here), or (rule R) its
//	    namespace isn't guarded and (ix);
//	(iii) a namespace with no change is never held;
//	(iv) the published bundle fits both limits;
//	(v) the same input fits the same way;
//	(vi) a single tenant whose bundle fits publishes all of it;
//	(vii) a changed cluster rule set shipped as it was says BundleTooLarge;
//	(viii) a namespace within its share is held only if releasing it, with
//	    the rest as published, doesn't fit (limits and reserve, measured
//	    here) or would leave out another published policy, or a protected
//	    namespace stays held (they are released first), unless the encode
//	    cap came first;
//	(ix) a published policy of a namespace within its share is left out
//	    only if its change doesn't fit alone: on the bundle in force with
//	    every other namespace's change held and the cluster rule sets'
//	    changes published, measured here, against the limits (and, once
//	    those changes are due, the reserve, without the prior namespaces'
//	    part, but with a part of its own for a namespace the wait held
//	    while protected: carried); or, once due, if its change grows its
//	    share by more than adoptionCap, or releasing it with the rest as
//	    published doesn't fit; unless the last resort ran, and even when
//	    the encode cap came first. A namespace is prior (released first, its change may take
//	    part of the reserve) exactly when it is last (measured here),
//	    within its share, its change fits alone and grows its share by at
//	    most adoptionCap (raw, counted; compressed, measured, or not
//	    measured alone by the builder, its content compressed alone);
//	    guarded (not left out: the cluster rule sets' changes wait) exactly
//	    when it is last, within its share, its change fits alone and those
//	    changes didn't wait a build already; protected when both; carried
//	    when prior, due, and held protected in the wait, and a wait
//	    carries exactly the protected namespaces it holds;
//	(x) the namespaces' changes take at most the prior namespaces' part
//	    of the reserve (adoptionCap of each limit, at most half the
//	    reserve; once the cluster rule sets' changes are due, none, but
//	    the carried namespaces' own part) over the bundle
//	    with every namespace's change held, or over the reserve line,
//	    whichever is larger, outside a first bundle, a single tenant and
//	    the last resort;
//
// INKWALL_FIT_SCENARIOS=n runs n scenarios (20 under the race detector,
// 200 without), from seed INKWALL_FIT_SEED_BASE (1 by default; logged);
// INKWALL_FIT_SEED=s runs scenario s alone. A failure prints the seed and
// the scenario.
func TestBundleFitProperties(t *testing.T) {
	t.Parallel()
	first, n := uint64(1), 200
	if raceDetector {
		n = 20
	}
	if v := os.Getenv("INKWALL_FIT_SEED_BASE"); v != "" {
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		first = s
	}
	if v := os.Getenv("INKWALL_FIT_SCENARIOS"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	if v := os.Getenv("INKWALL_FIT_SEED"); v != "" {
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		first, n = s, 1
	}
	t.Logf("seeds %d to %d: INKWALL_FIT_SEED_BASE=%d INKWALL_FIT_SCENARIOS=%d", first, first+uint64(n)-1, first, n)
	// The cores the other bundle size tests (fitSlots) leave.
	slots := make(chan struct{}, max(2, runtime.GOMAXPROCS(0)-cap(fitSlots)))
	var stats propStats
	t.Cleanup(func() {
		t.Logf("%d scenarios from seed %d, %d builds: %d fitted, %d gated, %d reserved, %d held, %d over a share, %d too large, "+
			"%d last resort, %d published policies left out, %d cluster changes waited, %d with a namespace released first, %d attacks, "+
			"%d encodes", n, first, stats.builds.Load(), stats.fitted.Load(), stats.gated.Load(), stats.reserved.Load(), stats.held.Load(),
			stats.over.Load(), stats.tooLarge.Load(), stats.kept.Load(), stats.leftOut.Load(), stats.waited.Load(), stats.prior.Load(),
			stats.attacked.Load(), stats.encodes.Load())
	})
	for seed := first; seed < first+uint64(n); seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			t.Parallel()
			slots <- struct{}{}
			defer func() { <-slots }()
			s := newPropScenario(t, seed, 0, &stats)
			s.run()
		})
	}
}

// TestBundleFitPinned runs scenarios of TestBundleFitProperties that
// failed, with the signing key they failed with (it moves gzip's output):
// seed 1300449, key 10, where repair's binary search past the encode cap
// left out a squatter whose release alone fitted (review 8, finding 2);
// seed 1392, where repair tried it with a shrinking change held, and a try
// whose reserve base, holding that change, was over the compressed limit
// didn't fit.
func TestBundleFitPinned(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ seed, key uint64 }{{1300449, 10}, {1392, 0}} {
		t.Run(fmt.Sprintf("seed%d/key%d", c.seed, c.key), func(t *testing.T) {
			t.Parallel()
			if raceDetector {
				t.Skip("its scenario is drawn without the race detector")
			}
			var stats propStats
			newPropScenario(t, c.seed, c.key, &stats).run()
		})
	}
}

type propStats struct {
	builds, fitted, gated, reserved, held, over, tooLarge, kept, leftOut, waited, attacked, encodes, prior atomic.Int64
}

// propScenario is one random scenario, and what it did so far.
type propScenario struct {
	t     *testing.T
	seed  uint64
	rng   *rand.Rand
	stats *propStats
	log   []string
	// share and reserve are spec.bundle.namespaceShare and clusterReserve
	// as the builder applies them.
	share, reserve int
	// maxEncodes is the encode cap, 0 for maxEncodes; rawHeavy: the
	// bundle nears its raw limit with rules that compress to almost
	// nothing.
	maxEncodes int
	rawHeavy   bool
	lim        fitLimits
	signer     *bundle.Signer
	// The cluster's objects, and the bundle in force.
	policies        []wafv1alpha1.WAFPolicy
	ingresses       []networkingv1.Ingress
	ruleSets        []wafv1alpha1.WAFRuleSet
	clusterRuleSets []wafv1alpha1.ClusterWAFRuleSet
	created         int
	prev            *bundlev1.Bundle
	lastVersion     uint64
	ns              []*propNS
	// cluster are the shared ClusterWAFRuleSets, crs the CRS's rules.
	cluster map[string]string
	crs     []int
	nextID  int
	// waited and carried are the last fit's (fitParams.waited and
	// carried); pending are the cluster
	// rule sets shipped as they were though they changed, as they are now,
	// with the round they were first; frozen: the last fit kept the bundle
	// in force.
	waited  map[string]*bundlev1.RuleSet
	carried map[string]bool
	pending map[string]propPending
	frozen  bool
	// The attacker: its namespace, what it does at the CRS upgrade
	// (attackBallast, attackOverRoom, attackRawNeutral, attackTakeRoom),
	// the rule id it squats, and the round of the upgrade.
	atk      *propNS
	atkKind  int
	squatID  int
	atkRound int
	// attackSquatters' namespaces, its victim and how they grow.
	squatters map[*propNS]bool
	victim    *propNS
	victimRS  string
	squatHow  int
	victimFix int // compressed bytes its fix adds, but a few
	failed    bool
}

type propPending struct {
	rs    *bundlev1.RuleSet
	since int
}

const (
	attackBallast = 1 + iota
	attackOverRoom
	attackRawNeutral
	// attackTakeRoom: the attacker, small, doesn't squat; at the upgrade,
	// which adds a rule id a victim's rule set uses, the victim ships its
	// fix, growing by part of the room, and the attacker grows by about
	// the same.
	attackTakeRoom
	// attackSquatters: many small namespaces a00.. bind the CRS and squat
	// a rule id of an upgrade to come, which a victim uses too (if one
	// binds the CRS); at the upgrade the victim ships a few bytes' fix, and
	// each squatter drops the id and grows: by part of the room (each fits
	// alone, not all), by part of adoptionCap (adoptions sharing it), or
	// with its flat comments swapped for noise. More last namespaces than
	// the encode cap measures alone.
	attackSquatters
	attackKinds = attackSquatters
)

type propNS struct {
	name string
	// style: 0 incompressible, 1 compressible, 2 both.
	style    int
	policies []*propPolicy
	ruleSets map[string]*propRuleSet
	next     int // the next policy and rule set number
}

type propPolicy struct {
	name    string
	own     []string // its WAFRuleSets
	cluster []string // its ClusterWAFRuleSets ("crs" too)
}

type propRuleSet struct {
	id   int // the rule id it starts with
	body string
}

func newPropScenario(t *testing.T, seed, key uint64, stats *propStats) *propScenario {
	// The signing key is the seed's (and key's), so that a seed's
	// scenario, sizes and all, is reproducible: the signature's bytes,
	// though few, move gzip's output, and the bundle carries the probe key
	// derived from it.
	var keySeed [ed25519.SeedSize]byte
	binary.LittleEndian.PutUint64(keySeed[:], seed)
	binary.LittleEndian.PutUint64(keySeed[8:], key)
	signer := bundle.NewSigner(ed25519.NewKeyFromSeed(keySeed[:]))
	return &propScenario{t: t, seed: seed, rng: rand.New(rand.NewPCG(seed, seed*0x9e3779b97f4a7c15)), stats: stats,
		share: defaultNamespaceShare, cluster: map[string]string{}, nextID: 100100, signer: signer, pending: map[string]propPending{},
		lim: fitLimits{raw: secretLimits.raw / smallScale, gz: secretLimits.gz / smallScale, slack: secretLimits.slack / smallScale}}
}

// meta is an object's metadata, created after the others.
func (s *propScenario) meta(ns, name string) metav1.ObjectMeta {
	s.created++
	return metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 1,
		CreationTimestamp: metav1.NewTime(time.Unix(1_800_000_000+int64(s.created), 0))}
}

func (s *propScenario) setRuleSet(ns, name, rules string) {
	for i := range s.ruleSets {
		if rs := &s.ruleSets[i]; rs.Namespace == ns && rs.Name == name {
			rs.Spec.Source.SecLang = rules
			rs.Generation++
			return
		}
	}
	s.ruleSets = append(s.ruleSets, wafv1alpha1.WAFRuleSet{ObjectMeta: s.meta(ns, name),
		Spec: wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: rules}}})
}

func (s *propScenario) setClusterRuleSet(name, rules string) {
	for i := range s.clusterRuleSets {
		if rs := &s.clusterRuleSets[i]; rs.Name == name {
			rs.Spec.Source.SecLang = rules
			rs.Generation++
			return
		}
	}
	s.clusterRuleSets = append(s.clusterRuleSets, wafv1alpha1.ClusterWAFRuleSet{ObjectMeta: s.meta("", name),
		Spec: wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{SecLang: rules}}})
}

func refs(bindings []string) []wafv1alpha1.RuleSetBinding {
	var out []wafv1alpha1.RuleSetBinding
	for _, r := range bindings {
		ref := wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: r}
		if c, ok := strings.CutPrefix(r, "cluster:"); ok {
			ref = wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: c}
		}
		out = append(out, wafv1alpha1.RuleSetBinding{Ref: ref})
	}
	return out
}

// addTenant adds an Ingress and a policy on it, as fitCluster.tenant.
func (s *propScenario) addTenant(ns, name string, bindings ...string) {
	prefix := networkingv1.PathTypePrefix
	s.ingresses = append(s.ingresses, networkingv1.Ingress{
		ObjectMeta: s.meta(ns, name),
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: name + "." + ns + ".example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	})
	s.policies = append(s.policies, wafv1alpha1.WAFPolicy{ObjectMeta: s.meta(ns, name), Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: name}},
		Mode:       wafv1alpha1.PolicyDetect,
		RuleSets:   refs(bindings),
	}})
}

func (s *propScenario) policy(ns, name string) int {
	return slices.IndexFunc(s.policies, func(p wafv1alpha1.WAFPolicy) bool { return p.Namespace == ns && p.Name == name })
}

func (s *propScenario) logf(format string, args ...any) {
	s.log = append(s.log, fmt.Sprintf(format, args...))
}

// fail reports the first invariant broken, with the seed and the scenario.
func (s *propScenario) fail(round int, format string, args ...any) {
	s.t.Helper()
	if s.failed {
		return
	}
	s.failed = true
	s.t.Errorf("seed %d, round %d: %s\nrerun: INKWALL_FIT_SEED=%d go test ./operator/internal/controller -run TestBundleFitProperties\nscenario:\n  %s",
		s.seed, round, fmt.Sprintf(format, args...), s.seed, strings.Join(s.log, "\n  "))
}

// noise is about n bytes of SecLang comments, random characters of 64,
// from the scenario's seed: gzip compresses them to about noiseRatio, and
// three times faster than random hex digits.
func (s *propScenario) noise(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, 0, n+100)
	for len(b) < n {
		b = append(b, '#', ' ')
		for range 10 {
			x := s.rng.Uint64()
			for range 10 {
				b = append(b, alphabet[x&63])
				x >>= 6
			}
		}
		b = append(b, '\n')
	}
	return string(b)
}

// propNoiseRatio is about what gzip compresses noise to.
const propNoiseRatio = 0.76

// body is rules of about gz bytes compressed, and raw more bytes of
// comments that compress to almost nothing, in the namespace's style.
func (s *propScenario) body(style, gz, raw int) string {
	var b strings.Builder
	switch style {
	case 0:
		b.WriteString(s.noise(int(float64(gz) / propNoiseRatio)))
	case 1:
		b.WriteString(flat(raw + gz))
	default:
		b.WriteString(s.noise(int(float64(gz) / propNoiseRatio)))
		b.WriteString(flat(raw))
	}
	return b.String()
}

func (rs *propRuleSet) rules() string {
	return fmt.Sprintf("SecRule ARGS \"@contains q%d\" \"id:%d,phase:1,pass,nolog\"\n", rs.id, rs.id) + rs.body
}

func (s *propScenario) id() int {
	s.nextID++
	return s.nextID
}

func (s *propScenario) crsRules() string {
	var b strings.Builder
	b.WriteString("SecMarker CRS\n")
	for _, id := range s.crs {
		fmt.Fprintf(&b, "SecRule ARGS \"@contains c%d\" \"id:%d,phase:1,pass,nolog\"\n", id, id)
	}
	return b.String()
}

// size is a random share of the compressed limit, from lo% to hi%, skewed
// towards lo.
func (s *propScenario) size(lo, hi float64) int {
	x := s.rng.Float64()
	return int(float64(s.lim.gz) * (lo + (hi-lo)*x*x) / 100)
}

func (s *propScenario) writeRuleSet(n *propNS, name string) {
	s.setRuleSet(n.name, name, n.ruleSets[name].rules())
}

func (s *propScenario) bindings(p *propPolicy) []string {
	refs := slices.Clone(p.own)
	for _, c := range p.cluster {
		refs = append(refs, "cluster:"+c)
	}
	return refs
}

// addPolicy adds a policy to n with a rule set of its own of about gz
// bytes compressed and raw bytes more raw. The attacker's bind the CRS.
func (s *propScenario) addPolicy(n *propNS, gz, raw int) *propPolicy {
	name := fmt.Sprintf("r%d", n.next)
	p := &propPolicy{name: fmt.Sprintf("p%d", n.next), own: []string{name}}
	n.next++
	n.ruleSets[name] = &propRuleSet{id: s.id(), body: s.body(n.style, gz, raw)}
	if s.rng.IntN(5) < 3 || n == s.atk || s.squatters[n] {
		p.cluster = append(p.cluster, "crs")
	}
	// In name order, so that the scenario is the seed's.
	for _, c := range slices.Sorted(maps.Keys(s.cluster)) {
		if s.rng.IntN(5) < 2 {
			p.cluster = append(p.cluster, c)
		}
	}
	slices.Sort(p.cluster)
	s.writeRuleSet(n, name)
	s.addTenant(n.name, p.name, s.bindings(p)...)
	n.policies = append(n.policies, p)
	return p
}

func (s *propScenario) setup() {
	nNS := 2 + s.rng.IntN(19)
	fill := 25 + s.rng.Float64()*80 // % of the compressed limit, at first
	if raceDetector {
		// Rounds grow it past the limits; the race detector makes gzip
		// about thirty times slower.
		nNS = 2 + s.rng.IntN(7)
		fill = 20 + s.rng.Float64()*60
	}
	rawFill := 0.0
	if s.rawHeavy = s.rng.IntN(6) == 0; s.rawHeavy {
		rawFill = 50 + s.rng.Float64()*55 // % of the raw limit, in flat comments
	}
	switch s.rng.IntN(8) {
	case 0:
		s.share = 40
	case 1:
		s.share = 10
	}
	switch x := s.rng.IntN(6); {
	case x < 2:
		s.reserve = 0
	case x < 4:
		s.reserve = defaultClusterReserve
	default:
		s.reserve = s.rng.IntN(51)
	}
	grandfather := s.rng.IntN(4) == 0
	share, reserve := s.share, s.reserve
	if grandfather {
		// Content published before the budget and the reserve, or with a
		// larger share.
		s.share, s.reserve = 100, 0
	}
	// The encode cap: mostly low, so that many scenarios fit in a few
	// seconds under the race detector, and so that it is often reached.
	switch x := s.rng.IntN(20); {
	case x < 14 || raceDetector:
		s.maxEncodes = 8 + s.rng.IntN(5)
	case x < 18:
		s.maxEncodes = 15 + s.rng.IntN(18)
	}
	for i := range s.rng.IntN(3) {
		name := fmt.Sprintf("shared%d", i)
		s.cluster[name] = "SecMarker SHARED\n" + s.body(s.rng.IntN(3), s.size(0, 12), 0)
		s.setClusterRuleSet(name, s.cluster[name])
	}
	s.crs = []int{300000}
	s.setClusterRuleSet("crs", s.crsRules())
	// Weights, and styles: the compressed fill is over the namespaces
	// whose rules don't compress to almost nothing.
	weights, styles := make([]float64, nNS), make([]int, nNS)
	total, totalGz := 0.0, 0.0
	for i := range weights {
		weights[i] = 0.2 + s.rng.Float64()
		if s.rng.IntN(6) == 0 {
			weights[i] *= 2 + 6*s.rng.Float64()
		}
		switch x := s.rng.IntN(20); {
		case x < 9 || i == 0:
			styles[i] = 0
		case x < 16:
			styles[i] = 2
		default:
			styles[i] = 1
		}
		total += weights[i]
		if styles[i] != 1 {
			totalGz += weights[i]
		}
	}
	// The attacker, in half the scenarios: the last namespace, which
	// squats the rule id of a CRS upgrade to come.
	if s.rng.IntN(2) == 0 {
		s.atkKind = 1 + s.rng.IntN(attackKinds)
		s.squatID = 300001 + s.rng.IntN(99)
		s.atkRound = 1 + s.rng.IntN(2)
		switch s.atkKind {
		case attackRawNeutral:
			styles[nNS-1] = 1
		case attackTakeRoom:
			// Small: its weight is about a tenth of the others'.
			weights[nNS-1] *= 0.1
		}
	}
	s.logf("setup: %d namespaces, share %d%%, reserve %d%% (100%% and 0%% at first: %t), fill %.0f%% compressed, %.0f%% raw in "+
		"flat comments, %d shared cluster rule sets, maxEncodes %d, attack %d on rule id %d in round %d", nNS, share, reserve,
		grandfather, fill, rawFill, len(s.cluster), s.maxEncodes, s.atkKind, s.squatID, s.atkRound)
	for i := range nNS {
		n := &propNS{name: fmt.Sprintf("n%02d", i), style: styles[i], ruleSets: map[string]*propRuleSet{}}
		s.ns = append(s.ns, n)
		if s.atkKind != 0 && s.atkKind != attackSquatters && i == nNS-1 {
			s.atk = n
		}
		gz, raw := 0, int(float64(s.lim.raw)*rawFill/100*weights[i]/total)
		if n.style != 1 {
			gz = int(float64(s.lim.gz) * fill / 100 * weights[i] / totalGz)
		} else {
			raw += int(float64(s.lim.gz) * s.rng.Float64() * 0.3)
		}
		k := 1 + s.rng.IntN(3)
		if n == s.atk {
			k = 1
			if s.atkKind == attackRawNeutral {
				raw = int(float64(s.lim.gz) * (0.08 + 0.1*s.rng.Float64()))
			}
		}
		for range k {
			s.addPolicy(n, gz/k, raw/k)
		}
		if n == s.atk && s.atkKind != attackTakeRoom {
			name := n.policies[0].own[0]
			n.ruleSets[name].id = s.squatID
			s.writeRuleSet(n, name)
		}
		s.logf("  %s: style %d, %d policies, %d bytes compressed, %d raw more", n.name, n.style, k, gz, raw)
	}
	if s.atkKind == attackSquatters {
		s.addSquatters()
	}
	s.build(0)
	s.share, s.reserve = share, reserve
}

// addSquatters adds attackSquatters' namespaces, and gives its victim the
// rule id they squat.
func (s *propScenario) addSquatters() {
	k := 6 + s.rng.IntN(35)
	if raceDetector {
		k = 3 + s.rng.IntN(6)
	}
	s.squatHow = s.rng.IntN(3)
	if s.squatHow == 1 && s.rng.IntN(2) == 0 {
		// The victim's fix grows it by part of adoptionCap too, more or
		// less than each squatter (review 8, finding 1).
		s.victimFix = int(float64(s.lim.gz) * (0.5 + 3*s.rng.Float64()) / 100)
	}
	for _, n := range s.ns {
		if p := n.policies[0]; slices.Contains(p.cluster, "crs") {
			s.victim, s.victimRS = n, p.own[0]
			n.ruleSets[p.own[0]].id = s.squatID
			s.writeRuleSet(n, p.own[0])
			break
		}
	}
	s.squatters = map[*propNS]bool{}
	for i := range k {
		n := &propNS{name: fmt.Sprintf("a%02d", i), style: 2, ruleSets: map[string]*propRuleSet{}}
		s.squatters[n] = true
		s.ns = append(s.ns, n)
		p := s.addPolicy(n, s.size(0.1, 0.6), s.lim.gz/200)
		n.ruleSets[p.own[0]].id = s.squatID
		s.writeRuleSet(n, p.own[0])
	}
	victim := "none"
	if s.victim != nil {
		victim = s.victim.name
	}
	s.logf("  %d squatters a00.. of rule id %d (victim %s, fix %d bytes more), growing by way %d", k, s.squatID, victim, s.victimFix,
		s.squatHow)
}

// squat is attackSquatters' move at the CRS upgrade that adds the id they
// squat.
func (s *propScenario) squat() {
	s.crs = append(s.crs, s.squatID)
	s.setClusterRuleSet("crs", s.crsRules())
	_, inForce := s.sizes(s.prev)
	room := max(s.lim.gz-inForce, s.lim.gz/100)
	adopt := s.lim.gz / 100 * adoptionCap
	for _, n := range s.ns {
		if !s.squatters[n] {
			continue
		}
		name := n.policies[0].own[0]
		rs := n.ruleSets[name]
		switch s.squatHow {
		case 0:
			rs.body += s.noise(int(float64(room) * (0.3 + 0.3*s.rng.Float64()) / propNoiseRatio))
		case 1:
			rs.body += s.noise(int(float64(adopt) * (0.2 + 0.7*s.rng.Float64()) / propNoiseRatio))
		default:
			raw := len(rs.body)
			rs.body = s.noise(raw * 3 / 4)
			rs.body += strings.Repeat("#", max(0, raw-len(rs.body)-1)) + "\n"
		}
		rs.id = s.id()
		s.writeRuleSet(n, name)
	}
	if v := s.victim; v != nil {
		name := s.victimRS
		v.ruleSets[name].id = s.id()
		v.ruleSets[name].body += "# fix\n"
		if s.victimFix > 0 {
			v.ruleSets[name].body += s.noise(int(float64(s.victimFix) / propNoiseRatio))
		}
		s.writeRuleSet(v, name)
	}
	s.logf("  CRS upgrade with rule id %d, which %d squatters squat (room %d); the victim fixes it", s.squatID, len(s.squatters), room)
}

// change makes one random change to n.
func (s *propScenario) change(n *propNS) {
	if len(n.policies) == 0 {
		p := s.addPolicy(n, s.size(0, 10), 0)
		s.logf("  %s: add %s (no policy left)", n.name, p.name)
		return
	}
	p := n.policies[s.rng.IntN(len(n.policies))]
	rs := n.ruleSets[p.own[0]]
	switch op := s.rng.IntN(10); {
	case op < 4:
		gz := s.size(0.5, 30)
		raw := 0
		if s.rawHeavy && n.style != 0 && s.rng.IntN(3) == 0 {
			raw = int(float64(s.lim.raw) * s.rng.Float64() * 0.3)
		}
		rs.body += s.body(n.style, gz, raw)
		s.writeRuleSet(n, p.own[0])
		s.logf("  %s: grow %s by %d compressed, %d raw more", n.name, p.own[0], gz, raw)
	case op < 6:
		cut := len(rs.body) * (2 + s.rng.IntN(8)) / 10
		if i := strings.LastIndexByte(rs.body[:cut], '\n'); i >= 0 {
			cut = i + 1
		} else {
			cut = 0
		}
		rs.body = rs.body[:cut]
		s.writeRuleSet(n, p.own[0])
		s.logf("  %s: shrink %s to %d bytes", n.name, p.own[0], len(rs.body))
	case op < 7:
		np := s.addPolicy(n, s.size(0, 20), 0)
		s.logf("  %s: add %s binding %v", n.name, np.name, s.bindings(np))
	case op < 8:
		n.policies = slices.DeleteFunc(n.policies, func(q *propPolicy) bool { return q == p })
		i := s.policy(n.name, p.name)
		s.policies = slices.Delete(s.policies, i, i+1)
		s.logf("  %s: delete %s", n.name, p.name)
	case op < 9:
		// Rebind: a cluster rule set, or another of its own.
		all := append(slices.Sorted(maps.Keys(s.cluster)), "crs")
		if c := all[s.rng.IntN(len(all))]; s.rng.IntN(3) > 0 {
			if i := slices.Index(p.cluster, c); i >= 0 {
				p.cluster = slices.Delete(p.cluster, i, i+1)
			} else {
				p.cluster = append(p.cluster, c)
				slices.Sort(p.cluster)
			}
		} else {
			names := slices.Sorted(maps.Keys(n.ruleSets))
			other := names[s.rng.IntN(len(names))]
			if i := slices.Index(p.own, other); i > 0 {
				p.own = slices.Delete(p.own, i, i+1)
			} else if i < 0 {
				p.own = append(p.own, other)
			}
		}
		w := &s.policies[s.policy(n.name, p.name)]
		w.Spec.RuleSets = refs(s.bindings(p))
		w.Generation++
		s.logf("  %s: rebind %s to %v", n.name, p.name, s.bindings(p))
	default:
		s.fixID(n, p.own[0])
	}
}

// fixID gives a rule set a new rule id: its fix for a CRS upgrade that
// adds its old one.
func (s *propScenario) fixID(n *propNS, name string) {
	rs := n.ruleSets[name]
	old := rs.id
	rs.id = s.id()
	s.writeRuleSet(n, name)
	s.logf("  %s: rule id of %s %d -> %d", n.name, name, old, rs.id)
}

// attack is the attacker's move at the CRS upgrade that adds the id it
// squats: it drops the id, and keeps one change pending from then on (the
// same input in every round).
func (s *propScenario) attack() {
	n := s.atk
	name := n.policies[0].own[0]
	rs := n.ruleSets[name]
	_, inForce := s.sizes(s.prev)
	_, share, _ := s.shareOf(s.prev, n.name)
	room := s.lim.gz - inForce
	switch s.atkKind {
	case attackBallast:
		// Just under its share.
		grow := s.lim.gz/100*s.share - s.lim.gz/100 - share
		rs.body += s.noise(int(float64(max(grow, 0)) / propNoiseRatio))
	case attackOverRoom:
		rs.body += s.noise(int(float64(room+s.lim.gz*5/100) / propNoiseRatio))
	case attackRawNeutral:
		raw := len(rs.body)
		rs.body = s.noise(raw * 3 / 4)
		rs.body += strings.Repeat("#", max(0, raw-len(rs.body)-1)) + "\n"
	}
	rs.id = s.id()
	s.writeRuleSet(n, name)
	s.logf("  attacker %s: drops rule id %d, %d bytes now (attack %d, room %d, share %d)", n.name, s.squatID, len(rs.body),
		s.atkKind, room, share)
}

func (s *propScenario) round(round int) {
	s.logf("round %d:", round)
	// A few namespaces change, so the bundle stays near its limits; the
	// attacker changes only by its move, and keeps it.
	for _, i := range s.rng.Perm(len(s.ns))[:1+s.rng.IntN(min(4, len(s.ns)))] {
		if s.ns[i] != s.atk && !s.squatters[s.ns[i]] {
			s.change(s.ns[i])
		}
	}
	if len(s.cluster) > 0 && s.rng.IntN(10) < 3 {
		names := slices.Sorted(maps.Keys(s.cluster))
		c := names[s.rng.IntN(len(names))]
		if s.rng.IntN(2) == 0 {
			s.cluster[c] += s.body(s.rng.IntN(3), s.size(0.5, 15), 0)
		} else {
			s.cluster[c] = s.cluster[c][:len(s.cluster[c])/2]
			if i := strings.LastIndexByte(s.cluster[c], '\n'); i >= 0 {
				s.cluster[c] = s.cluster[c][:i+1]
			}
		}
		s.setClusterRuleSet(c, s.cluster[c])
		s.logf("  cluster rule set %s: %d bytes", c, len(s.cluster[c]))
	}
	switch {
	case s.atkKind == attackSquatters && round == s.atkRound:
		s.squat()
		s.stats.attacked.Add(1)
	case s.atk != nil && round == s.atkRound && s.atkKind == attackTakeRoom:
		s.takeRoom()
		s.stats.attacked.Add(1)
	case s.atk != nil && round == s.atkRound:
		// The admin's upgrade adds the id the attacker squats.
		s.crs = append(s.crs, s.squatID)
		s.setClusterRuleSet("crs", s.crsRules())
		s.logf("  CRS upgrade with rule id %d, which attacker %s squats", s.squatID, s.atk.name)
		s.attack()
		s.stats.attacked.Add(1)
	case s.rng.IntN(20) < 7:
		s.upgrade()
	}
	s.build(round)
}

// takeRoom is attackTakeRoom's move: the CRS upgrade adds the rule id of a
// victim's rule set (a namespace that binds the CRS, picked at random), the
// victim ships its fix, growing by part of the room, and the attacker, small,
// grows by about as much (the room above the reserve, or all of it).
func (s *propScenario) takeRoom() {
	var victims []*propNS
	var names []string
	for _, n := range s.ns {
		for _, p := range n.policies {
			if n != s.atk && !s.squatters[n] && slices.Contains(p.cluster, "crs") {
				victims, names = append(victims, n), append(names, p.own[0])
			}
		}
	}
	if len(victims) == 0 {
		s.upgrade()
		return
	}
	_, inForce := s.sizes(s.prev)
	room := s.lim.gz - inForce
	if s.rng.IntN(2) == 0 {
		room -= s.lim.gz / 100 * s.reserve
	}
	room = max(room, s.lim.gz/100)
	i := s.rng.IntN(len(victims))
	v, name := victims[i], names[i]
	s.crs = append(s.crs, v.ruleSets[name].id)
	s.setClusterRuleSet("crs", s.crsRules())
	s.fixID(v, name)
	grow := room * (3 + s.rng.IntN(5)) / 10
	v.ruleSets[name].body += s.noise(int(float64(grow) / propNoiseRatio))
	s.writeRuleSet(v, name)
	a := s.atk.policies[0].own[0]
	s.atk.ruleSets[a].body += s.noise(int(float64(room*(4+s.rng.IntN(5))/10) / propNoiseRatio))
	s.writeRuleSet(s.atk, a)
	s.logf("  CRS upgrade with rule id of %s/%s, which fixes it and grows by %d; attacker %s takes the room (%d)", v.name, name,
		grow, s.atk.name, room)
}

// upgrade upgrades the CRS: with a rule id a namespace's rules use, or
// not; sometimes every namespace that binds it changes in the same build.
func (s *propScenario) upgrade() {
	var hit []*propNS
	var hitRS []string
	for _, n := range s.ns {
		for _, p := range n.policies {
			if slices.Contains(p.cluster, "crs") && n != s.atk && !s.squatters[n] {
				hit = append(hit, n)
				hitRS = append(hitRS, p.own[0])
			}
		}
	}
	if len(hit) > 0 && s.rng.IntN(2) == 0 {
		i := s.rng.IntN(len(hit))
		n, name := hit[i], hitRS[i]
		id := n.ruleSets[name].id
		if !slices.Contains(s.crs, id) {
			s.crs = append(s.crs, id)
		}
		s.setClusterRuleSet("crs", s.crsRules())
		s.logf("  CRS upgrade with rule id %d, which %s/%s uses", id, n.name, name)
		if s.rng.IntN(5) < 3 {
			s.fixID(n, name)
			if s.rng.IntN(2) == 0 {
				rs := n.ruleSets[name]
				gz := s.size(0.5, 45)
				rs.body += s.body(n.style, gz, 0)
				s.writeRuleSet(n, name)
				s.logf("  %s: grow %s by %d compressed with the fix", n.name, name, gz)
			}
		}
	} else {
		s.crs = append(s.crs, s.id()+200000)
		s.setClusterRuleSet("crs", s.crsRules())
		s.logf("  CRS upgrade with rule id %d", s.crs[len(s.crs)-1])
	}
	if len(hit) > 0 && s.rng.IntN(3) == 0 {
		// Every CRS binder changes in this build.
		for i, n := range hit {
			rs := n.ruleSets[hitRS[i]]
			rs.body += s.body(n.style, s.size(0, 4), 0)
			s.writeRuleSet(n, hitRS[i])
		}
		s.logf("  every CRS binder changes")
	}
}

func (s *propScenario) run() {
	s.setup()
	// Rounds of changes, then rounds without: the attacker's input, and
	// everyone's, stays fixed.
	const changes, quiet = 3, 3
	for round := 1; round <= changes+quiet && !s.failed; round++ {
		if round <= changes {
			s.round(round)
			continue
		}
		s.logf("round %d: no change", round)
		s.build(round)
	}
}

// sizes are b's, signed and compressed as published; gz is -1 over the
// raw limit, 0 for no bundle.
func (s *propScenario) sizes(b *bundlev1.Bundle) (raw, gz int) {
	if b == nil {
		return 0, 0
	}
	signed, err := s.signer.Sign(b)
	if err != nil {
		s.t.Fatal(err)
	}
	raw = proto.Size(signed)
	if raw > s.lim.raw {
		return raw, -1
	}
	data, err := bundle.Encode(signed)
	if err != nil {
		s.t.Fatal(err)
	}
	return raw, len(data)
}

func (s *propScenario) fits(b *bundlev1.Bundle) bool {
	raw, gz := s.sizes(b)
	return raw <= s.lim.raw && gz >= 0 && gz <= s.lim.gz
}

// shareOf is ns's share of b, as the invariants define it: what b saves
// without ns's policies and WAFRuleSets, raw and compressed; cluster rule
// sets stay. !ok: b is over the raw limit, and not compressed.
func (s *propScenario) shareOf(b *bundlev1.Bundle, ns string) (raw, gz int, ok bool) {
	if b == nil {
		return 0, 0, true
	}
	c := proto.Clone(b).(*bundlev1.Bundle)
	c.Policies = slices.DeleteFunc(c.Policies, func(p *bundlev1.Policy) bool { return strings.HasPrefix(p.GetId(), ns+"/") })
	c.RuleSets = slices.DeleteFunc(c.RuleSets, func(rs *bundlev1.RuleSet) bool {
		return strings.HasPrefix(rs.GetId(), "WAFRuleSet/"+ns+"/")
	})
	rawAll, gzAll := s.sizes(b)
	rawWithout, gzWithout := s.sizes(c)
	if gzAll < 0 || gzWithout < 0 {
		return rawAll - rawWithout, 0, false
	}
	return rawAll - rawWithout, gzAll - gzWithout, true
}

func namespacesOf(b *bundlev1.Bundle) map[string]bool {
	out := map[string]bool{}
	for _, p := range b.GetPolicies() {
		out[namespaceOfID(p.GetId())] = true
	}
	return out
}

// changed are the namespaces with a change from prev to full, "" for the
// cluster rule sets.
func changed(prev, full *bundlev1.Bundle) map[string]bool {
	out := map[string]bool{}
	was := map[string]proto.Message{}
	for _, p := range prev.GetPolicies() {
		was[p.GetId()] = p
	}
	for _, rs := range prev.GetRuleSets() {
		was[rs.GetId()] = rs
	}
	for _, p := range full.GetPolicies() {
		if old, ok := was[p.GetId()]; !ok || !proto.Equal(old, p) {
			out[namespaceOfID(p.GetId())] = true
		}
	}
	for _, rs := range full.GetRuleSets() {
		if old, ok := was[rs.GetId()]; ok && !proto.Equal(old, rs) {
			out[namespaceOfID(rs.GetId())] = true
		}
	}
	return out
}

func ids(b *bundlev1.Bundle) map[string]bool {
	out := map[string]bool{}
	for _, p := range b.GetPolicies() {
		out[p.GetId()] = true
	}
	return out
}

func ruleSetsOf(b *bundlev1.Bundle) map[string]*bundlev1.RuleSet {
	out := map[string]*bundlev1.RuleSet{}
	for _, rs := range b.GetRuleSets() {
		out[rs.GetId()] = rs
	}
	return out
}

// sameFit says how two fits of the same input differ; "" when they don't.
func sameFit(a, b fitted) string {
	switch {
	case !maps.Equal(a.held, b.held):
		return fmt.Sprintf("held %v, then %v", slices.Collect(maps.Keys(a.held)), slices.Collect(maps.Keys(b.held)))
	case !maps.Equal(a.heldRuleSets, b.heldRuleSets):
		return fmt.Sprintf("held rule sets %v, then %v", slices.Collect(maps.Keys(a.heldRuleSets)), slices.Collect(maps.Keys(b.heldRuleSets)))
	case a.kept != b.kept || a.changed != b.changed || a.encodes != b.encodes || a.gated != b.gated || a.reserved != b.reserved:
		return fmt.Sprintf("kept %t changed %t encodes %d gated %t reserved %t, then %t %t %d %t %t", a.kept, a.changed, a.encodes,
			a.gated, a.reserved, b.kept, b.changed, b.encodes, b.gated, b.reserved)
	case !maps.Equal(a.over, b.over) || !maps.Equal(a.protected, b.protected) || !maps.Equal(a.carry, b.carry) ||
		!maps.Equal(a.carried, b.carried):
		return fmt.Sprintf("over %v protected %v carry %v carried %v, then %v %v %v %v", a.over, a.protected, a.carry, a.carried,
			b.over, b.protected, b.carry, b.carried)
	case !maps.EqualFunc(a.waited, b.waited, func(x, y *bundlev1.RuleSet) bool { return proto.Equal(x, y) }):
		return "other cluster rule sets waited"
	case !proto.Equal(a.next, b.next):
		return "another bundle"
	}
	return ""
}

// checkRuleIDs stands in for the engine's compile of a policy with its
// rule sets, which the scenarios' rules fail only by a rule id two of its
// rule sets use: the CRS upgrades that a namespace's rules as they were
// don't compile with. The scenarios' rules are SecMarker and SecRule lines,
// each SecRule with an id, then comments only: only the lines before the
// first comment are read.
func checkRuleIDs(p *bundlev1.Policy, ruleSets []*bundlev1.RuleSet) error {
	seen := map[string]string{}
	for _, rs := range ruleSets {
		text := rs.GetSeclang()
		for text != "" && !strings.HasPrefix(text, "#") {
			var line string
			line, text, _ = strings.Cut(text, "\n")
			_, id, ok := strings.Cut(line, "id:")
			if !strings.HasPrefix(line, "SecRule ") || !ok {
				continue
			}
			id, _, _ = strings.Cut(id, ",")
			if other, dup := seen[id]; dup && other != rs.GetId() {
				return fmt.Errorf("rule id %s in %s and %s", id, other, rs.GetId())
			}
			seen[id] = rs.GetId()
		}
	}
	return nil
}

// resolve resolves the cluster with prev in force.
func (s *propScenario) resolve(prev *bundlev1.Bundle) resolver.Input {
	return resolver.Input{CheckPolicy: checkRuleIDs, Policies: slices.Clone(s.policies), Ingresses: slices.Clone(s.ingresses),
		RuleSets: slices.Clone(s.ruleSets), ClusterRuleSets: slices.Clone(s.clusterRuleSets), Previous: prev}
}

// next builds the bundle of res as the builder does, on prev and the
// version last published then.
func (s *propScenario) next(prev *bundlev1.Bundle, lastVersion uint64, res resolver.Result) (*bundlev1.Bundle, bool) {
	next, changed, err := bundle.Next(prev, &bundlev1.Bundle{ClusterId: "cluster-uid", Policies: res.Policies, RuleSets: res.RuleSets,
		ProbeKey: s.signer.ProbeKey()}, lastVersion, time.Unix(1_800_000_000, 0), false)
	if err != nil {
		s.t.Fatal(err)
	}
	return next, changed
}

// publish builds the bundle as the builder does, and fits it; observe sees
// the fit, if there was one.
func (s *propScenario) publish(round int, observe func(fitted)) *bundlev1.Bundle {
	in := s.resolve(s.prev)
	res := resolver.Resolve(in)
	prev, lastVersion := s.prev, s.lastVersion
	build := func(res resolver.Result) (*bundlev1.Bundle, bool, error) {
		next, changed := s.next(prev, lastVersion, res)
		return next, changed, nil
	}
	next, changed, _ := build(res)
	if !changed {
		return s.prev
	}
	opts := fitOptions{maxEncodes: s.maxEncodes, limits: s.lim}
	params := fitParams{share: s.share, reserve: s.reserve, waited: s.waited, carried: s.carried}
	h, ok, err := fit(in, res, next, changed, s.signer, params, build, build, opts)
	if err != nil {
		s.t.Fatal(err)
	}
	s.frozen = !ok
	observe(h)
	// (v): one build in five, again (in ten under the race detector).
	if every := cmp.Or(10*btoi(raceDetector), 5); (s.seed+uint64(round))%uint64(every) == 0 {
		again, okAgain, err := fit(in, res, next, changed, s.signer, params, build, build, opts)
		if err != nil {
			s.t.Fatal(err)
		}
		if d := sameFit(h, again); d != "" || ok != okAgain {
			s.fail(round, "(v) the same input fits two ways: %s (ok %t, then %t)", d, ok, okAgain)
		}
	}
	if ok {
		s.waited, s.carried = h.waited, h.carry
		if h.changed {
			s.prev = h.next
			s.lastVersion = max(s.lastVersion, h.next.GetVersion())
		}
	}
	return s.prev
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// propUnits are a namespace's changes, as the builder holds them.
type propUnits struct {
	policies map[types.NamespacedName]bool
	ruleSets map[string]bool
}

// units are the changes from prev of full, the bundle of res with every
// change, by namespace, "" for the cluster rule sets': the policies it
// publishes as their spec is that differ from prev's, and the rule sets
// prev has that differ.
func units(prev, full *bundlev1.Bundle, res resolver.Result) map[string]*propUnits {
	out := map[string]*propUnits{}
	unit := func(ns string) *propUnits {
		if out[ns] == nil {
			out[ns] = &propUnits{policies: map[types.NamespacedName]bool{}, ruleSets: map[string]bool{}}
		}
		return out[ns]
	}
	was := map[string]*bundlev1.Policy{}
	for _, p := range prev.GetPolicies() {
		was[p.GetId()] = p
	}
	now := map[string]*bundlev1.Policy{}
	for _, p := range full.GetPolicies() {
		now[p.GetId()] = p
	}
	for key, st := range res.PolicyStatus {
		id := resolver.PolicyID(key.Namespace, key.Name)
		if p := now[id]; st.Applied && p != nil && (was[id] == nil || !proto.Equal(was[id], p)) {
			unit(key.Namespace).policies[key] = true
		}
	}
	wasRS := ruleSetsOf(prev)
	for id, rs := range ruleSetsOf(full) {
		if wasRS[id] != nil && !proto.Equal(wasRS[id], rs) {
			unit(namespaceOfID(id)).ruleSets[id] = true
		}
	}
	return out
}

// oracle measures tries of one build as the builder's rules define them,
// by resolving and encoding here.
type oracle struct {
	s           *propScenario
	prev, full  *bundlev1.Bundle
	lastVersion uint64
	units       map[string]*propUnits
	// published are the policies prev and full have.
	published map[string]bool
	// prior are the namespaces the builder released first, guarded those
	// it may not leave out (not due), protected those of them that are
	// prior (checked by (ix)).
	prior, guarded, protected map[string]bool
	bases                     map[string][2]int
	// carriedBefore are the namespaces the build before held in a wait
	// while protected (fitParams.carried); carried those of them that are
	// prior once due, which alone share a part of the reserve.
	carriedBefore, carried map[string]bool
	// due: the cluster rule sets' changes waited a build already; alones
	// are alone's measures, by namespace; none is the bundle with every
	// namespace's change held, accounted.
	due    bool
	alones map[string]propAlone
	none   *[2]int
}

// propAlone is a namespace's change measured alone: the bundle's sizes,
// accounted; changed: it changes the bundle; fits: the limits, as
// published and accounted.
type propAlone struct {
	raw, gz       int
	changed, fits bool
}

func (s *propScenario) oracle(prev, full *bundlev1.Bundle, lastVersion uint64) *oracle {
	o := &oracle{s: s, prev: prev, full: full, lastVersion: lastVersion, published: map[string]bool{}, bases: map[string][2]int{},
		prior: map[string]bool{}, guarded: map[string]bool{}, protected: map[string]bool{}, alones: map[string]propAlone{}}
	o.units = units(prev, full, resolver.Resolve(s.resolve(prev)))
	inFull := ids(full)
	for id := range ids(prev) {
		if inFull[id] {
			o.published[id] = true
		}
	}
	return o
}

// hold resolves with the units of the namespaces hold says held ("" for
// the cluster rule sets'), prev in force, and builds the bundle.
func (o *oracle) hold(hold func(ns string) bool) (*bundlev1.Bundle, bool) {
	in := o.s.resolve(o.prev)
	in.Hold, in.HoldRuleSets = map[types.NamespacedName]string{}, map[string]string{}
	for ns, u := range o.units {
		if !hold(ns) {
			continue
		}
		for key := range u.policies {
			in.Hold[key] = "held"
		}
		for id := range u.ruleSets {
			in.HoldRuleSets[id] = "held"
		}
	}
	return o.s.next(o.prev, o.lastVersion, resolver.Resolve(in))
}

// leftOut are the published policies next leaves out.
func (o *oracle) leftOut(next *bundlev1.Bundle) map[string]bool {
	in := ids(next)
	out := map[string]bool{}
	for id := range o.published {
		if !in[id] {
			out[id] = true
		}
	}
	return out
}

// accounted is a copy of next with the published policies it leaves out
// added back as prev has them, with the rule sets they bind that next
// doesn't have, in id order.
func (o *oracle) accounted(next *bundlev1.Bundle) *bundlev1.Bundle {
	b := proto.Clone(next).(*bundlev1.Bundle)
	in, have := ids(next), ruleSetsOf(next)
	wasRS := ruleSetsOf(o.prev)
	versions := o.prev.GetPolicyVersions()
	for i, p := range o.prev.GetPolicies() {
		if !o.published[p.GetId()] || in[p.GetId()] {
			continue
		}
		b.Policies = append(b.Policies, p)
		if i < len(versions) {
			b.PolicyVersions = append(b.PolicyVersions, versions[i])
		}
		for _, r := range p.GetRuleSets() {
			if id := r.GetRuleSetId(); have[id] == nil && wasRS[id] != nil {
				have[id] = wasRS[id]
				b.RuleSets = append(b.RuleSets, wasRS[id])
			}
		}
	}
	slices.SortFunc(b.Policies, func(x, y *bundlev1.Policy) int { return cmp.Compare(x.GetId(), y.GetId()) })
	slices.SortFunc(b.RuleSets, func(x, y *bundlev1.RuleSet) int { return cmp.Compare(x.GetId(), y.GetId()) })
	return b
}

// reserving reports whether the reserve applies to this build.
func (o *oracle) reserving() bool {
	return o.prev != nil && o.s.reserve > 0 && len(namespacesOf(o.full)) > 1
}

// inReserve reports whether sizes leave less than the reserve free.
func (o *oracle) inReserve(raw, gz int) bool {
	l := o.s.lim
	return o.reserving() && (gz < 0 || l.raw-raw < l.raw/100*o.s.reserve || l.gz-gz < l.gz/100*o.s.reserve)
}

// base is the reserve's base of a try that holds what held says: the same
// try with every namespace's change held but the prior namespaces' it
// releases, accounted. self: the try holds every other change already.
func (o *oracle) base(held func(ns string) bool) (raw, gz int, self bool) {
	var names []string
	self = true
	for ns := range o.units {
		h := held(ns)
		if ns != "" && !h && !o.reserves(ns) {
			h, self = true, false
		}
		if h {
			names = append(names, ns)
		}
	}
	if self {
		return 0, 0, true
	}
	slices.Sort(names)
	key := strings.Join(names, ",")
	if b, ok := o.bases[key]; ok {
		return b[0], b[1], false
	}
	next, _ := o.hold(func(ns string) bool { return slices.Contains(names, ns) })
	raw, gz = o.s.sizes(o.accounted(next))
	o.bases[key] = [2]int{raw, gz}
	return raw, gz, false
}

// fits reports whether next, built with what held says held, fits as the
// builder's rules say: unchanged, or it fits both limits, as published and
// with the published policies it leaves out counted, and the reserve. A
// try that holds the cluster rule sets' changes and releases a guarded
// namespace (a wait) is measured with those changes published.
func (o *oracle) fits(next *bundlev1.Bundle, changed bool, held func(ns string) bool) bool {
	if !changed {
		return true
	}
	if !o.s.fits(next) {
		return false
	}
	measured := next
	if held("") && slices.ContainsFunc(slices.Collect(maps.Keys(o.guarded)), func(ns string) bool { return !held(ns) }) {
		was := held
		held = func(ns string) bool { return ns != "" && was(ns) }
		measured = o.withCluster(next)
	}
	raw, gz := o.s.sizes(o.accounted(measured))
	if raw > o.s.lim.raw || gz < 0 || gz > o.s.lim.gz {
		return false
	}
	if o.inReserve(raw, gz) {
		bRaw, bGz, self := o.base(held)
		if !self && (bGz < 0 || raw > bRaw || gz > bGz) {
			return false
		}
		if !slices.ContainsFunc(slices.Collect(maps.Keys(o.prior)), func(ns string) bool { return o.reserves(ns) && !held(ns) }) {
			return true
		}
		// The prior namespaces' changes take at most their part of the
		// reserve.
		none, _ := o.hold(func(ns string) bool { return ns != "" || held("") })
		nRaw, nGz := o.s.sizes(o.accounted(none))
		aRaw, aGz := o.adoptPart()
		return o.adopts(raw, gz, nRaw, nGz, aRaw, aGz)
	}
	return true
}

// withCluster is a copy of b with the cluster rule sets as full has them:
// how the builder measures a try that waits for a guarded namespace whose
// change it releases.
func (o *oracle) withCluster(b *bundlev1.Bundle) *bundlev1.Bundle {
	c := proto.Clone(b).(*bundlev1.Bundle)
	now := ruleSetsOf(o.full)
	for i, rs := range c.RuleSets {
		if id := rs.GetId(); namespaceOfID(id) == "" && now[id] != nil {
			c.RuleSets[i] = now[id]
		}
	}
	return c
}

// last reports whether holding ns leaves out one of its published
// policies: its version in prev, with ns's rule sets as prev has them,
// doesn't compile with a cluster rule set it binds that changed, as full
// has it.
func (o *oracle) last(ns string) bool {
	if o.units[ns] == nil {
		return false
	}
	was, now := ruleSetsOf(o.prev), ruleSetsOf(o.full)
	for _, p := range o.prev.GetPolicies() {
		if namespaceOfID(p.GetId()) != ns || !o.published[p.GetId()] {
			continue
		}
		var bound []*bundlev1.RuleSet
		changed := false
		for _, b := range p.GetRuleSets() {
			id := b.GetRuleSetId()
			rs := was[id]
			if namespaceOfID(id) == "" && now[id] != nil {
				changed = changed || !proto.Equal(rs, now[id])
				rs = now[id]
			}
			if rs != nil {
				bound = append(bound, rs)
			}
		}
		if changed && checkRuleIDs(p, bound) != nil {
			return true
		}
	}
	return false
}

// measureAlone measures ns's change alone: on prev with every other
// namespace's change held and the cluster rule sets' changes published.
func (o *oracle) measureAlone(ns string) propAlone {
	if a, ok := o.alones[ns]; ok {
		return a
	}
	next, changed := o.hold(func(other string) bool { return other != ns && other != "" })
	a := propAlone{changed: changed, fits: true}
	if changed {
		a.raw, a.gz = o.s.sizes(o.accounted(next))
		a.fits = o.s.fits(next) && a.raw <= o.s.lim.raw && a.gz >= 0 && a.gz <= o.s.lim.gz
	}
	o.alones[ns] = a
	return a
}

// noneSizes are the sizes of the bundle with every namespace's change held
// and the cluster rule sets' published, accounted.
func (o *oracle) noneSizes() (raw, gz int) {
	if o.none == nil {
		next, _ := o.hold(func(ns string) bool { return ns != "" })
		raw, gz := o.s.sizes(o.accounted(next))
		o.none = &[2]int{raw, gz}
	}
	return o.none[0], o.none[1]
}

// part is the prior namespaces' part of the reserve in a build:
// adoptionCap of each limit, at most half the reserve.
func (o *oracle) part() (raw, gz int) {
	if !o.reserving() {
		return 0, 0
	}
	l := o.s.lim
	return min(l.raw/100*adoptionCap, l.raw/100*o.s.reserve/2), min(l.gz/100*adoptionCap, l.gz/100*o.s.reserve/2)
}

// carrying reports whether, due, namespaces held in the wait while
// protected are prior: they alone then share a part of the reserve.
func (o *oracle) carrying() bool { return o.due && len(o.carried) > 0 }

// reserves reports whether ns's change may take part of the reserve: it is
// prior, and carried when some are.
func (o *oracle) reserves(ns string) bool { return o.prior[ns] && (!o.carrying() || o.carried[ns]) }

// adoptPart is the prior namespaces' part of the reserve in this build
// (part): none once the cluster rule sets' changes are due, but for the
// namespaces carried.
func (o *oracle) adoptPart() (raw, gz int) {
	if o.due && !o.carrying() {
		return 0, 0
	}
	return o.part()
}

// adopts reports whether sizes raw and gz are larger than none, or than
// the reserve line, whichever is larger, by at most aRaw and aGz.
func (o *oracle) adopts(raw, gz, noneRaw, noneGz, aRaw, aGz int) bool {
	l := o.s.lim
	lineRaw, lineGz := l.raw-l.raw/100*o.s.reserve, l.gz-l.gz/100*o.s.reserve
	return gz >= 0 && noneGz >= 0 && raw <= max(lineRaw, noneRaw)+aRaw && gz <= max(lineGz, noneGz)+aGz
}

// alone reports whether ns's change fits alone: the limits, as published
// and with the published policies it leaves out counted; not the reserve,
// but once the cluster rule sets' changes are due (it then has no part of
// it left, but if it was held in the wait while protected: a part).
func (o *oracle) alone(ns string) bool {
	a := o.measureAlone(ns)
	if !a.changed || !a.fits {
		return a.fits
	}
	if o.due && o.inReserve(a.raw, a.gz) {
		nRaw, nGz := o.noneSizes()
		aRaw, aGz := 0, 0
		if o.carriedBefore[ns] {
			aRaw, aGz = o.part()
		}
		return o.adopts(a.raw, a.gz, nRaw, nGz, aRaw, aGz)
	}
	return true
}

// small reports whether ns's change grows its share by at most
// adoptionCap: raw, counted, and compressed, the bundle with its change
// alone over the bundle with none (measured says whether the builder
// measured it alone; not measured, its content compressed alone, now over
// before: gzAlone).
func (o *oracle) small(ns string, measured bool) bool {
	capRaw, capGz := o.s.lim.raw/100*adoptionCap, o.s.lim.gz/100*adoptionCap
	if rawShare(o.full, ns)-rawShare(o.prev, ns) > capRaw {
		return false
	}
	if a := o.measureAlone(ns); measured && a.changed {
		_, nGz := o.noneSizes()
		return a.gz-max(nGz, 0) <= capGz
	}
	now, err := gzAlone(o.full, ns)
	if err != nil {
		o.s.t.Fatal(err)
	}
	was, err := gzAlone(o.prev, ns)
	if err != nil {
		o.s.t.Fatal(err)
	}
	return now-was <= capGz
}

func (s *propScenario) build(round int) {
	f := s
	prev, lastVersion := s.prev, s.lastVersion
	waitedBefore, carriedBefore := s.waited, s.carried
	var fits []fitted
	pub := s.publish(round, func(h fitted) { fits = append(fits, h) })
	s.stats.builds.Add(1)
	if len(fits) == 0 {
		// Unchanged: nothing waits.
		s.pending = map[string]propPending{}
		return
	}
	s.stats.fitted.Add(1)
	h := fits[0]
	// (iv): the published bundle fits, measured here.
	if pub != prev && !s.fits(pub) {
		r, g := s.sizes(pub)
		s.fail(round, "(iv) the published bundle %d doesn't fit: %d raw, %d compressed; held %v, kept %t, protected %v, over %v, "+
			"%d encodes", pub.GetVersion(), r, g, heldNames(h), h.kept, h.protected, h.over, h.encodes)
	}
	s.stats.encodes.Add(int64(h.encodes))
	full := h.all
	// The bundle with every change, measured here (the gate's oracle).
	rawFull, gzFull := s.sizes(full)
	if m := h.allSizes; m != nil && m.gzKnown && (m.raw != rawFull || m.gz != gzFull) {
		s.fail(round, "the builder measured the bundle with every change at %d raw, %d compressed; it is %d, %d", m.raw, m.gz, rawFull, gzFull)
	}
	fullFits := rawFull <= f.lim.raw && gzFull >= 0 && gzFull <= f.lim.gz
	if pub == full && !fullFits {
		s.fail(round, "(iv) the published bundle %d, with every change, doesn't fit", pub.GetVersion())
	}
	tenants := len(namespacesOf(full))
	freeRaw, freeGz := f.lim.raw/100*s.share, f.lim.gz/100*s.share
	gate := tenants > 1 && (prev != nil || !fullFits) &&
		(gzFull < 0 || f.lim.raw-rawFull < freeRaw || f.lim.gz-gzFull < freeGz)
	if h.gated != gate {
		s.fail(round, "the builder's gate is %t, want %t (raw %d, compressed %d, %d tenants)", h.gated, gate, rawFull, gzFull, tenants)
	}
	o := s.oracle(prev, full, lastVersion)
	// The cluster rule sets' changes waited a build already: no namespace
	// is protected.
	due := false
	for id, rs := range ruleSetsOf(full) {
		if w := waitedBefore[id]; w != nil && proto.Equal(w, rs) {
			due = true
		}
	}
	o.due = due
	o.carriedBefore, o.carried = map[string]bool{}, map[string]bool{}
	for ns := range carriedBefore {
		o.carriedBefore[ns] = due
	}
	for ns := range h.prior {
		o.prior[ns] = true
		if !due {
			o.protected[ns] = true
		}
		if o.carriedBefore[ns] {
			o.carried[ns] = true
		}
	}
	for ns := range h.guarded {
		o.guarded[ns] = true
	}
	// Reserved: the namespaces' changes but the prior ones grow the bundle
	// into the reserve.
	reserved := false
	if fullFits && o.inReserve(rawFull, gzFull) {
		bRaw, bGz, self := o.base(func(string) bool { return false })
		reserved = !self && (bGz < 0 || rawFull > bRaw || gzFull > bGz)
		if !reserved && slices.ContainsFunc(slices.Collect(maps.Keys(h.prior)), o.reserves) {
			// The prior namespaces' changes take at most their part.
			nRaw, nGz := o.noneSizes()
			aRaw, aGz := o.adoptPart()
			reserved = !o.adopts(rawFull, gzFull, nRaw, nGz, aRaw, aGz)
		}
	}
	switch {
	case gate:
		s.stats.gated.Add(1)
	case reserved:
		s.stats.reserved.Add(1)
	}
	if !fullFits {
		s.stats.tooLarge.Add(1)
	}
	if h.kept {
		s.stats.kept.Add(1)
	}
	if len(h.over) > 0 {
		s.stats.over.Add(1)
	}
	if len(h.prior) > 0 {
		s.stats.prior.Add(1)
	}
	var tooLarge []string
	for key, st := range h.res.PolicyStatus {
		if st.Reason == resolver.ReasonBundleTooLarge {
			tooLarge = append(tooLarge, key.String())
		}
	}
	slices.Sort(tooLarge)
	held := h.holds() || len(tooLarge) > 0
	if held {
		s.stats.held.Add(1)
	}
	s.logf("  build: bundle with every change %d raw, %d compressed (fits %t, gate %t, reserved %t, %d tenants); held %v %v, "+
		"over %v, prior %v, protected %v, kept %t, frozen %t, %d encodes", rawFull, gzFull, fullFits, gate, reserved, tenants,
		heldNames(h), tooLarge, slices.Sorted(maps.Keys(h.over)), slices.Sorted(maps.Keys(h.prior)), slices.Sorted(maps.Keys(h.protected)),
		h.kept, s.frozen, h.encodes)
	if s.frozen {
		return
	}

	// (vi), (i): it fits, the budget doesn't apply, and nothing grows into
	// the reserve.
	if fullFits && !gate && !reserved {
		label := "(i)"
		if tenants == 1 {
			label = "(vi)"
		}
		if held {
			s.fail(round, "%s the bundle with every change fits, without the budget or the reserve, and %v %v are held", label,
				heldNames(h), tooLarge)
		}
		if !slices.EqualFunc(pub.GetPolicies(), full.GetPolicies(), func(a, b *bundlev1.Policy) bool { return proto.Equal(a, b) }) ||
			!slices.EqualFunc(pub.GetRuleSets(), full.GetRuleSets(), func(a, b *bundlev1.RuleSet) bool { return proto.Equal(a, b) }) {
			s.fail(round, "%s the bundle with every change fits, without the budget or the reserve, and isn't what is published", label)
		}
	}

	// (ix): prior, guarded and protected namespaces as the rules define
	// them; not measured alone (the encode cap), a change fits alone.
	for _, ns := range slices.Sorted(maps.Keys(o.units)) {
		if ns == "" || h.kept || !held {
			continue // not fitted further: no namespace is prior
		}
		last, measured := o.last(ns), h.alone[ns]
		fits := !measured || o.alone(ns)
		wantPrior := last && !h.over[ns] && fits && o.small(ns, measured)
		wantGuarded := last && !h.over[ns] && fits && !due
		switch {
		case h.prior[ns] != wantPrior:
			s.fail(round, "(ix) namespace %s prior %t, want %t (last %t, over its share %t, measured alone %t, fits alone %t, grows "+
				"by at most adoptionCap %t)", ns, h.prior[ns], wantPrior, last, h.over[ns], measured, fits, o.small(ns, measured))
		case h.guarded[ns] != wantGuarded:
			s.fail(round, "(ix) namespace %s guarded %t, want %t (last %t, over its share %t, fits alone %t, due %t)", ns,
				h.guarded[ns], wantGuarded, last, h.over[ns], fits, due)
		case h.protected[ns] != (wantPrior && wantGuarded):
			s.fail(round, "(ix) namespace %s protected %t, want %t (prior %t, due %t)", ns, h.protected[ns], wantPrior && wantGuarded,
				h.prior[ns], due)
		}
	}
	// (ix): once due, the prior namespaces the wait held while protected
	// are carried (they alone share a part of the reserve); a wait carries
	// the protected namespaces it holds into the next build.
	for _, ns := range slices.Sorted(maps.Keys(o.units)) {
		if ns != "" && h.carried[ns] != o.carried[ns] {
			s.fail(round, "(ix) namespace %s carried %t, want %t (prior %t, due %t, held in the wait while protected %t)", ns,
				h.carried[ns], o.carried[ns], h.prior[ns], due, carriedBefore[ns])
		}
	}
	nsHeld := map[string]bool{}
	for k := range h.held {
		nsHeld[k.Namespace] = true
	}
	for id := range h.heldRuleSets {
		nsHeld[namespaceOfID(id)] = true
	}
	wantCarry := map[string]bool{}
	for ns := range h.protected {
		if len(h.waited) > 0 && nsHeld[ns] {
			wantCarry[ns] = true
		}
	}
	if !maps.Equal(h.carry, wantCarry) && len(h.carry)+len(wantCarry) > 0 {
		s.fail(round, "(ix) the build carries %v, want %v (the protected namespaces it holds, when it waits)",
			slices.Sorted(maps.Keys(h.carry)), slices.Sorted(maps.Keys(wantCarry)))
	}
	// (ii), (ix): a published policy is left out only by the budget, rule R,
	// or the last resort.
	rawBudget, gzBudget := f.lim.raw/100*s.share, f.lim.gz/100*s.share
	leftOut := map[string]bool{}
	for id := range o.leftOut(pub) {
		s.stats.leftOut.Add(1)
		if h.kept {
			continue
		}
		if st := h.res.PolicyStatus[keyOf(id)]; st.Reason != resolver.ReasonBundleTooLarge {
			s.fail(round, "published policy %s is left out, and says %s: %s", id, st.Reason, st.Message)
		}
		leftOut[namespaceOfID(id)] = true
	}
	for _, ns := range slices.Sorted(maps.Keys(leftOut)) {
		if h.over[ns] {
			rawNow, gzNow, okNow := s.shareOf(full, ns)
			rawWas, gzWas, okWas := s.shareOf(prev, ns)
			// A compressed share moves by tens of KiB (gzip's blocks):
			// within slack.
			tol := f.lim.slack
			overRaw := rawNow > rawBudget && rawNow > rawWas
			overGz := okNow && okWas && gzNow > gzBudget-tol && gzNow > gzWas-tol
			if !gate || !overRaw && !overGz {
				s.fail(round, "(ii) namespace %s's published policy is left out, and its share isn't over the budget and grown: "+
					"raw %d (was %d, budget %d), compressed %d (was %d, budget %d), gate %t", ns, rawNow, rawWas, rawBudget,
					gzNow, gzWas, gzBudget, gate)
			}
			continue
		}
		if h.guarded[ns] {
			s.fail(round, "(ii) namespace %s is guarded, and its published policy is left out", ns)
			continue
		}
		// Rule R (a), (ix): its change doesn't fit the limits alone (and,
		// due, the reserve), or, after a wait, it grows its share by more
		// than adoptionCap, or releasing it, with the rest as published,
		// doesn't fit; even at the encode cap.
		if o.alone(ns) && (!due || o.small(ns, true) && o.releasable(ns, pub, h)) {
			s.fail(round, "(ix) namespace %s's published policy is left out, its namespace is within its share, its change "+
				"fits alone on the bundle in force with every other namespace's change held, and (due %t) releasing it with the "+
				"rest as published fits (encodes %d of %d, repaired %t, carried %t)", ns, due, h.encodes, cmp.Or(s.maxEncodes, maxEncodes),
				h.repaired, o.carried[ns])
		}
	}
	s.checkReserve(round, prev, full, pub, h, o)

	// (iii): only namespaces with a change are held.
	moved := changed(prev, full)
	for key := range h.held {
		if !moved[key.Namespace] {
			s.fail(round, "(iii) policy %s is held, and its namespace has no change", key)
		}
	}
	for id := range h.heldRuleSets {
		if !moved[namespaceOfID(id)] {
			s.fail(round, "(iii) rule set %s is held, and it has no change", id)
		}
	}
	for _, key := range tooLarge {
		if ns, _, _ := strings.Cut(key, "/"); !moved[ns] {
			s.fail(round, "(iii) policy %s is BundleTooLarge, and its namespace has no change", key)
		}
	}

	s.checkStatuses(round, prev, full, pub, h)
	s.checkLiveness(round, prev, full, pub, h, o)
	s.checkReleases(round, pub, h, o)
}

// checkReserve: (x) the namespaces' changes take at most the prior
// namespaces' part of the reserve (adoptPart: none once the cluster rule
// sets' changes are due, but the carried ones') over the bundle with every
// namespace's change held, or over the reserve line, whichever is larger;
// but for a first bundle, a single tenant and the last resort. Measured as
// the builder measures the try it publishes: with the published policies
// it leaves out counted, and, if it waits for a guarded namespace whose
// change it releases, with the cluster rule sets' changes.
func (s *propScenario) checkReserve(round int, prev, full, pub *bundlev1.Bundle, h fitted, o *oracle) {
	if !o.reserving() || h.kept || pub == prev {
		return
	}
	nsHeld, clusterHeld := map[string]bool{}, false
	for k := range h.held {
		nsHeld[k.Namespace] = true
	}
	for id := range h.heldRuleSets {
		if ns := namespaceOfID(id); ns != "" {
			nsHeld[ns] = true
		} else {
			clusterHeld = true
		}
	}
	measured := pub
	counted := clusterHeld && slices.ContainsFunc(slices.Collect(maps.Keys(o.guarded)), func(ns string) bool { return !nsHeld[ns] })
	if counted {
		measured = o.withCluster(pub)
	}
	raw, gz := s.sizes(o.accounted(measured))
	if !o.inReserve(raw, gz) {
		return
	}
	next, _ := o.hold(func(ns string) bool { return ns != "" || clusterHeld && !counted })
	nRaw, nGz := s.sizes(o.accounted(next))
	if aRaw, aGz := o.adoptPart(); !o.adopts(raw, gz, nRaw, nGz, aRaw, aGz) {
		s.fail(round, "(x) the published bundle takes the reserve (%d%%) past the prior namespaces' part (%d, %d bytes): %d raw, %d "+
			"compressed, with every namespace's change held %d, %d (due %t, prior %v, held %v)", s.reserve, aRaw, aGz, raw, gz,
			nRaw, nGz, o.due, slices.Sorted(maps.Keys(h.prior)), heldNames(h))
	}
}

// keyOf is the WAFPolicy of a policy id.
func keyOf(id string) types.NamespacedName {
	ns, name, _ := strings.Cut(id, "/")
	return types.NamespacedName{Namespace: ns, Name: name}
}

// checkStatuses: held policies and rule sets say BundleTooLarge, (vii) a
// changed cluster rule set shipped as it was does too, and heldCount
// counts every BundleTooLarge.
func (s *propScenario) checkStatuses(round int, prev, full, pub *bundlev1.Bundle, h fitted) {
	n := 0
	for key, st := range h.res.PolicyStatus {
		if st.Reason == resolver.ReasonBundleTooLarge {
			n++
		} else if _, ok := h.held[key]; ok {
			s.fail(round, "held policy %s says %s", key, st.Reason)
		}
	}
	was := ruleSetsOf(prev)
	for id, st := range h.res.RuleSetStatus {
		if st.Reason == resolver.ReasonBundleTooLarge {
			n++
		} else if _, ok := h.heldRuleSets[id]; ok && was[id] != nil {
			s.fail(round, "held rule set %s says %s", id, st.Reason)
		}
	}
	if c := heldCount(h); c != n {
		s.fail(round, "heldCount is %d, and %d objects say BundleTooLarge", c, n)
	}
	now := ruleSetsOf(pub)
	for id, rs := range ruleSetsOf(full) {
		if namespaceOfID(id) != "" || was[id] == nil || proto.Equal(was[id], rs) || !proto.Equal(now[id], was[id]) {
			continue
		}
		if st := h.res.RuleSetStatus[id]; st.Reason != resolver.ReasonBundleTooLarge {
			s.fail(round, "(vii) cluster rule set %s changed, ships as it was, and says %s: %s", id, st.Reason, st.Message)
		}
	}
}

// checkLiveness: a cluster rule set's change is published within two
// builds, unless the last resort runs, or it doesn't fit even with every
// namespace's change held, or then no policy that binds it resolves (each
// keeps its previous version, which binds it as it was).
func (s *propScenario) checkLiveness(round int, prev, full, pub *bundlev1.Bundle, h fitted, o *oracle) {
	was, now := ruleSetsOf(prev), ruleSetsOf(pub)
	pending := map[string]propPending{}
	for id, rs := range ruleSetsOf(full) {
		if namespaceOfID(id) != "" || was[id] == nil || proto.Equal(was[id], rs) || !proto.Equal(now[id], was[id]) {
			continue
		}
		s.stats.waited.Add(1)
		p, ok := s.pending[id]
		if !ok || !proto.Equal(p.rs, rs) {
			pending[id] = propPending{rs: rs, since: round}
			continue
		}
		pending[id] = p
		if h.kept {
			continue
		}
		// With every namespace's change held, it ships as it is now (a
		// policy that resolves binds it) and fits.
		held := func(ns string) bool { return ns != "" }
		if next, ch := o.hold(held); proto.Equal(ruleSetsOf(next)[id], rs) && o.fits(next, ch, held) {
			s.fail(round, "liveness: cluster rule set %s's change waits since round %d, and it fits with every namespace's change held",
				id, p.since)
		}
	}
	s.pending = pending
}

// checkReleases: (viii) a namespace within its share is held only if
// releasing it, with the rest as published, doesn't fit or would leave out
// a published policy the published bundle has, or a protected namespace
// stays held, unless the encode cap came first.
func (s *propScenario) checkReleases(round int, pub *bundlev1.Bundle, h fitted, o *oracle) {
	if h.kept || h.capped {
		return
	}
	nsHeld := map[string]bool{}
	for k := range h.held {
		nsHeld[k.Namespace] = true
	}
	for id := range h.heldRuleSets {
		if ns := namespaceOfID(id); ns != "" {
			nsHeld[ns] = true
		}
	}
	for _, ns := range slices.Sorted(maps.Keys(nsHeld)) {
		if h.over[ns] {
			continue
		}
		// While a protected namespace is held, the others' changes are.
		if !o.protected[ns] && slices.ContainsFunc(slices.Collect(maps.Keys(o.protected)), func(p string) bool { return nsHeld[p] }) {
			continue
		}
		if o.releasable(ns, pub, h) {
			s.fail(round, "(viii) namespace %s, within its share, is held, and releasing it (the rest as published) fits and leaves "+
				"no other published policy out; encodes %d of %d; held %v", ns, h.encodes, cmp.Or(s.maxEncodes, maxEncodes), heldNames(h))
		}
	}
}

// releasable reports whether releasing held namespace ns's change, with
// the rest as h publishes it (pub), fits and leaves out no other policy
// that pub has.
func (o *oracle) releasable(ns string, pub *bundlev1.Bundle, h fitted) bool {
	nsHeld, clusterHeld := map[string]bool{}, false
	for k := range h.held {
		nsHeld[k.Namespace] = true
	}
	for id := range h.heldRuleSets {
		if n := namespaceOfID(id); n != "" {
			nsHeld[n] = true
		} else {
			clusterHeld = true
		}
	}
	try := func(other string) bool {
		return other != ns && (other == "" && clusterHeld || other != "" && nsHeld[other])
	}
	next, ch := o.hold(try)
	inPub := ids(pub)
	for id := range o.leftOut(next) {
		if inPub[id] {
			return false
		}
	}
	return o.fits(next, ch, try)
}
