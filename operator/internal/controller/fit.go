// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// One namespace mustn't keep the other namespaces' changes from the
// engines, by filling the bundle or by growing it past its limits (7,200
// KiB compressed, 64 MiB raw). The builder holds back changes, namespace by
// namespace, and publishes the others. A change is a unit: a policy that
// differs from its version in the bundle in force (or is new), or a rule
// set that does. A held policy keeps its previous version, or is left out
// when new (resolver.Input.Hold); a held rule set ships as it was, and the
// policies that bind it are checked with that version
// (resolver.Input.HoldRuleSets). A namespace's units are held together.
//
// Share. A namespace's content is its policies and its rule sets
// (WAFRuleSets, bound only from their own namespace). Cluster rule sets (ClusterWAFRuleSets, the CRS) are in
// nobody's share, whoever binds them: a namespace's share depends only on
// its own content. Its share is what the bundle saves without that
// content, raw and compressed, each measured on the whole bundle as it is
// published: gzip refers back across messages, so sizes don't add up from
// messages measured alone. Taking content out also moves what follows it
// in gzip's blocks: a compressed share is exact to tens of KiB, and can
// even come out negative (it then ranks as 0).
//
// Gate. The budget applies only when the bundle with every change would
// leave less than spec.bundle.namespaceShare (25% by default) of either
// limit free, and never when one namespace has all the content (a single
// tenant) or to a first bundle that fits.
//
// Budget. Under the gate, a namespace is over its share when its share,
// measured, with its changes is over spec.bundle.namespaceShare of a
// limit, and its changes grow that measure from its share of the bundle in
// force (none, for a namespace new to it or a first bundle). Its changes
// are then held. A raw share is always measured (counted); a compressed
// share is measured only within the encode cap, for the namespaces whose
// raw share could be over the compressed budget: first those whose holding
// would leave out a policy the bundle in force has, then the largest raw
// shares. A compressed share not measured, now or in the bundle in force,
// is within the budget. Nothing published is taken out: a namespace over
// its share may still change without growing it.
//
// Reserve. spec.bundle.clusterReserve (10% by default) of each limit is
// kept for cluster rule set changes, which only an admin makes: a CRS
// upgrade mustn't wait for room that tenants filled. A bundle fits the
// reserve when it leaves the reserve of both limits free, or when it is no
// larger, raw and compressed, than the same bundle with every namespace's
// change held but the prior ones (its base; below), and, if it releases a
// prior namespace's change, larger than the same bundle with every
// namespace's change held, or than the reserve line, whichever is larger,
// by at most adoptionCap (4%) of each limit (at most half the reserve;
// once the cluster rule sets' changes are due, below, only for the
// namespaces the wait held while protected): namespaces' changes
// may not grow the bundle into the reserve, cluster rule set changes may,
// and the prior namespaces' changes, which adopt them, may take that part
// of it together. It never applies to a single tenant, to a first bundle,
// or to the last resort. Otherwise, without the gate, a bundle that fits
// its limits and the reserve is published as it is, as before the budget.
//
// Fit. If the bundle, with those changes held, still doesn't fit (its
// limits or the reserve), the other namespaces with a change are ranked by
// share, the largest first (the larger of its raw share of the raw limit
// and its compressed share of the compressed limit, its raw share when not
// measured; ties to the namespace whose oldest object was created last,
// then to its name), the prior namespaces (below) come after the others,
// and the cluster rule sets' changes after every namespace. The builder
// holds the shortest prefix of that order with which the bundle fits (a
// binary search), then tries to release each group of the prefix, from the
// last, keeping a release only when the bundle still fits, and goes over
// the prefix again until a pass releases nothing.
//
// Left out. A namespace is last when holding it leaves out a policy the
// bundle in force has: the policy's previous version doesn't compile with
// a cluster rule set as it is now (its version now does: it is in the
// bundle with every change). Its change fits alone when it fits on the
// bundle in force with every other namespace's change held and the cluster
// rule sets' changes, which it adopts, published, against the limits only,
// not the reserve (but once the cluster rule sets' changes are due: then
// the reserve too, without the prior namespaces' part, but for a namespace
// the wait held while protected: with a part of its own). That costs two
// encodes per last namespace, and one more, before the search, the
// smallest growth first as estimated by compressing its content alone
// (gzAlone); not measured within the cap, it fits. A last namespace within
// its share whose change fits alone is guarded while the cluster rule
// sets' changes may still wait (below): a try that leaves out its policy
// doesn't fit. It is prior when its change, besides, grows its share by at
// most adoptionCap of each limit, raw (counted) and compressed (the bundle
// with its change alone over the bundle with none, or not measured, its
// content compressed alone, now over then): what adopting a cluster rule
// set's change takes, not ballast. Prior namespaces come after every other
// namespace in the order, so they are released first, the smallest growth
// first (measured, or estimated), and their changes may take part of the
// reserve. A prior namespace that is guarded is protected: a try that
// holds it and releases another namespace's change doesn't fit. Outside
// the last resort, a try that leaves out a published policy doesn't fit,
// unless its namespace is held over its share, or is last and not
// guarded. So when the guarded namespaces' changes don't all fit, the
// cluster rule sets' changes are held for one build (a wait): those that
// fit are published against them as they were, measured with the cluster
// rule sets' changes too, so that these fit next build, and the others'
// changes wait (and, when repair holds them, in the next build too: two
// builds at most per cluster rule set change). The cluster rule sets' changes are never held that way two
// builds in a row (fitParams.waited): in the next build (they are due), no
// namespace is guarded and the prior ones have no part of the reserve, a
// last one may be left out, and one held then no longer fits alone, unless
// the bundle changed. But the prior namespaces the wait held while they
// were protected (carried: fitParams.carried) share a part of their own,
// adoptionCap again, released before the other prior namespaces, the
// smallest change first: so a squatter released before an adopter in the
// wait doesn't take the part its fix needs, unless the wait held the
// squatter too (a residual: see 0004). When the encode cap comes before the releases were
// all tried, the last namespaces within their share whose change fits
// alone and that the cap would leave held untried are tried past it
// (repair): together, then the most of them in release order, then each
// of the others with those. Every try is measured with the published policies it leaves
// out counted, as they were (with the rule sets and schemas they bind), so
// leaving out a policy frees no room for anyone. A policy left out says
// BundleTooLarge and counts as held, and so does a cluster rule set whose
// change isn't published.
//
// Never frozen. When the bundle doesn't fit even with every unit held, the
// bundle in force is published again with every unit held, deletions
// published, and the InkwallConfig settings of the bundle in force: the
// last resort, which may leave out any policy whose previous version
// doesn't compile, and isn't held to the reserve. Only when even that
// doesn't fit does the bundle in force stay as it is.
//
// Guarantee. What is published was encoded, signed, as it is published,
// and fits; the order only picks what is held, so it needn't be monotone.
// A namespace with no change is never held. A namespace within its budget
// is held only when releasing it, with the other releases kept, didn't fit
// (the release passes end only when none is left to release), or a
// protected namespace is held, or when the encode cap came first. A
// published policy of a namespace within its budget is left out only when
// its change doesn't fit alone, or in the build after a wait, when a try
// that released it didn't fit or its change grows its share by more than
// adoptionCap; never because the encode cap came first (but past the
// maxEncodes encodes repair has to try them one by one). A cluster rule
// set's change is held only when every namespace with a change is held too
// and the bundle still doesn't fit, or, for one build, for guarded
// namespaces whose changes don't all fit. The prior namespaces' changes
// take at most adoptionCap (at most half the reserve) of the reserve per
// build, and in the build after a wait only those the wait held while
// protected: at most twice that per cluster rule set change (but across
// restarts: fitParams.waited and carried are the reconciler's).
//
// Cost. A raw size is counted (proto.Size) before anything is marshaled,
// and a bundle over the raw limit is never compressed. A bundle whose raw
// size leaves the gate's and the reserve's room in both limits, even
// compressed at worst, is published as it is: nothing is counted. A build
// encodes at most maxEncodes bundles: the one with every change; under the
// gate, the compressed share of at most maxMeasured namespaces, as above,
// and for those over the budget, the bundle in force and their shares in
// it; two per last namespace (alone), and the bundle with every
// namespace's change held, while the search keeps its encodes; the
// reserve's bases, one per set of prior namespaces a try releases, and
// that one; the shares the order needs, until maxMeasured; and the tries:
// the budget's, every unit held, the last resort, a binary search of
// log2(n) + 1 for n namespaces with a change, and releases until the cap.
// Past the cap, repair tries at most log2(m) + 3 more for m last
// namespaces, and then tries them one by one until maxEncodes more
// encodes are spent (a try encodes up to 3, so maxEncodes + 2 at most), only in a build with a cluster rule set's change. A try that
// leaves out a policy, or is measured with the cluster rule sets' changes
// it holds, is encoded twice: as measured, and as published; a try that
// holds a protected namespace and releases another isn't encoded. Which
// namespaces are last is compiled once per published policy that binds a
// changed cluster rule set, without encoding, and each last namespace's
// content is compressed alone twice (now and then), at most the bundle's
// size twice in all.

const (
	// maxEncodes bounds the bundles a build encodes to fit.
	maxEncodes = 64
	// maxMeasured bounds the namespaces whose compressed share is measured.
	maxMeasured = 16
	// defaultNamespaceShare is spec.bundle.namespaceShare's default.
	defaultNamespaceShare = 25
	// defaultClusterReserve is spec.bundle.clusterReserve's default.
	defaultClusterReserve = 10
	// adoptionCap is how much of each limit, in percent, a change that
	// adopts a cluster rule set's change may grow its namespace's share by
	// and be released first, and how much of the reserve such changes may
	// take together in a build: fixing a rule id, or a rule a CRS upgrade
	// breaks, takes a few bytes, and a rule set rewritten for it rarely 1%.
	adoptionCap = 4
)

// fitLimits are the limits a bundle is fitted to.
type fitLimits struct {
	// raw and gz are a bundle's largest size, signed, raw and compressed.
	raw, gz int
	// slack bounds what gzip's back-references across a namespace's
	// content can add to its compressed share over its raw one.
	slack int
}

// secretLimits are its Secrets' (the tests scale them down).
var secretLimits = fitLimits{raw: bundlesecret.MaxBundleBytes, gz: bundle.MaxCompressedBytes, slack: 128 << 10}

// mayBeOverGz reports whether content of raw bytes may be over a
// compressed budget of gz bytes: compressed, a share is at most about the
// raw one (slack).
func (l fitLimits) mayBeOverGz(raw, gz int) bool { return raw+raw/64+l.slack > gz }

// roomy reports whether a bundle of raw bytes, unsigned, surely leaves at
// least freeRaw and freeGz bytes of the limits free: the signature adds
// well under 4 KiB, gzip at most raw/64.
func (l fitLimits) roomy(raw, freeRaw, freeGz int) bool {
	return raw+4<<10 <= l.raw-freeRaw && raw+raw/64+4<<10 <= l.gz-freeGz
}

// part is pct percent of the raw and compressed limits.
func (l fitLimits) part(pct int) (raw, gz int) { return l.raw / 100 * pct, l.gz / 100 * pct }

// namespaceShare is the budget spec.bundle.namespaceShare sets, in
// percent.
func namespaceShare(share int32) int {
	if share <= 0 {
		return defaultNamespaceShare
	}
	return min(max(int(share), 5), 100)
}

// clusterReserve is the reserve spec.bundle.clusterReserve sets, in
// percent: its default when unset.
func clusterReserve(reserve *int32) int {
	if reserve == nil {
		return defaultClusterReserve
	}
	return min(max(int(*reserve), 0), 50)
}

// fitParams are what a fit follows besides the build: the InkwallConfig's
// share and reserve, in percent, and the cluster rule sets the build
// before shipped as they were, though they changed (fitted.waited).
type fitParams struct {
	share, reserve int
	waited         map[string]*bundlev1.RuleSet
	// carried are the namespaces the build before held while they were
	// protected, in a wait (fitted.carry): in the due build they alone
	// share the prior namespaces' part of the reserve.
	carried map[string]bool
}

// holdUnit is a change the builder can hold back.
type holdUnit struct {
	// policy is held, or ruleSet (its id).
	policy  types.NamespacedName
	ruleSet string
}

// holdGroup is a namespace's units, or the cluster rule sets'.
type holdGroup struct {
	// namespace is "" for the cluster rule sets.
	namespace string
	units     []holdUnit
	// created is its oldest object's creation.
	created time.Time
	// raw and gz are its share of the bundle with every change; gz isn't
	// measured unless gzKnown. rawWas is its raw share of the bundle in
	// force.
	raw, gz int
	gzKnown bool
	rawWas  int
	tried   bool // measured, or tried to
	// budget says why its changes are over its share, measured; "" when
	// they aren't.
	budget string
	// last: holding it leaves out a policy the bundle in force has (its
	// previous version doesn't compile with a cluster rule set as it is
	// now). fits: its change fits the limits alone (or that wasn't
	// measured, within the cap: aloneKnown). growRaw is how much its change
	// grows its raw share (counted), growGz how much the bundle with its
	// change alone is larger compressed than with none (measured with
	// aloneKnown), and estGz how much its content grows compressed alone,
	// without the rest of the bundle (gzAlone: an estimate of growGz that
	// costs compressing its content only). prior: last, within its budget,
	// its change fits alone and
	// grows it by at most adoptionCap of each limit (the adoption): it is
	// released before every other namespace's change, and such changes may
	// take adoptionCap of the reserve together.
	// guarded: last, within its budget and its change fits alone, while the
	// cluster rule sets' changes may still wait (not due): holding it may
	// not leave that policy out, the cluster rule sets' changes wait
	// instead. protected: prior and guarded: holding it holds every other
	// namespace's change too.
	last, fits, prior, guarded, protected bool
	// carried: prior, in the due build, and held in the wait while
	// protected (fitParams.carried).
	carried                bool
	growRaw, growGz, estGz int
	aloneKnown             bool
}

// growth is how much its change alone grows the bundle, of the limit it
// grows most: compressed, measured, or estimated (estGz) when not.
func (g *holdGroup) growth(l fitLimits) float64 {
	gz := g.estGz
	if g.aloneKnown {
		gz = g.growGz
	}
	return max(float64(g.growRaw)/float64(l.raw), float64(gz)/float64(l.gz))
}

// gzAlone is the size of ns's policies and rule sets in b, compressed
// alone: the difference between two of them estimates how much a change
// grows the bundle compressed (gzip refers back 32 KiB at most, so the
// rest of the bundle changes it little), at the cost of compressing ns's
// content only.
func gzAlone(b *bundlev1.Bundle, ns string) (int, error) {
	part := &bundlev1.Bundle{}
	for _, p := range b.GetPolicies() {
		if namespaceOfID(p.GetId()) == ns {
			part.Policies = append(part.Policies, p)
		}
	}
	for _, rs := range b.GetRuleSets() {
		if strings.HasPrefix(rs.GetId(), "WAFRuleSet/") && namespaceOfID(rs.GetId()) == ns {
			part.RuleSets = append(part.RuleSets, rs)
		}
	}
	raw, err := proto.Marshal(part)
	if err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	return buf.Len(), nil
}

// rank is its share of the limit it takes most of; not measured, its
// compressed share counts as its raw one. gzip can make a compressed share
// negative: it then counts as 0.
func (g *holdGroup) rank(l fitLimits) float64 {
	gz := g.gz
	if !g.gzKnown {
		gz = g.raw
	}
	return max(float64(g.raw)/float64(l.raw), float64(max(gz, 0))/float64(l.gz))
}

// sizes are a bundle's, signed, as published.
type sizes struct {
	raw, gz int
	gzKnown bool
	// err is bundle.ErrTooLarge's, when it doesn't fit.
	err error
}

// namespaceOfID is the namespace of a policy's or a WAFRuleSet's id; ""
// for a ClusterWAFRuleSet's.
func namespaceOfID(id string) string {
	if strings.HasPrefix(id, "ClusterWAFRuleSet/") {
		return ""
	}
	ns, _, _ := strings.Cut(strings.TrimPrefix(id, "WAFRuleSet/"), "/")
	return ns
}

// errReserve is why a bundle that fits its limits isn't published as it
// is: it would leave less than the cluster reserve free.
var errReserve = errors.New("the bundle would leave less than spec.bundle.clusterReserve free")

// fitted is a build with the changes held that the budget, the limits and
// the reserve hold.
type fitted struct {
	res     resolver.Result
	next    *bundlev1.Bundle
	changed bool
	// held are the policies held back, heldRuleSets the rule sets.
	held         map[types.NamespacedName]string
	heldRuleSets map[string]string
	// tooLarge is why the bundle with every change isn't published
	// (bundle.ErrTooLarge, or errReserve); nil when it fits (the budget
	// alone holds changes).
	tooLarge error
	// kept: even with every change held it didn't fit, so it is the bundle
	// in force with deletions, and its settings.
	kept bool
	// waited are the cluster rule sets it ships as they were, though they
	// changed, as they are now, by id: the next build's fitParams.waited.
	// carry are the protected namespaces it holds when it waits: the next
	// build's fitParams.carried.
	waited map[string]*bundlev1.RuleSet
	carry  map[string]bool
	// encodes is how many bundles were encoded to fit it.
	encodes int
	// For the tests: all is the bundle with every change, and allSizes
	// its sizes if it was measured; gated whether the budget applied,
	// reserved whether the reserve held changes, over the namespaces held
	// over their share, prior those whose change was released first,
	// guarded those whose change the cluster rule sets' changes could wait
	// for, protected those of them that were prior, alone the last
	// namespaces whose change was measured alone, carried those of the due
	// build that share a part of the reserve (fitParams.carried), capped
	// whether the encode cap came before every release was tried, and
	// repaired whether repair then tried a last namespace's.
	all       *bundlev1.Bundle
	allSizes  *sizes
	gated     bool
	reserved  bool
	capped    bool
	repaired  bool
	over      map[string]bool
	prior     map[string]bool
	guarded   map[string]bool
	protected map[string]bool
	alone     map[string]bool
	carried   map[string]bool
}

// holds reports whether it holds anything back.
func (h fitted) holds() bool { return len(h.held)+len(h.heldRuleSets) > 0 }

// holdsGroup reports whether it holds g's change.
func (h fitted) holdsGroup(g *holdGroup) bool {
	return slices.ContainsFunc(g.units, func(u holdUnit) bool {
		if u.ruleSet != "" {
			_, held := h.heldRuleSets[u.ruleSet]
			return held
		}
		_, held := h.held[u.policy]
		return held
	})
}

// fitter reduces a build.
type fitter struct {
	in     resolver.Input
	signer *bundle.Signer
	// build makes the bundle of a resolution (as bundle.Next); keep makes
	// it with the settings of the bundle in force.
	build, keep func(resolver.Result) (*bundlev1.Bundle, bool, error)
	params      fitParams
	lim         fitLimits
	groups      []*holdGroup // the namespaces with a change
	cluster     *holdGroup   // the cluster rule sets' changes; nil without
	tooLarge    error
	encodes     int
	tries       int
	maxEncodes  int
	// next and full are the bundle with every change and its sizes;
	// measured counts the compressed shares measured; gated: the budget
	// applies.
	next     *bundlev1.Bundle
	full     sizes
	measured int
	gated    bool
	// reserve is the reserve of each limit, in bytes; reserving: it
	// applies; reserved: it holds changes; adopt is how much of it the
	// prior namespaces' changes may take together in this build, and part
	// how much they may in a build (adoptionCap of each limit, at most half
	// the reserve). bases are the reserve's bases measured, by the groups
	// they hold. none is the bundle with every namespace's change held,
	// measured, once protect ran.
	reserveRaw, reserveGz int
	adoptRaw, adoptGz     int
	partRaw, partGz       int
	reserving, reserved   bool
	bases                 map[string]sizes
	none                  *sizes
	// due: the cluster rule sets' changes waited a build already, so none
	// is guarded; carrying: then some prior namespaces are carried (below).
	// protected: protect ran. capped: the encode cap came before every
	// release was tried; repaired: repair then tried a last namespace's.
	due, carrying, protectedDone, capped, repaired bool
	// published are the policies, by id, that both the bundle in force and
	// the bundle with every change have, with their namespace.
	published map[string]string
}

// fit returns the build of res, next (changed as bundle.Next said), with
// the changes held that the budget, the limits and the reserve hold (see
// above). ok is false only when even the bundle in force with deletions
// doesn't fit: it then stays, and tooLarge says why.
func fit(in resolver.Input, res resolver.Result, next *bundlev1.Bundle, changed bool, signer *bundle.Signer, params fitParams,
	build, keep func(resolver.Result) (*bundlev1.Bundle, bool, error), opts fitOptions) (fitted, bool, error) {
	f := &fitter{in: in, signer: signer, build: build, keep: keep, params: params, maxEncodes: cmp.Or(opts.maxEncodes, maxEncodes),
		lim: secretLimits}
	if opts.limits != (fitLimits{}) {
		f.lim = opts.limits
	}
	h, ok, err := f.fit(res, next, changed)
	h.encodes, h.all, h.gated, h.reserved, h.capped, h.repaired = f.encodes, next, f.gated, f.reserved, f.capped, f.repaired
	if f.next != nil {
		h.allSizes = &f.full
	}
	mark := func(m *map[string]bool, ns string, set bool) {
		if set {
			if *m == nil {
				*m = map[string]bool{}
			}
			(*m)[ns] = true
		}
	}
	for _, g := range f.groups {
		mark(&h.over, g.namespace, g.budget != "")
		mark(&h.prior, g.namespace, g.prior)
		mark(&h.guarded, g.namespace, g.guarded)
		mark(&h.protected, g.namespace, g.protected)
		mark(&h.alone, g.namespace, g.aloneKnown)
		mark(&h.carried, g.namespace, g.carried)
	}
	if ok && err == nil {
		h.waited = waited(in.Previous, next, h.next)
		for _, g := range f.groups {
			if len(h.waited) > 0 && g.protected && h.holdsGroup(g) {
				mark(&h.carry, g.namespace, true)
			}
		}
	}
	if opts.observe != nil {
		opts.observe(h)
	}
	return h, ok, err
}

// waited are the cluster rule sets of all, the bundle with every change,
// that changed from prev and that pub ships as they were, by id.
func waited(prev, all, pub *bundlev1.Bundle) map[string]*bundlev1.RuleSet {
	was, published := map[string]*bundlev1.RuleSet{}, map[string]*bundlev1.RuleSet{}
	for _, rs := range prev.GetRuleSets() {
		was[rs.GetId()] = rs
	}
	for _, rs := range pub.GetRuleSets() {
		published[rs.GetId()] = rs
	}
	var out map[string]*bundlev1.RuleSet
	for _, rs := range all.GetRuleSets() {
		id := rs.GetId()
		if namespaceOfID(id) != "" || was[id] == nil || proto.Equal(was[id], rs) || !proto.Equal(published[id], was[id]) {
			continue
		}
		if out == nil {
			out = map[string]*bundlev1.RuleSet{}
		}
		out[id] = rs
	}
	return out
}

// fitOptions are for the tests: maxEncodes, if not 0, limits smaller than
// the Secrets', if set, and a function that sees every fit.
type fitOptions struct {
	maxEncodes int
	limits     fitLimits
	observe    func(fitted)
}

func (f *fitter) fit(res resolver.Result, next *bundlev1.Bundle, changed bool) (fitted, bool, error) {
	as := fitted{res: res, next: next, changed: changed}
	raw := proto.Size(next)
	multi := f.in.Previous != nil && tenants(next) > 1
	f.reserving = multi && f.params.reserve > 0
	if f.reserving {
		f.reserveRaw, f.reserveGz = f.lim.part(f.params.reserve)
		capRaw, capGz := f.lim.part(adoptionCap)
		f.partRaw, f.partGz = min(capRaw, f.reserveRaw/2), min(capGz, f.reserveGz/2)
		f.adoptRaw, f.adoptGz = f.partRaw, f.partGz
	}
	freeRaw, freeGz := f.budgets()
	if f.lim.roomy(raw, max(freeRaw, f.reserveRaw), max(freeGz, f.reserveGz)) || f.lim.roomy(raw, 0, 0) && !multi {
		// It fits, and neither the budget nor the reserve applies.
		return as, true, nil
	}
	f.units(res)
	full, err := f.measure(next)
	if err != nil {
		return fitted{}, false, err
	}
	f.next, f.full = next, full
	f.gated = f.gate(next, full)
	if !f.gated && full.err == nil && !f.inReserve(full) {
		return as, true, nil
	}
	f.tooLarge = full.err
	f.published = map[string]string{}
	inForce := map[string]bool{}
	for _, p := range f.in.Previous.GetPolicies() {
		inForce[p.GetId()] = true
	}
	for _, p := range res.Policies {
		if inForce[p.GetId()] {
			f.published[p.GetId()] = namespaceOfID(p.GetId())
		}
	}
	for _, g := range f.groups {
		g.raw = rawShare(next, g.namespace)
	}
	f.findDue()
	if f.due {
		// The prior namespaces' part of the reserve went to the wait build;
		// those it held while protected get a part of their own (protect).
		f.adoptRaw, f.adoptGz = 0, 0
	}
	f.findLast()
	if f.gated {
		if err := f.shares(); err != nil {
			return fitted{}, false, err
		}
	}
	if f.tooLarge == nil && f.inReserve(full) {
		// Into the reserve: published as it is only if the namespaces'
		// changes, but the prior ones, don't grow it, and those take at
		// most their part of it.
		if err := f.protect(); err != nil {
			return fitted{}, false, err
		}
		ok, err := f.reserveFits(full, nil, false)
		if err != nil {
			return fitted{}, false, err
		}
		if !ok {
			f.reserved, f.tooLarge = true, f.reserveErr(full)
		}
	}
	var budget []*holdGroup
	for _, g := range f.groups {
		if g.budget != "" {
			budget = append(budget, g)
		}
	}
	if len(budget) == 0 && f.tooLarge == nil {
		return as, true, nil
	}
	if err := f.protect(); err != nil {
		return fitted{}, false, err
	}
	if len(budget) > 0 {
		h, ok, err := f.try(budget, false)
		if err != nil || ok {
			return h, ok, err
		}
		if f.tooLarge == nil {
			f.tooLarge = h.tooLarge
			f.reserved = errors.Is(h.tooLarge, errReserve)
		}
	}
	return f.search(budget)
}

// tenants counts the namespaces with content in b.
func tenants(b *bundlev1.Bundle) int {
	seen := map[string]bool{}
	for _, p := range b.GetPolicies() {
		seen[namespaceOfID(p.GetId())] = true
	}
	return len(seen)
}

// gate reports whether the budget applies to next, whose sizes are full:
// the bundle with every change would leave less than a namespace's share
// of a limit free, more than one namespace has content, and it isn't a
// first bundle that fits.
func (f *fitter) gate(next *bundlev1.Bundle, full sizes) bool {
	if tenants(next) <= 1 || f.in.Previous == nil && full.err == nil {
		return false
	}
	freeRaw, freeGz := f.budgets()
	// Not compressed: over the raw limit.
	return full.err != nil || !full.gzKnown || f.lim.raw-full.raw < freeRaw || f.lim.gz-full.gz < freeGz
}

// budgets are a namespace's share of the raw and compressed limits.
func (f *fitter) budgets() (raw, gz int) { return f.lim.part(f.params.share) }

// inReserve reports whether a bundle of sizes s would leave less than the
// reserve free, when it applies.
func (f *fitter) inReserve(s sizes) bool {
	return f.reserving && (s.err != nil || !s.gzKnown || f.lim.raw-s.raw < f.reserveRaw || f.lim.gz-s.gz < f.reserveGz)
}

// reserveErr says that a bundle of sizes s would leave less than the
// reserve free.
func (f *fitter) reserveErr(s sizes) error {
	return fmt.Errorf("%w (%d%%): %d bytes raw of %d, %d compressed of %d", errReserve, f.params.reserve, s.raw, f.lim.raw, s.gz, f.lim.gz)
}

// within reports whether s, which fits the limits, is no larger than b,
// raw and compressed. b may be over the compressed limit (a change it holds
// shrinks the bundle): s is then no larger than it, so far. One over the
// raw limit isn't compressed, so it can't tell.
func (s sizes) within(b sizes) bool {
	return s.err == nil && s.gzKnown && b.gzKnown && s.raw <= b.raw && s.gz <= b.gz
}

// measure returns b's sizes signed, as published. A bundle over the raw
// limit isn't marshaled.
func (f *fitter) measure(b *bundlev1.Bundle) (sizes, error) {
	if raw := proto.Size(b); raw > f.lim.raw {
		return sizes{raw: raw, err: fmt.Errorf("%w: %d bytes, at most %d", bundle.ErrTooLarge, raw, f.lim.raw)}, nil
	}
	signed, err := f.signer.Sign(b)
	if err != nil {
		return sizes{}, err
	}
	s := sizes{raw: proto.Size(signed)}
	if s.raw > f.lim.raw {
		s.err = fmt.Errorf("%w: %d bytes, at most %d", bundle.ErrTooLarge, s.raw, f.lim.raw)
		return s, nil
	}
	f.encodes++
	data, err := bundle.Encode(signed)
	s.gz, s.gzKnown = len(data), data != nil
	if err == nil && s.gz > f.lim.gz {
		err = fmt.Errorf("%w: %d bytes compressed, at most %d", bundle.ErrTooLarge, s.gz, f.lim.gz)
	}
	if errors.Is(err, bundle.ErrTooLarge) {
		s.err = err
		return s, nil
	}
	return s, err
}

// reserve is the encodes the search needs: the budget's try, every unit
// held, the last resort, the reserve's bases and the binary search.
func (f *fitter) reserve() int { return 5 + bits.Len(uint(len(f.groups)+1)) }

// units groups the changes of res from the bundle in force by namespace.
func (f *fitter) units(res resolver.Result) {
	created := map[string]time.Time{}
	for _, p := range f.in.Policies {
		created[resolver.PolicyID(p.Namespace, p.Name)] = p.CreationTimestamp.Time
	}
	for _, rs := range f.in.RuleSets {
		created[resolver.RuleSetID("WAFRuleSet", rs.Namespace, rs.Name)] = rs.CreationTimestamp.Time
	}
	for _, rs := range f.in.ClusterRuleSets {
		created[resolver.RuleSetID("ClusterWAFRuleSet", "", rs.Name)] = rs.CreationTimestamp.Time
	}
	group := map[string]*holdGroup{}
	add := func(ns, id string, u holdUnit) {
		g := group[ns]
		if g == nil {
			g = &holdGroup{namespace: ns, created: created[id]}
			group[ns] = g
			if ns == "" {
				f.cluster = g
			} else {
				f.groups = append(f.groups, g)
			}
		}
		g.units = append(g.units, u)
		if created[id].Before(g.created) {
			g.created = created[id]
		}
	}
	keys := map[string]types.NamespacedName{}
	for key, st := range res.PolicyStatus {
		if st.Applied {
			keys[resolver.PolicyID(key.Namespace, key.Name)] = key
		}
	}
	previous := map[string]*bundlev1.Policy{}
	for _, p := range f.in.Previous.GetPolicies() {
		previous[p.GetId()] = p
	}
	for _, p := range res.Policies {
		key, ok := keys[p.GetId()]
		if !ok {
			continue // a previous version kept: not a change
		}
		if old, ok := previous[p.GetId()]; ok && proto.Equal(p, old) {
			continue
		}
		add(key.Namespace, p.GetId(), holdUnit{policy: key})
	}
	oldRuleSets := map[string]*bundlev1.RuleSet{}
	for _, rs := range f.in.Previous.GetRuleSets() {
		oldRuleSets[rs.GetId()] = rs
	}
	for _, rs := range res.RuleSets {
		// One the bundle in force doesn't have ships with the changed
		// policies that bind it.
		if old, ok := oldRuleSets[rs.GetId()]; ok && !proto.Equal(rs, old) {
			add(namespaceOfID(rs.GetId()), rs.GetId(), holdUnit{ruleSet: rs.GetId()})
		}
	}
	slices.SortFunc(f.groups, func(a, b *holdGroup) int { return cmp.Compare(a.namespace, b.namespace) })
}

// without takes ns's content out of b until restore is called: its
// policies and its rule sets. Cluster rule sets stay, whoever binds them:
// they are in nobody's share.
func without(b *bundlev1.Bundle, ns string) (restore func()) {
	policies, ruleSets := b.Policies, b.RuleSets
	var kept []*bundlev1.Policy
	for _, p := range policies {
		if namespaceOfID(p.GetId()) == ns {
			continue
		}
		kept = append(kept, p)
	}
	b.Policies = kept
	// A WAFRuleSet is bound only from its own namespace.
	b.RuleSets = slices.DeleteFunc(slices.Clone(ruleSets), func(rs *bundlev1.RuleSet) bool {
		return strings.HasPrefix(rs.GetId(), "WAFRuleSet/") && namespaceOfID(rs.GetId()) == ns
	})
	return func() { b.Policies, b.RuleSets = policies, ruleSets }
}

// rawShare is ns's raw share of b: counted, not marshaled.
func rawShare(b *bundlev1.Bundle, ns string) int {
	all := proto.Size(b)
	restore := without(b, ns)
	defer restore()
	return all - proto.Size(b)
}

// gzShare is ns's compressed share of b, whose sizes are all; !ok when it
// isn't known.
func (f *fitter) gzShare(b *bundlev1.Bundle, all sizes, ns string) (int, bool, error) {
	restore := without(b, ns)
	defer restore()
	s, err := f.measure(b)
	if err != nil || !s.gzKnown || !all.gzKnown {
		return 0, false, err
	}
	return all.gz - s.gz, true, nil
}

// shares marks, under the gate, the namespaces whose changes grow their
// share, measured, past the budget. A raw share is counted. A compressed
// share is measured, within the cap, only for the namespaces whose raw
// share could be over the compressed budget: first those whose holding
// would leave out a published policy (last), then the largest raw shares.
// One not measured, now or in the bundle in force, is within the budget.
// It leaves two encodes for each last namespace, and one more (protect).
func (f *fitter) shares() error {
	rawBudget, gzBudget := f.budgets()
	prev := f.in.Previous
	var measure []*holdGroup
	lastOnes := 0
	for _, g := range f.groups {
		if prev != nil {
			g.rawWas = rawShare(prev, g.namespace)
		}
		if g.raw > rawBudget && g.raw > g.rawWas {
			g.budget = fmt.Sprintf("with this change its content would take %d bytes of the bundle's %d raw (%d%%)",
				g.raw, f.lim.raw, percent(g.raw, f.lim.raw))
			continue
		}
		if g.last {
			lastOnes++
		}
		if f.lim.mayBeOverGz(g.raw, gzBudget) {
			measure = append(measure, g)
		}
	}
	// By risk, then by raw share; f.groups are by name.
	slices.SortStableFunc(measure, func(a, b *holdGroup) int {
		return cmp.Or(compareBool(b.last, a.last), cmp.Compare(b.raw, a.raw))
	})
	var before *sizes
	for _, g := range measure {
		// Its share, the bundle in force's, and its share of it; protect's
		// two encodes per last namespace.
		if f.measured >= maxMeasured || !f.full.gzKnown || f.encodes+f.reserve()+2*lastOnes+min(lastOnes, 1)+3 > f.maxEncodes {
			return nil
		}
		g.tried = true
		f.measured++
		var err error
		if g.gz, g.gzKnown, err = f.gzShare(f.next, f.full, g.namespace); err != nil {
			return err
		}
		if !g.gzKnown || g.gz <= gzBudget {
			continue
		}
		gzWas, known := 0, true
		if prev != nil && g.rawWas > 0 {
			if before == nil {
				s, err := f.measure(prev)
				if err != nil {
					return err
				}
				before = &s
			}
			if gzWas, known, err = f.gzShare(prev, *before, g.namespace); err != nil {
				return err
			}
		}
		if known && g.gz > gzWas {
			g.budget = fmt.Sprintf("with this change its content would take %d bytes of the bundle's %d compressed (%d%%)",
				g.gz, f.lim.gz, percent(g.gz, f.lim.gz))
			if g.last {
				lastOnes--
			}
		}
	}
	return nil
}

// gzShares measures, for the order, the compressed share of the groups
// that want it, the largest raw shares first, at most maxMeasured in all,
// leaving the encodes the search needs.
func (f *fitter) gzShares(want func(*holdGroup) bool) error {
	byRaw := slices.Clone(f.groups)
	slices.SortStableFunc(byRaw, func(a, b *holdGroup) int { return cmp.Compare(b.raw, a.raw) })
	for _, g := range byRaw {
		if f.measured >= maxMeasured || !f.full.gzKnown || f.encodes+f.reserve()+2 > f.maxEncodes {
			return nil
		}
		if g.gzKnown || g.tried || !want(g) {
			continue
		}
		g.tried = true
		f.measured++
		var err error
		if g.gz, g.gzKnown, err = f.gzShare(f.next, f.full, g.namespace); err != nil {
			return err
		}
	}
	return nil
}

func percent(n, of int) int { return n * 100 / of }

// message is the BundleTooLarge message of u, of g; waits: a protected
// namespace is held with it; first: a prior namespace's change is
// released, and g isn't prior.
func (f *fitter) message(g *holdGroup, u holdUnit, kept, waits, first bool) string {
	what := "this policy's change"
	if u.ruleSet != "" {
		what = "this rule set's change"
	}
	if g.budget != "" && !kept {
		return fmt.Sprintf("not published: namespace %s is over its share of the bundle: %s, over spec.bundle.namespaceShare (%d%%), "+
			"and more than in the bundle in force. A namespace's changes that grow its share past it are held back while the bundle "+
			"with every change would leave less than that share of a limit free (nothing published is taken out), so %s is held. "+
			"Shrink the namespace's policies or rule sets, or raise spec.bundle.namespaceShare", g.namespace, g.budget, f.params.share, what)
	}
	var head string
	if errors.Is(f.tooLarge, errReserve) {
		head = fmt.Sprintf("not published: %v, which is kept for cluster rule set changes, such as a CRS upgrade; namespaces' changes "+
			"may not grow the bundle into it. ", f.tooLarge)
	} else {
		head = fmt.Sprintf("not published: the bundle with every change is too large (%v). ", f.tooLarge)
	}
	if kept {
		return head + fmt.Sprintf("Even with every change held back it doesn't fit, so the bundle in force is published again "+
			"with deletions only, and %s is held. Shrink the largest namespaces' policies or rule sets", what)
	}
	head += "Changes are held back namespace by namespace until it fits, the namespace with the largest share of the bundle first, " +
		"and cluster rule sets after every namespace; "
	if g.namespace == "" {
		return head + fmt.Sprintf("even with every namespace's changes held it doesn't fit, or a namespace whose change fits alone "+
			"has a published policy that doesn't compile with it as it is now (the messages of that namespace's objects say so): "+
			"it then waits one build, while that namespace's change is published, so %s is held. Shrink the largest namespaces' "+
			"policies or rule sets", what)
	}
	gz := fmt.Sprintf("%d", g.gz)
	if !g.gzKnown {
		gz = fmt.Sprintf("up to about %d (not measured)", g.raw)
	}
	last := ""
	waitsWith := " Holding it leaves a policy of its that the bundle in force has, whose previous version doesn't compile with a " +
		"cluster rule set as it is now, in the bundle: that cluster rule set's change waits with it, one build at most."
	leftNext := " If its change doesn't fit next build, when that change no longer waits, that policy is left out: ship a smaller " +
		"change (the fix apart from a larger rewrite), or ask the cluster admin for room."
	switch {
	case g.protected:
		last = waitsWith + fmt.Sprintf(" Next build it is released before the other namespaces' changes again, with the namespaces "+
			"this wait holds likewise, which share %d%% of a limit of the reserve.", adoptionCap) + leftNext
	case g.guarded:
		last = waitsWith + fmt.Sprintf(" Its change grows its share by more than %d%% of a limit, more than adopting that change "+
			"takes, so it isn't released before the other namespaces' changes and may not grow the bundle into the reserve.", adoptionCap) +
			leftNext
	case g.last:
		last = fmt.Sprintf(" A policy of its that the bundle in force has, whose previous version doesn't compile with a cluster rule "+
			"set as it is now, is left out: its change doesn't fit even alone on the bundle in force with that cluster rule set's "+
			"change, or that change waited a build for it already, and the namespaces whose change adopts it took the room, the "+
			"smallest first, or its change grows its share by more than %d%% of a limit and the room left doesn't take it.", adoptionCap)
	case waits:
		last = " A namespace whose published policy doesn't compile with a cluster rule set's change is held in this build, and " +
			"that change waits for it: until it is released, the other namespaces' changes wait too, two builds at most."
	case first:
		last = fmt.Sprintf(" The namespaces whose change adopts a cluster rule set's change (their published policy doesn't compile "+
			"with it as it is now, and their change grows their share by at most %d%% of a limit) are released before the others, "+
			"whatever their share, and the room they leave doesn't take this change.", adoptionCap)
	}
	return head + fmt.Sprintf("namespace %s's content takes %s bytes of the bundle compressed and %d raw, and the bundle "+
		"with its changes released doesn't fit, so %s is held.%s Shrink the namespace's policies or rule sets", g.namespace, gz, g.raw, what, last)
}

// hold resolves with the groups' units held.
func (f *fitter) hold(groups []*holdGroup, kept bool) fitted {
	h := fitted{held: map[types.NamespacedName]string{}, heldRuleSets: map[string]string{}, tooLarge: f.tooLarge, kept: kept}
	waits := slices.ContainsFunc(groups, func(g *holdGroup) bool { return g.protected })
	first := slices.ContainsFunc(f.groups, func(g *holdGroup) bool { return g.prior && !slices.Contains(groups, g) })
	for _, g := range groups {
		for _, u := range g.units {
			if u.ruleSet != "" {
				h.heldRuleSets[u.ruleSet] = f.message(g, u, kept, waits, first && !g.prior)
			} else {
				h.held[u.policy] = f.message(g, u, kept, waits, first && !g.prior)
			}
		}
	}
	in := f.in
	in.Hold, in.HoldRuleSets = h.held, h.heldRuleSets
	h.res = resolver.Resolve(in)
	return h
}

// leftOut are the namespaces of the policies that both the bundle in
// force and the bundle with every change have, and res leaves out.
func (f *fitter) leftOut(res resolver.Result) map[string]bool {
	if len(f.published) == 0 {
		return nil
	}
	in := map[string]bool{}
	for _, p := range res.Policies {
		in[p.GetId()] = true
	}
	out := map[string]bool{}
	for id, ns := range f.published {
		if !in[id] {
			out[ns] = true
		}
	}
	return out
}

// resolve resolves with the groups' units held, and builds the bundle
// (kept: with the settings of the bundle in force).
func (f *fitter) resolve(groups []*holdGroup, kept bool) (fitted, error) {
	f.tries++
	h := f.hold(groups, kept)
	build := f.build
	if kept {
		build = f.keep
	}
	var err error
	h.next, h.changed, err = build(h.res)
	return h, err
}

// try resolves and builds with the groups' units held, and reports
// whether the bundle fits. Outside the last resort (kept), it doesn't when
// it holds a protected namespace and releases another namespace's change
// (the protected ones are released first), or when it leaves out a policy
// the bundle in force has, unless the policy's namespace is held over its
// share, or is last and not guarded; and it must fit the reserve.
func (f *fitter) try(groups []*holdGroup, kept bool) (fitted, bool, error) {
	if !kept && slices.ContainsFunc(groups, func(g *holdGroup) bool { return g.protected }) {
		for _, g := range f.groups {
			if !g.protected && !slices.Contains(groups, g) {
				f.tries++
				return fitted{tooLarge: f.tooLarge}, false, nil
			}
		}
	}
	h, err := f.resolve(groups, kept)
	if err != nil {
		return h, false, err
	}
	if kept {
		if !h.changed {
			return h, true, nil
		}
		s, err := f.measure(h.next)
		if err != nil || s.err != nil {
			h.tooLarge = cmp.Or(s.err, h.tooLarge)
			return h, false, err
		}
		return h, true, nil
	}
	allowed := map[string]bool{}
	for _, g := range groups {
		if g.budget != "" || g.last && !g.guarded {
			allowed[g.namespace] = true
		}
	}
	for ns := range f.leftOut(h.res) {
		if !allowed[ns] {
			return h, false, nil
		}
	}
	ok, err := f.fits(&h, groups)
	return h, ok, err
}

// fits reports whether h, resolved with the groups' units held, fits its
// limits and the reserve, measured with the published policies it leaves
// out counted; and, if it leaves one out, as it is published. A try that
// holds the cluster rule sets' changes and releases a guarded namespace
// (they wait for it) is measured with those changes too, as they are now:
// what is published against them as they were leaves them the room they
// take in the next build.
func (f *fitter) fits(h *fitted, groups []*holdGroup) (bool, error) {
	if !h.changed {
		// Unchanged: the bundle in force, which fits.
		return true, nil
	}
	counted := f.cluster != nil && slices.Contains(groups, f.cluster) &&
		slices.ContainsFunc(f.groups, func(g *holdGroup) bool { return g.guarded && !slices.Contains(groups, g) })
	s, added, err := f.size(h, counted)
	if err != nil {
		return false, err
	}
	if s.err != nil {
		h.tooLarge = s.err
		return false, nil
	}
	if f.inReserve(s) {
		if ok, err := f.reserveFits(s, groups, counted); err != nil || !ok {
			h.tooLarge = f.reserveErr(s)
			return false, err
		}
	}
	if added || counted {
		// What is published must fit as it is, too: gzip isn't monotone,
		// and taking content out can grow the bundle compressed.
		if s, err = f.measure(h.next); err != nil || s.err != nil {
			h.tooLarge = s.err
			return false, err
		}
	}
	return true, nil
}

// size measures h's bundle with the published policies it leaves out
// counted, and, if counted, with the cluster rule sets' changes as they
// are now. added: it leaves one out.
func (f *fitter) size(h *fitted, counted bool) (sizes, bool, error) {
	added, restore := f.accounted(h.res, h.next)
	defer restore()
	if counted {
		defer f.withCluster(h.next)()
	}
	s, err := f.measure(h.next)
	return s, added, err
}

// withCluster puts in b the cluster rule sets' changes, as they are now,
// in place of the versions it ships, until restore is called.
func (f *fitter) withCluster(b *bundlev1.Bundle) (restore func()) {
	changed := map[string]bool{}
	for _, u := range f.cluster.units {
		changed[u.ruleSet] = true
	}
	now := map[string]*bundlev1.RuleSet{}
	for _, rs := range f.next.GetRuleSets() {
		if changed[rs.GetId()] {
			now[rs.GetId()] = rs
		}
	}
	ruleSets := b.RuleSets
	b.RuleSets = slices.Clone(ruleSets)
	for i, rs := range b.RuleSets {
		if n := now[rs.GetId()]; n != nil {
			b.RuleSets[i] = n
		}
	}
	return func() { b.RuleSets = ruleSets }
}

// reserveFits reports whether the bundle of a try that holds groups
// (counted: measured with the cluster rule sets' changes), of sizes s, fits
// the reserve though it leaves less than the reserve free: it is no larger
// than its base, so that only the cluster rule sets' and the prior
// namespaces' changes grow it into the reserve; and if it releases a prior
// namespace's change, it is larger than the same try with every
// namespace's change held, or than the reserve line, whichever is larger,
// by at most adoptRaw and adoptGz, so that the prior namespaces' changes
// take at most that much of the reserve together.
func (f *fitter) reserveFits(s sizes, groups []*holdGroup, counted bool) (bool, error) {
	base, self, err := f.base(groups, counted)
	if err != nil || !self && !s.within(base) {
		return false, err
	}
	if !slices.ContainsFunc(f.groups, func(g *holdGroup) bool { return f.reserves(g) && !slices.Contains(groups, g) }) {
		return true, nil // its base holds every namespace's change
	}
	held := slices.Clone(f.groups)
	if f.cluster != nil && !counted && slices.Contains(groups, f.cluster) {
		held = append(held, f.cluster)
	}
	none, err := f.baseOf(held)
	return err == nil && f.adopts(s, none, f.adoptRaw, f.adoptGz), err
}

// reserves reports whether g's change may take part of the reserve: g is
// prior, and, in a due build that carries namespaces, carried.
func (f *fitter) reserves(g *holdGroup) bool { return g.prior && (!f.carrying || g.carried) }

// adopts reports whether a bundle of sizes s, which fits the limits, is
// larger than none, the same try with every namespace's change held, or
// than the reserve line, whichever is larger, by at most adoptRaw and
// adoptGz, the prior namespaces' part of the reserve. none may be over a
// limit: s is then no larger than it, so far.
func (f *fitter) adopts(s, none sizes, adoptRaw, adoptGz int) bool {
	return s.err == nil && s.gzKnown && none.gzKnown &&
		s.raw <= max(f.lim.raw-f.reserveRaw, none.raw)+adoptRaw && s.gz <= max(f.lim.gz-f.reserveGz, none.gz)+adoptGz
}

// base is the reserve's base of a try that holds groups (counted: measured
// with the cluster rule sets' changes): the same try with every namespace's
// change held but the prior namespaces' it releases, measured as a try is,
// so that namespaces' changes may not grow the bundle into the reserve,
// and the cluster rule sets' and the prior namespaces' may (reserveFits).
// self: the try holds every other namespace's change already, so it is its
// own base.
func (f *fitter) base(groups []*holdGroup, counted bool) (sizes, bool, error) {
	held := slices.Clone(groups)
	self := true
	for _, g := range f.groups {
		if !f.reserves(g) && !slices.Contains(groups, g) {
			held, self = append(held, g), false
		}
	}
	if self {
		return sizes{}, true, nil
	}
	if counted {
		// Released: what it then leaves out is counted, as it was.
		held = slices.DeleteFunc(held, func(g *holdGroup) bool { return g == f.cluster })
	}
	s, err := f.baseOf(held)
	return s, false, err
}

// baseOf measures the try that holds the groups held as a try is, without
// the cluster rule sets' changes it holds, once per set of groups.
func (f *fitter) baseOf(held []*holdGroup) (sizes, error) {
	names := make([]string, 0, len(held))
	for _, g := range held {
		names = append(names, g.namespace)
	}
	slices.Sort(names)
	key := strings.Join(names, "/")
	if s, ok := f.bases[key]; ok {
		return s, nil
	}
	h, err := f.resolve(held, false)
	if err != nil {
		return sizes{}, err
	}
	s, _, err := f.size(&h, false)
	if err != nil {
		return sizes{}, err
	}
	if f.bases == nil {
		f.bases = map[string]sizes{}
	}
	f.bases[key] = s
	return s, nil
}

// accounted adds to next, the bundle of res, the published policies res
// leaves out, as they are in the bundle in force, with the rule sets they
// bind that next doesn't have, until restore is called:
// a try is measured with them, so that leaving out a policy frees no room
// for anyone. added: res leaves one out.
func (f *fitter) accounted(res resolver.Result, next *bundlev1.Bundle) (added bool, restore func()) {
	in := map[string]bool{}
	for _, p := range res.Policies {
		in[p.GetId()] = true
	}
	var back []*bundlev1.Policy
	var versions []uint64
	prevVersions := f.in.Previous.GetPolicyVersions()
	for i, p := range f.in.Previous.GetPolicies() {
		if _, pub := f.published[p.GetId()]; pub && !in[p.GetId()] {
			back = append(back, p)
			if i < len(prevVersions) {
				versions = append(versions, prevVersions[i])
			}
		}
	}
	if len(back) == 0 {
		return false, func() {}
	}
	policies, ruleSets, pv := next.Policies, next.RuleSets, next.PolicyVersions
	have := map[string]bool{}
	for _, rs := range ruleSets {
		have[rs.GetId()] = true
	}
	wasRuleSets := map[string]*bundlev1.RuleSet{}
	for _, rs := range f.in.Previous.GetRuleSets() {
		wasRuleSets[rs.GetId()] = rs
	}
	addRuleSets := slices.Clone(ruleSets)
	for _, p := range back {
		for _, b := range p.GetRuleSets() {
			if id := b.GetRuleSetId(); !have[id] && wasRuleSets[id] != nil {
				have[id] = true
				addRuleSets = append(addRuleSets, wasRuleSets[id])
			}
		}
	}
	// In id order, as the bundle has them.
	addPolicies := append(slices.Clone(policies), back...)
	slices.SortFunc(addPolicies, func(a, b *bundlev1.Policy) int { return cmp.Compare(a.GetId(), b.GetId()) })
	slices.SortFunc(addRuleSets, func(a, b *bundlev1.RuleSet) int { return cmp.Compare(a.GetId(), b.GetId()) })
	next.Policies, next.RuleSets = addPolicies, addRuleSets
	next.PolicyVersions = append(slices.Clone(pv), versions...)
	return true, func() {
		next.Policies, next.RuleSets, next.PolicyVersions = policies, ruleSets, pv
	}
}

// order is the order groups within their budget are held in: the largest
// share first, ties to the namespace whose oldest object was created last,
// then to its name; then the prior namespaces, released before the others,
// the carried ones last (released first), the largest growth first
// (holdGroup.growth), then by share; the cluster rule sets last.
func (f *fitter) order() []*holdGroup {
	var order []*holdGroup
	for _, g := range f.groups {
		if g.budget == "" {
			order = append(order, g)
		}
	}
	slices.SortFunc(order, func(a, b *holdGroup) int {
		return cmp.Or(compareBool(a.prior, b.prior), compareBool(a.carried, b.carried), comparePrior(f.lim, a, b),
			cmp.Compare(b.rank(f.lim), a.rank(f.lim)), b.created.Compare(a.created), cmp.Compare(a.namespace, b.namespace))
	})
	if f.cluster != nil {
		order = append(order, f.cluster)
	}
	return order
}

// search holds, on top of budget, the shortest prefix of the order with
// which the bundle fits, then releases what it can.
func (f *fitter) search(budget []*holdGroup) (fitted, bool, error) {
	// The order needs every compressed share the cap allows.
	if err := f.gzShares(func(g *holdGroup) bool { return g.budget == "" }); err != nil {
		return fitted{}, false, err
	}
	order := f.order()
	released := map[*holdGroup]bool{}
	held := func(k int) []*holdGroup {
		out := slices.Clone(budget)
		for _, g := range order[:k] {
			if !released[g] {
				out = append(out, g)
			}
		}
		return out
	}
	var best fitted
	ok := false
	if len(order) > 0 {
		var err error
		if best, ok, err = f.try(held(len(order)), false); err != nil {
			return fitted{}, false, err
		}
	}
	if !ok {
		// The last resort.
		h, ok, err := f.try(held(len(order)), true)
		if err == nil && !ok && f.tooLarge != nil {
			h.tooLarge = f.tooLarge
		}
		return h, ok, err
	}
	// held(lo) doesn't fit (lo = 0 is what fit tried), held(hi) does.
	lo, hi := 0, len(order)
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		h, ok, err := f.try(held(mid), false)
		if err != nil {
			return fitted{}, false, err
		}
		if ok {
			best, hi = h, mid
		} else {
			lo = mid
		}
	}
	// Release what fits, from the end of the prefix, until a pass releases
	// nothing: the order isn't monotone, so a release can make room for one
	// tried before. A group is tried again only after a release since its
	// last try (releases counts them); releasing order[hi-1] alone is
	// held(hi-1), which didn't fit. The cap bounds the tries, encoded or
	// not; when it comes first, repair releases the prior namespaces that
	// it would leave out untried.
	bestHeld := held(hi)
	releases, failed := 0, map[*holdGroup]int{order[hi-1]: 0}
	tried := func(g *holdGroup) bool { at, ok := failed[g]; return ok && at == releases }
	for more := true; more; {
		more = false
		for i := hi - 1; i >= 0; i-- {
			g := order[i]
			if released[g] || tried(g) {
				continue
			}
			if f.encodes >= f.maxEncodes || f.tries >= 4*f.maxEncodes {
				f.capped = true
				return f.repair(best, bestHeld, tried)
			}
			released[g] = true
			try := held(hi)
			h, ok, err := f.try(try, false)
			if err != nil {
				return fitted{}, false, err
			}
			if ok {
				best, bestHeld, more = h, try, true
				releases++
			} else {
				delete(released, g)
				failed[g] = releases
			}
		}
	}
	return best, true, nil
}

// repair keeps the encode cap from leaving out a published policy within
// its budget: best, which holds bestHeld, is what the search found when the
// cap came, and tried reports whether a group's release was tried since
// the last release. The last namespaces within their budget whose change
// fits alone, held in best and not tried, are those whose policy the cap
// would leave out (in a due build), or that the cluster rule sets' changes
// would wait for untried (they are guarded). Repair tries, past the cap,
// releasing all of them with the other releases kept; then with the other
// namespaces' changes held too, but the last ones' (they wait a build:
// held, not left out), and with the held last namespaces the search tried
// too; then the most of them, in the order's release order
// (the prior ones first, the smallest growth first), that fit with those
// held (a binary search); then each one still held once, released from
// what is then to be published. So such a namespace is held, or its policy
// left out, only by a try that released it and didn't fit. That costs at most log2(n) + 3
// tries for n of them, and then at most maxEncodes encodes more (a try
// encodes at most three bundles: its base, as measured and as published),
// only in a build with a cluster rule set's change and when the cap came
// first; the namespaces those encodes leave untried stay held.
func (f *fitter) repair(best fitted, bestHeld []*holdGroup, tried func(*holdGroup) bool) (fitted, bool, error) {
	var todo, all []*holdGroup
	for _, g := range slices.Backward(f.order()) {
		if g.last && g.budget == "" && g.fits && slices.Contains(bestHeld, g) {
			all = append(all, g)
			if !tried(g) {
				todo = append(todo, g)
			}
		}
	}
	if len(todo) == 0 {
		return best, true, nil
	}
	f.repaired = true
	release := func(held []*holdGroup, n int) []*holdGroup {
		return slices.DeleteFunc(slices.Clone(held), func(g *holdGroup) bool { return slices.Contains(todo[:n], g) })
	}
	h, ok, err := f.try(release(bestHeld, len(todo)), false)
	if err != nil || ok {
		return h, ok, err
	}
	wait := slices.Clone(bestHeld)
	for _, g := range f.groups {
		if !g.last && !slices.Contains(wait, g) {
			wait = append(wait, g)
		}
	}
	// With the others held, those the search tried, with them released,
	// are worth trying again too.
	todo = all
	if h, ok, err = f.try(release(wait, len(todo)), false); err != nil || ok {
		return h, ok, err
	}
	// release(wait, lo) fits (lo = 0 holds more than best: best stands
	// for it), release(wait, hi) doesn't.
	lo, hi := 0, len(todo)
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		h, ok, err := f.try(release(wait, mid), false)
		if err != nil {
			return fitted{}, false, err
		}
		if ok {
			best, bestHeld, lo = h, release(wait, mid), mid
		} else {
			hi = mid
		}
	}
	// The binary search tried todo[lo] after todo[:lo] only, none after
	// it, and with the other namespaces' changes held, which can grow the
	// bundle (a change that shrinks it): try each one still held once, in
	// that order, released from what best publishes, keeping a release
	// that fits, until maxEncodes more encodes are spent (maxEncodes + 2 at
	// most, since a try encodes up to 3; the constant: a test's smaller cap
	// doesn't shrink it). todo[lo] was, if lo > 0.
	start := f.encodes
	for i, g := range todo {
		if !slices.Contains(bestHeld, g) || i == lo && lo > 0 {
			continue
		}
		if f.encodes-start >= maxEncodes {
			break
		}
		try := slices.DeleteFunc(slices.Clone(bestHeld), func(o *holdGroup) bool { return o == g })
		h, ok, err := f.try(try, false)
		if err != nil {
			return fitted{}, false, err
		}
		if ok {
			best, bestHeld = h, try
		}
	}
	return best, true, nil
}

// findDue marks the cluster rule sets' changes due when one of them waited
// a build already (fitParams.waited) as it is now: none waits again for a
// last namespace.
func (f *fitter) findDue() {
	if f.cluster == nil || len(f.params.waited) == 0 {
		return
	}
	now := map[string]*bundlev1.RuleSet{}
	for _, rs := range f.next.GetRuleSets() {
		now[rs.GetId()] = rs
	}
	for _, u := range f.cluster.units {
		if w := f.params.waited[u.ruleSet]; w != nil && proto.Equal(w, now[u.ruleSet]) {
			f.due = true
		}
	}
}

// findLast marks the namespaces whose holding leaves out a policy the
// bundle in force has: its previous version, with its namespace's rule
// sets as they were, doesn't compile with a cluster rule set it binds as
// it is now. Holding a namespace ships its rule sets as they were, and a
// policy binds only its own namespace's.
func (f *fitter) findLast() {
	if len(f.published) == 0 || len(f.groups) == 0 || f.cluster == nil || f.in.CheckPolicy == nil {
		return
	}
	now, was := map[string]*bundlev1.RuleSet{}, map[string]*bundlev1.RuleSet{}
	for _, rs := range f.next.GetRuleSets() {
		now[rs.GetId()] = rs
	}
	for _, rs := range f.in.Previous.GetRuleSets() {
		was[rs.GetId()] = rs
	}
	group := map[string]*holdGroup{}
	for _, g := range f.groups {
		group[g.namespace] = g
	}
	for _, p := range f.in.Previous.GetPolicies() {
		g := group[namespaceOfID(p.GetId())]
		if _, pub := f.published[p.GetId()]; !pub || g == nil || g.last {
			continue
		}
		var bound []*bundlev1.RuleSet
		changed := false
		for _, b := range p.GetRuleSets() {
			id := b.GetRuleSetId()
			rs := was[id]
			if namespaceOfID(id) == "" && now[id] != nil {
				changed = changed || !proto.Equal(now[id], rs)
				rs = now[id]
			}
			if rs != nil {
				bound = append(bound, rs)
			}
		}
		g.last = changed && f.in.CheckPolicy(p, bound) != nil
	}
}

// comparePrior orders two prior groups by their growth, the largest first.
func comparePrior(l fitLimits, a, b *holdGroup) int {
	if !a.prior || !b.prior {
		return 0
	}
	return cmp.Compare(b.growth(l), a.growth(l))
}

// protect measures, once, whether the change of each last namespace within
// its budget fits alone, the smallest growth first, as estimated (within
// the cap, the changes likeliest to be an adoption are measured), and marks
// the prior, guarded and protected ones: guarded none once the cluster rule
// sets' changes waited a build (due).
func (f *fitter) protect() error {
	if f.protectedDone {
		return nil
	}
	f.protectedDone = true
	var lasts []*holdGroup
	for _, g := range f.groups {
		if g.last && g.budget == "" {
			now, err := gzAlone(f.next, g.namespace)
			if err != nil {
				return err
			}
			was, err := gzAlone(f.in.Previous, g.namespace)
			if err != nil {
				return err
			}
			g.fits, g.growRaw, g.estGz = true, g.raw-rawShare(f.in.Previous, g.namespace), now-was
			lasts = append(lasts, g)
		}
	}
	slices.SortStableFunc(lasts, func(a, b *holdGroup) int { return cmp.Compare(a.growth(f.lim), b.growth(f.lim)) })
	for _, g := range lasts {
		if err := f.alone(g); err != nil {
			return err
		}
	}
	capRaw, capGz := f.lim.part(adoptionCap)
	for _, g := range f.groups {
		gz := g.estGz
		if g.aloneKnown {
			gz = g.growGz
		}
		g.prior = g.last && g.budget == "" && g.fits && g.growRaw <= capRaw && gz <= capGz
		g.guarded = g.last && g.budget == "" && g.fits && !f.due
		g.protected = g.prior && g.guarded
		g.carried = g.prior && f.due && f.params.carried[g.namespace]
		f.carrying = f.carrying || g.carried
	}
	if f.carrying {
		// They were held in the wait while protected, so that the others'
		// changes took that build's part: they share one of their own.
		f.adoptRaw, f.adoptGz = f.partRaw, f.partGz
	}
	return nil
}

// alone measures whether g's change fits the limits alone: on the bundle
// in force with every other namespace's change held, and the cluster rule
// sets' changes, which it adopts, published (two encodes, within the cap,
// and once the bundle with every namespace's change held, for growGz; not
// measured, it fits). The reserve doesn't apply: adopting them may use it.
func (f *fitter) alone(g *holdGroup) error {
	need := 2 + f.reserve()
	if f.none == nil {
		need++
	}
	if f.encodes+need > f.maxEncodes {
		return nil
	}
	if f.none == nil {
		s, err := f.baseOf(f.groups)
		if err != nil {
			return err
		}
		f.none = &s
	}
	others := slices.DeleteFunc(slices.Clone(f.groups), func(o *holdGroup) bool { return o == g })
	h, err := f.resolve(others, false)
	if err != nil || !h.changed {
		return err
	}
	s, added, err := f.size(&h, false)
	if err != nil {
		return err
	}
	g.aloneKnown = true
	if s.err != nil {
		g.fits = false
		return nil
	}
	g.growGz = s.gz
	if f.none.gzKnown {
		g.growGz -= f.none.gz
	}
	if f.due && f.inReserve(s) {
		// Due, the reserve has no part left for it, but for a namespace
		// held in the wait while protected (carried).
		aRaw, aGz := 0, 0
		if f.params.carried[g.namespace] {
			aRaw, aGz = f.partRaw, f.partGz
		}
		if !f.adopts(s, *f.none, aRaw, aGz) {
			g.fits = false
			return nil
		}
	}
	if added {
		if s, err = f.measure(h.next); err != nil {
			return err
		}
		g.fits = s.err == nil
	}
	return nil
}

// overShares are the namespaces over their share (share%) of b, as
// published, at rest: each one's share of the limit it takes most of, in
// percent. A raw share is counted; a compressed one is measured for the
// namespaces whose raw share could be over the budget, the largest first,
// at most maxMeasured. A single tenant is over none.
func overShares(b *bundlev1.Bundle, signer *bundle.Signer, lim fitLimits, share int) (map[string]float64, error) {
	if b == nil || tenants(b) <= 1 {
		return nil, nil
	}
	// Measured on a copy: without changes the bundle it measures.
	b = proto.Clone(b).(*bundlev1.Bundle)
	f := &fitter{signer: signer, lim: lim, params: fitParams{share: share}, maxEncodes: maxEncodes}
	rawBudget, gzBudget := f.budgets()
	namespaces := map[string]bool{}
	for _, p := range b.GetPolicies() {
		namespaces[namespaceOfID(p.GetId())] = true
	}
	out := map[string]float64{}
	type candidate struct {
		ns  string
		raw int
	}
	var measure []candidate
	for ns := range namespaces {
		raw := rawShare(b, ns)
		if raw > rawBudget {
			out[ns] = 100 * float64(raw) / float64(lim.raw)
		}
		if lim.mayBeOverGz(raw, gzBudget) {
			measure = append(measure, candidate{ns, raw})
		}
	}
	if len(measure) == 0 {
		return out, nil
	}
	slices.SortFunc(measure, func(a, b candidate) int { return cmp.Or(cmp.Compare(b.raw, a.raw), cmp.Compare(a.ns, b.ns)) })
	all, err := f.measure(b)
	if err != nil || !all.gzKnown {
		return out, err
	}
	for _, c := range measure[:min(len(measure), maxMeasured)] {
		gz, ok, err := f.gzShare(b, all, c.ns)
		if err != nil {
			return nil, err
		}
		if ok && gz > gzBudget {
			out[c.ns] = max(out[c.ns], 100*float64(gz)/float64(lim.gz))
		}
	}
	return out, nil
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// heldCount is how many policies and rule sets f holds back, or leaves
// out because of what it holds (BundleTooLarge), with the cluster rule
// sets whose change ships as it was because every policy binding them is
// held.
func heldCount(f fitted) int {
	ruleSets := maps.Clone(f.heldRuleSets)
	for id, st := range f.res.RuleSetStatus {
		if st.Reason == resolver.ReasonBundleTooLarge {
			if ruleSets == nil {
				ruleSets = map[string]string{}
			}
			ruleSets[id] = st.Message
		}
	}
	n := len(ruleSets)
	for key, st := range f.res.PolicyStatus {
		if _, held := f.held[key]; held || st.Reason == resolver.ReasonBundleTooLarge {
			n++
		}
	}
	return n
}

// heldNames lists some of the policies and rule sets held back, for the
// log.
func heldNames(f fitted) []string {
	names := make([]string, 0, len(f.held)+len(f.heldRuleSets))
	for key := range f.held {
		names = append(names, key.String())
	}
	for id := range f.heldRuleSets {
		names = append(names, id)
	}
	slices.Sort(names)
	if len(names) > 10 {
		names = append(names[:10], fmt.Sprintf("and %d more", len(names)-10))
	}
	return names
}
