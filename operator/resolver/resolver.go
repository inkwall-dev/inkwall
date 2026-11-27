// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package resolver turns the cluster's WAF objects into bundle policies
// (0004 §4.5): each WAFPolicy's targets are expanded into concrete host /
// path matches, its rule sets resolved, and conflicts between policies
// settled. It is pure: the same objects always give the same result.
//
// A policy that can't be resolved (a missing rule set, rules that don't
// compile, a conflict) keeps the version it has in the previous bundle, so
// a bad edit never removes or weakens protection already in force; a policy
// that was never resolved is left out until it is fixed. Its Accepted
// condition says why.
package resolver

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/iplist"
	enginepolicy "github.com/inkwall-dev/inkwall/pkg/policy"
)

// RulesLabel must be set to "true" on a ConfigMap a rule set reads rules
// from: the operator only watches labeled ConfigMaps.
const RulesLabel = "waf.inkwall.dev/rules"

// Condition reasons for Accepted.
const (
	ReasonAccepted          = "Accepted"
	ReasonInvalidRef        = "InvalidRef"
	ReasonConflict          = "Conflict"
	ReasonRuleCompileError  = "RuleCompileError"
	ReasonTargetUnsupported = "TargetUnsupported"
	// ReasonTargetNotAttached: an HTTPRoute target no Gateway of an
	// integration accepted; the policy doesn't apply to it.
	ReasonTargetNotAttached = "TargetNotAttached"
	// ReasonRouteOverlap: a route of the policy overlaps a route of a
	// policy in another namespace that the engine can't tell apart from it.
	ReasonRouteOverlap = "RouteOverlap"
	// ReasonRuleSetsIncompatible: the policy's rule sets compile alone but
	// not together, as the engine loads them.
	ReasonRuleSetsIncompatible = "RuleSetsIncompatible"
	// ReasonInvalidSpec: the engine can't compile the policy's spec (a
	// value admission didn't refuse); in the bundle, it would make every
	// engine refuse the bundle.
	ReasonInvalidSpec = "InvalidSpec"
	// ReasonBundleTooLarge: the bundle with the policy as it is now
	// doesn't fit its Secrets, so the policy is held back (Input.Hold).
	ReasonBundleTooLarge = "BundleTooLarge"
)

// PolicyValid is the Accepted message of a policy that resolved with
// nothing to report.
const PolicyValid = "the policy is valid"

// Input is the cluster state to resolve.
type Input struct {
	Policies  []wafv1alpha1.WAFPolicy
	Ingresses []networkingv1.Ingress
	// IngressRoutes are Traefik's (traefik.io/v1alpha1); none when its
	// CRD isn't installed.
	IngressRoutes []unstructured.Unstructured
	// HTTPRoutes are Gateway API's; none when its CRDs aren't installed.
	HTTPRoutes []gatewayv1.HTTPRoute
	// VirtualServices are Istio's (networking.istio.io); none when its
	// CRD isn't installed.
	VirtualServices []unstructured.Unstructured
	RuleSets        []wafv1alpha1.WAFRuleSet
	ClusterRuleSets []wafv1alpha1.ClusterWAFRuleSet
	// IPLists are the WAFIPLists policies name in spec.ipLists.
	IPLists []wafv1alpha1.WAFIPList
	// ConfigMaps rule sets read rules from (labeled RulesLabel).
	ConfigMaps []corev1.ConfigMap
	// Previous is the bundle in force; nil when there is none.
	Previous *bundlev1.Bundle
	// CheckRules checks SecLang read from a ConfigMap
	// (coraza.CheckUserRules); inline rules were checked at admission.
	CheckRules func(string) error
	// AssumeAttached takes every HTTPRoute as accepted by its Gateways,
	// for objects read from files, which have no status.
	AssumeAttached bool
	// CheckPolicy compiles a policy with its rule sets as the engine does
	// (policy.CheckPolicy): rule sets valid alone may not be together
	// (duplicate rule IDs). Nil: not checked.
	CheckPolicy func(*bundlev1.Policy, []*bundlev1.RuleSet) error
	// Hold names the policies the bundle doesn't take as they are now,
	// with the message of their BundleTooLarge status: the bundle with
	// them doesn't fit its Secrets (the builder decides which). Each keeps
	// its previous version, as a policy that fails does, or is left out
	// if it has none.
	Hold map[types.NamespacedName]string
	// HoldRuleSets names, by id, the rule sets the bundle doesn't take as
	// they are now, with the message of their BundleTooLarge status: each
	// ships as it is in Previous, and the policies that bind it are checked
	// with that version. One Previous doesn't have isn't held.
	//
	// A held policy (Hold) whose previous version doesn't compile with the
	// rule sets of its namespace that changed holds them too: they ship as
	// they were. A ClusterWAFRuleSet is never held for a policy: when the
	// previous version doesn't compile with one that changed, the policy is
	// left out, and its status says so.
	HoldRuleSets map[string]string
}

// Status is a resolved Accepted condition.
type Status struct {
	Accepted bool
	Reason   string
	Message  string
	// Applied means the bundle enforces the policy as its spec is now:
	// not a previous version, and not left out.
	Applied bool
}

// Result is what goes into the bundle, and the status of each object.
type Result struct {
	// Policies sorted by id; RuleSets are the ones they use, sorted by id.
	Policies []*bundlev1.Policy
	RuleSets []*bundlev1.RuleSet
	// PolicyStatus is keyed by the WAFPolicy.
	PolicyStatus map[types.NamespacedName]Status
	// RuleSetStatus is keyed by RuleSet id (RuleSetID), for every rule set.
	RuleSetStatus map[string]Status
}

// PolicyID is a policy's id in the bundle.
func PolicyID(namespace, name string) string { return namespace + "/" + name }

// RuleSetID is a rule set's id in the bundle.
func RuleSetID(kind, namespace, name string) string {
	if kind == "ClusterWAFRuleSet" {
		return kind + "/" + name
	}
	return kind + "/" + namespace + "/" + name
}

// Resolve resolves in.
func Resolve(in Input) Result {
	r := &resolution{in: in, out: Result{
		PolicyStatus:  map[types.NamespacedName]Status{},
		RuleSetStatus: map[string]Status{},
	}}
	r.resolveRuleSets()
	r.resolvePolicies()
	return r.out
}

type resolution struct {
	in  Input
	out Result
	// ruleSets holds the rule sets that resolved, by id.
	ruleSets map[string]*bundlev1.RuleSet
	// heldRuleSets are the rule sets of Input.HoldRuleSets, and those a
	// held policy holds too, that ship as they were; heldNow are those
	// rule sets as they are now.
	heldRuleSets map[string]bool
	heldNow      map[string]*bundlev1.RuleSet
}

func (r *resolution) resolveRuleSets() {
	r.ruleSets = map[string]*bundlev1.RuleSet{}
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{}
	for i := range r.in.ConfigMaps {
		cm := &r.in.ConfigMaps[i]
		configMaps[types.NamespacedName{Namespace: cm.Namespace, Name: cm.Name}] = cm
	}
	add := func(id string, src wafv1alpha1.RuleSetSource, cmNamespace string) {
		rs, st := r.ruleSet(id, src, configMaps, cmNamespace)
		r.out.RuleSetStatus[id] = st
		if st.Accepted {
			r.ruleSets[id] = rs
		}
	}
	for _, rs := range r.in.RuleSets {
		add(RuleSetID("WAFRuleSet", rs.Namespace, rs.Name), rs.Spec.Source, rs.Namespace)
	}
	for _, rs := range r.in.ClusterRuleSets {
		src := wafv1alpha1.RuleSetSource{Builtin: rs.Spec.Source.Builtin, SecLang: rs.Spec.Source.SecLang}
		ns := ""
		if ref := rs.Spec.Source.ConfigMapRef; ref != nil {
			src.ConfigMapRef = &ref.ConfigMapKeyRef
			ns = ref.Namespace
		}
		add(RuleSetID("ClusterWAFRuleSet", "", rs.Name), src, ns)
	}
	// A held rule set ships as it is in the bundle in force.
	previous := map[string]*bundlev1.RuleSet{}
	for _, rs := range r.in.Previous.GetRuleSets() {
		previous[rs.GetId()] = rs
	}
	hold := func(id, msg string) {
		now, ok := r.ruleSets[id]
		if !ok || previous[id] == nil || proto.Equal(now, previous[id]) || r.heldRuleSets[id] {
			return
		}
		if r.heldRuleSets == nil {
			r.heldRuleSets, r.heldNow = map[string]bool{}, map[string]*bundlev1.RuleSet{}
		}
		r.heldRuleSets[id], r.heldNow[id] = true, now
		r.ruleSets[id] = previous[id]
		r.out.RuleSetStatus[id] = Status{Reason: ReasonBundleTooLarge, Message: msg + "; its previous version stays in force"}
	}
	for _, id := range slices.Sorted(maps.Keys(r.in.HoldRuleSets)) {
		hold(id, r.in.HoldRuleSets[id])
	}
	// A held policy's previous version that doesn't compile with the rule
	// sets as they are now holds those of its namespace that changed: a
	// WAFRuleSet is bound only from its own namespace. Never a cluster rule
	// set (resolvePolicies leaves such a policy out).
	if len(r.in.Hold) == 0 {
		return
	}
	policies := map[string]*bundlev1.Policy{}
	for _, p := range r.in.Previous.GetPolicies() {
		policies[p.GetId()] = p
	}
	keys := slices.SortedFunc(maps.Keys(r.in.Hold), func(a, b types.NamespacedName) int {
		return cmp.Compare(PolicyID(a.Namespace, a.Name), PolicyID(b.Namespace, b.Name))
	})
	for _, key := range keys {
		prev := policies[PolicyID(key.Namespace, key.Name)]
		var changed []string
		shipped := map[string]*bundlev1.RuleSet{}
		for _, b := range prev.GetRuleSets() {
			id := b.GetRuleSetId()
			now, old := r.ruleSets[id], previous[id]
			switch {
			case now == nil:
				if old != nil {
					shipped[id] = old
				}
			case old != nil && !proto.Equal(now, old) && strings.HasPrefix(id, "WAFRuleSet/"):
				changed = append(changed, id)
				shipped[id] = now
			default:
				shipped[id] = now
			}
		}
		if len(changed) == 0 {
			continue
		}
		if _, err := r.checkPolicy(prev, shipped); err != nil {
			for _, id := range changed {
				hold(id, fmt.Sprintf("not published: WAFPolicy %s is held back (BundleTooLarge) and its previous version, "+
					"which stays in force, doesn't compile with this rule set as it is now", prev.GetId()))
			}
		}
	}
}

func (r *resolution) ruleSet(id string, src wafv1alpha1.RuleSetSource, configMaps map[types.NamespacedName]*corev1.ConfigMap, cmNamespace string) (*bundlev1.RuleSet, Status) {
	out := &bundlev1.RuleSet{Id: id}
	switch {
	case src.Builtin == wafv1alpha1.BuiltinCRSv4:
		out.Source = &bundlev1.RuleSet_Builtin{Builtin: bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4}
	case src.Builtin != "":
		return nil, Status{Reason: ReasonInvalidRef, Message: fmt.Sprintf("unknown built-in rule set %q", src.Builtin)}
	case src.SecLang != "":
		out.Source = &bundlev1.RuleSet_Seclang{Seclang: src.SecLang}
	case src.ConfigMapRef != nil:
		key := types.NamespacedName{Namespace: cmNamespace, Name: src.ConfigMapRef.Name}
		cm, ok := configMaps[key]
		if !ok {
			return nil, Status{Reason: ReasonInvalidRef, Message: fmt.Sprintf(
				"ConfigMap %s not found, or not labeled %s=true", key, RulesLabel)}
		}
		rules, ok := cm.Data[src.ConfigMapRef.Key]
		if !ok {
			return nil, Status{Reason: ReasonInvalidRef, Message: fmt.Sprintf("ConfigMap %s has no key %q", key, src.ConfigMapRef.Key)}
		}
		if r.in.CheckRules != nil {
			if err := r.in.CheckRules(rules); err != nil {
				return nil, Status{Reason: ReasonRuleCompileError, Message: fmt.Sprintf("ConfigMap %s key %q: %v", key, src.ConfigMapRef.Key, err)}
			}
		}
		out.Source = &bundlev1.RuleSet_Seclang{Seclang: rules}
	default:
		return nil, Status{Reason: ReasonInvalidRef, Message: "the rule set has no source"}
	}
	return out, Status{Accepted: true, Reason: ReasonAccepted, Message: "the rule set is valid"}
}

// Target precedence (0002 §4.2): a route of several policies goes to the
// one with the most specific target, then to the older one.
const (
	rankIngress       = iota // an Ingress, an IngressRoute or a VirtualService
	rankHTTPRoute            // a whole HTTPRoute
	rankHTTPRouteRule        // one rule of an HTTPRoute (sectionName)
)

// candidate is a policy being resolved.
type candidate struct {
	obj    *wafv1alpha1.WAFPolicy
	key    types.NamespacedName
	policy *bundlev1.Policy
	status Status
	// failed means the policy falls back to its previous version.
	failed bool
	// held means the bundle doesn't take the policy as it is now
	// (Input.Hold): it is failed too.
	held bool
	// rank is the precedence of each route (by routeKey), from its most
	// specific target.
	rank map[string]int
	// domains are the domains of each route (by routeKey): see overlap.go.
	domains map[string]map[string]bool
	// overlaps describe the routes the policy shares with policies of
	// other namespaces; lost is set when one of them applies instead.
	overlaps []string
	lost     bool
}

// addRoutes adds routes from a target of the given precedence, routed in
// the given domains.
func (c *candidate) addRoutes(rank int, routes []*bundlev1.RouteMatch, domains ...string) {
	c.policy.Routes = append(c.policy.Routes, routes...)
	for _, m := range routes {
		k := routeKey(m)
		c.rank[k] = max(c.rank[k], rank)
		if c.domains[k] == nil {
			c.domains[k] = map[string]bool{}
		}
		for _, d := range domains {
			c.domains[k][d] = true
		}
	}
}

func (r *resolution) resolvePolicies() {
	ingresses := map[types.NamespacedName]*networkingv1.Ingress{}
	for i := range r.in.Ingresses {
		ing := &r.in.Ingresses[i]
		ingresses[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}] = ing
	}
	ingressRoutes := map[types.NamespacedName]*unstructured.Unstructured{}
	for i := range r.in.IngressRoutes {
		ir := &r.in.IngressRoutes[i]
		ingressRoutes[types.NamespacedName{Namespace: ir.GetNamespace(), Name: ir.GetName()}] = ir
	}
	httpRoutes := map[types.NamespacedName]*gatewayv1.HTTPRoute{}
	for i := range r.in.HTTPRoutes {
		hr := &r.in.HTTPRoutes[i]
		httpRoutes[types.NamespacedName{Namespace: hr.Namespace, Name: hr.Name}] = hr
	}

	virtualServices := map[types.NamespacedName]*unstructured.Unstructured{}
	for i := range r.in.VirtualServices {
		vs := &r.in.VirtualServices[i]
		virtualServices[types.NamespacedName{Namespace: vs.GetNamespace(), Name: vs.GetName()}] = vs
	}

	// Oldest first: on a conflict the older policy wins, as in Gateway API,
	// so a new policy can't take protection away from a route.
	policies := slices.Clone(r.in.Policies)
	slices.SortFunc(policies, func(a, b wafv1alpha1.WAFPolicy) int {
		if c := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}
		return cmp.Compare(PolicyID(a.Namespace, a.Name), PolicyID(b.Namespace, b.Name))
	})

	var cands []*candidate
	owner := map[string]*candidate{} // target -> the policy that has it
	for i := range policies {
		c := r.candidate(&policies[i], ingresses, ingressRoutes, httpRoutes, virtualServices)
		for _, t := range c.obj.Spec.TargetRefs {
			k := targetKey(c.key.Namespace, t)
			if prev, ok := owner[k]; ok {
				target := t.Kind + " " + t.Name
				if t.SectionName != "" {
					target = fmt.Sprintf("rule %s of %s", t.SectionName, target)
				}
				c.fail(ReasonConflict, fmt.Sprintf("%s is also targeted by the older WAFPolicy %s, which applies to it",
					target, prev.key.Name))
				continue
			}
			owner[k] = c
		}
		cands = append(cands, c)
	}

	previous := map[string]*bundlev1.Policy{}
	previousRuleSets := map[string]*bundlev1.RuleSet{}
	if p := r.in.Previous; p != nil {
		for _, pol := range p.GetPolicies() {
			previous[pol.GetId()] = pol
		}
		for _, rs := range p.GetRuleSets() {
			previousRuleSets[rs.GetId()] = rs
		}
	}

	// The policy each candidate puts in the bundle: its spec, or its
	// previous version; nil: left out. A policy the engine can't compile
	// (its rule sets together, or any of its settings) is left out too (or
	// keeps its previous version, if that compiles): in the bundle, it
	// would make every engine refuse the bundle, for every policy.
	pols := make([]*bundlev1.Policy, len(cands))
	for i, c := range cands {
		pols[i] = c.policy
		if msg, held := r.in.Hold[c.key]; held && !c.failed {
			c.fail(ReasonBundleTooLarge, msg)
			c.held = true
		}
		if !c.failed {
			if reason, err := r.checkPolicy(c.policy, r.ruleSets); err != nil {
				c.fail(reason, err.Error())
			}
		}
		if c.failed {
			prev, ok := previous[c.policy.GetId()]
			if !ok {
				if c.held {
					c.status.Message += "; it has no previous version, so it is left out until the bundle fits"
				}
				pols[i] = nil
				continue
			}
			if _, err := r.checkPolicy(prev, previousRuleSets); err != nil {
				c.status.Message += "; its previous version doesn't compile either, so the policy is left out"
				pols[i] = nil
				continue
			}
			c.status.Message += keptPrevious
			pols[i] = proto.Clone(prev).(*bundlev1.Policy)
		}
	}
	// The bundle has one version of each rule set: a policy that resolved
	// ships with the current one. A previous version kept that binds a rule
	// set that changed since, and that such a policy binds too, would ship
	// with the new rules it wasn't checked with: it is left out. A held
	// policy's previous version ships with them if it compiles with them,
	// as a policy that didn't change does: holding back one policy must not
	// take its protection away because others use a rule set it binds. If
	// it doesn't, it is left out (Input.HoldRuleSets).
	//
	// A policy that fails only because its namespace's rule set is held
	// (Input.HoldRuleSets) is held too, here. A changed ClusterWAFRuleSet
	// that isn't held ships as it is now even when every policy that binds
	// it is held: holding a policy never holds a cluster rule set.
	heldLike := func(c *candidate) bool {
		return c.held || c.failed && slices.ContainsFunc(c.policy.GetRuleSets(), func(b *bundlev1.RuleSetBinding) bool {
			return r.heldRuleSets[b.GetRuleSetId()]
		})
	}
	current := map[string]bool{}
	for i, c := range cands {
		if pols[i] == nil {
			continue
		}
		for _, b := range pols[i].GetRuleSets() {
			id := b.GetRuleSetId()
			if !c.failed || heldLike(c) && strings.HasPrefix(id, "ClusterWAFRuleSet/") && !r.heldRuleSets[id] &&
				r.ruleSets[id] != nil && previousRuleSets[id] != nil {
				current[id] = true
			}
		}
	}
	for i, c := range cands {
		if pols[i] == nil || !c.failed {
			continue
		}
		mixed := false
		for _, b := range pols[i].GetRuleSets() {
			id := b.GetRuleSetId()
			if !current[id] || proto.Equal(r.ruleSets[id], previousRuleSets[id]) {
				continue
			}
			if heldLike(c) {
				mixed = true
				continue
			}
			c.status.Message = strings.Replace(c.status.Message, keptPrevious, fmt.Sprintf(
				"; its previous version binds rule set %s, which changed since and which other policies use as it is now, so the policy is left out", id), 1)
			pols[i] = nil
			break
		}
		if !mixed {
			continue
		}
		shipped := map[string]*bundlev1.RuleSet{}
		for _, b := range pols[i].GetRuleSets() {
			id := b.GetRuleSetId()
			rs := previousRuleSets[id]
			if current[id] {
				rs = r.ruleSets[id]
			}
			if rs != nil {
				shipped[id] = rs
			}
		}
		if _, err := r.checkPolicy(pols[i], shipped); err != nil {
			// The rule sets of its namespace that changed are held with it
			// (resolveRuleSets), so a cluster rule set changed: it is never
			// held for one namespace's policy (Input.HoldRuleSets).
			var changed []string
			for _, b := range pols[i].GetRuleSets() {
				id := b.GetRuleSetId()
				if current[id] && previousRuleSets[id] != nil && !proto.Equal(r.ruleSets[id], previousRuleSets[id]) {
					kind, name, _ := strings.Cut(id, "/")
					changed = append(changed, kind+" "+name)
				}
			}
			names := strings.Join(changed, ", ")
			if names == "" {
				names = "the rule sets other policies use" // unreachable: one changed
			}
			c.status.Message = strings.Replace(c.status.Message, keptPrevious, fmt.Sprintf(
				"; and its previous version doesn't compile with %s as it is now, which changed since and which other policies use, "+
					"so the policy is left out until its change is published", names), 1)
			pols[i] = nil
		}
	}

	// A route of several policies (from routes with the same host and path)
	// goes to the most specific target, then to the older policy. A route
	// of a previous version that the spec doesn't give ranks as an Ingress.
	// Between namespaces, it goes to the older policy unless a newer one is
	// stricter (dominates): a tenant can't take a route from another
	// tenant's policy with a more specific target, nor weaken it.
	type claim struct {
		c    *candidate
		rank int
		i    int
	}
	routeOwner := map[string]claim{}
	for i, c := range cands {
		for _, m := range pols[i].GetRoutes() {
			k := routeKey(m)
			o, ok := routeOwner[k]
			switch {
			case !ok:
				routeOwner[k] = claim{c, c.rank[k], i}
			case o.c.key.Namespace != c.key.Namespace:
				if dominates(pols[i], pols[o.i]) {
					routeOwner[k] = claim{c, c.rank[k], i}
				}
			case c.rank[k] > o.rank:
				routeOwner[k] = claim{c, c.rank[k], i}
			}
		}
	}

	// Overlapping routes of different namespaces, not of the same key.
	removed := r.overlaps(cands, pols, func(i int, m *bundlev1.RouteMatch) bool { return routeOwner[routeKey(m)].i == i })

	used := map[string]*bundlev1.RuleSet{}
	shipped := map[string]*candidate{} // by policy ID
	for i, c := range cands {
		pol := pols[i]
		if pol == nil {
			continue
		}
		usedRuleSets := r.ruleSets
		if c.failed {
			usedRuleSets = previousRuleSets
		}
		var kept []*bundlev1.RouteMatch
		var shadowed []string
		seen := map[string]bool{}
		for _, m := range pol.GetRoutes() {
			k := routeKey(m)
			switch o := routeOwner[k]; {
			case o.c != c && o.c.key.Namespace != c.key.Namespace:
				if !seen[k] {
					seen[k] = true
					c.lost = true
					c.overlaps = append(c.overlaps, fmt.Sprintf("%s: WAFPolicy %s applies to it", describeRoute(m), o.c.policy.GetId()))
					o.c.overlaps = append(o.c.overlaps, fmt.Sprintf("%s: this policy applies to it, not WAFPolicy %s", describeRoute(m), c.policy.GetId()))
				}
			case o.c != c:
				why := "older policy"
				if o.rank > c.rank[k] {
					why = "policy on a more specific target"
				}
				shadowed = append(shadowed, fmt.Sprintf("%s (%s %s)", describeRoute(m), why, o.c.policy.GetId()))
			case removed[i][k]:
				seen[k] = true
			case !seen[k]:
				seen[k] = true
				kept = append(kept, m)
			}
		}
		pol.Routes = kept
		if len(shadowed) > 0 && !c.failed {
			c.status.Message = fmt.Sprintf("%s; routes covered by another policy, which applies to them: %s",
				c.status.Message, strings.Join(shadowed, ", "))
		}
		for _, b := range pol.GetRuleSets() {
			if id := b.GetRuleSetId(); r.heldRuleSets[id] && !c.failed {
				kind, rest, _ := strings.Cut(id, "/")
				c.status.Message = fmt.Sprintf("%s; %s %s is held back at its previous version (BundleTooLarge; see its status)",
					c.status.Message, kind, path.Base(rest))
			}
		}
		for _, b := range pol.GetRuleSets() {
			// A rule set a policy that resolved binds ships as it is now,
			// whatever the order of the policies, and so does a cluster rule
			// set a held policy binds (current).
			switch id := b.GetRuleSetId(); {
			case current[id]:
				used[id] = r.ruleSets[id]
			default:
				used[id] = usedRuleSets[id]
			}
		}
		c.status.Applied = !c.failed
		r.out.Policies = append(r.out.Policies, pol)
		shipped[pol.GetId()] = c
	}
	r.checkBundle(shipped, used)
	r.reportHeldOut(cands)
	r.reportShippedAsWas(cands, used, previous)
	// After every policy's routes: an overlap is reported on both.
	for _, c := range cands {
		c.reportOverlaps()
		r.out.PolicyStatus[c.key] = c.status
	}

	slices.SortFunc(r.out.Policies, func(a, b *bundlev1.Policy) int { return cmp.Compare(a.GetId(), b.GetId()) })
	for _, rs := range used {
		if rs != nil {
			r.out.RuleSets = append(r.out.RuleSets, rs)
		}
	}
	slices.SortFunc(r.out.RuleSets, func(a, b *bundlev1.RuleSet) int { return cmp.Compare(a.GetId(), b.GetId()) })
}

// checkBundle checks each policy of the bundle (r.out.Policies, shipped:
// their candidates by ID) with the rule sets it ships with (used, by ID),
// as the engine compiles the bundle, and leaves out those that don't
// compile, and the rule sets no policy left binds: whatever got them
// there, one would make every engine refuse the bundle. The rule sets
// don't change with the policies left out, so one pass is enough.
//
// It can't leave out a policy that resolved, whose rule sets ship as they
// are now, nor a previous version kept, whose rule sets ship as they were or
// it is left out: it guards against what would get there all the same.
// TODO: a policy it leaves out keeps the routes it took from others, which
// then go uninspected; route ownership would have to be decided again.
func (r *resolution) checkBundle(shipped map[string]*candidate, used map[string]*bundlev1.RuleSet) {
	kept := r.out.Policies[:0]
	for _, pol := range r.out.Policies {
		err := r.checkRules(pol, used)
		if err == nil {
			kept = append(kept, pol)
			continue
		}
		c := shipped[pol.GetId()]
		if c.failed {
			c.status.Message = strings.Replace(c.status.Message, keptPrevious,
				"; its previous version doesn't compile with the rule sets in the bundle either, so the policy is left out", 1)
		} else {
			c.fail(ReasonRuleSetsIncompatible, fmt.Sprintf("it doesn't compile with the rule sets in the bundle, so it is left out: %v", err))
			c.status.Applied = false
		}
	}
	r.out.Policies = kept
	bound := map[string]bool{}
	for _, pol := range kept {
		for _, b := range pol.GetRuleSets() {
			bound[b.GetRuleSetId()] = true
		}
	}
	for id := range used {
		if !bound[id] {
			delete(used, id)
		}
	}
}

// reportHeldOut gives BundleTooLarge, not RuleSetsIncompatible, to a
// policy left out because a rule set it binds is held (Input.HoldRuleSets):
// as it is now, it compiles with that rule set as it is now, but not as it
// was with the others as they are now. Holding left it out, not its rules.
func (r *resolution) reportHeldOut(cands []*candidate) {
	if len(r.heldRuleSets) == 0 {
		return
	}
	in := map[string]bool{}
	for _, p := range r.out.Policies {
		in[p.GetId()] = true
	}
	for _, c := range cands {
		if in[c.policy.GetId()] || c.status.Reason != ReasonRuleSetsIncompatible {
			continue
		}
		var held []string
		now := map[string]*bundlev1.RuleSet{}
		for _, b := range c.policy.GetRuleSets() {
			id := b.GetRuleSetId()
			now[id] = r.ruleSets[id]
			if r.heldRuleSets[id] {
				now[id] = r.heldNow[id]
				kind, name, _ := strings.Cut(id, "/")
				if kind == "WAFRuleSet" {
					_, name, _ = strings.Cut(name, "/")
				}
				held = append(held, kind+" "+name)
			}
		}
		if len(held) == 0 {
			continue
		}
		if _, err := r.checkPolicy(c.policy, now); err != nil {
			continue
		}
		c.status = Status{Reason: ReasonBundleTooLarge, Message: fmt.Sprintf(
			"not published: %s is held back at its previous version (BundleTooLarge; see its status), and the policy doesn't "+
				"compile with it as it was and the other rule sets as they are now, so it is left out until that change is "+
				"published (%s)", strings.Join(held, ", "), c.status.Message)}
	}
}

// reportShippedAsWas gives BundleTooLarge to a ClusterWAFRuleSet that
// changed but ships as it was (used, by ID), because every policy that
// binds it keeps its previous version, one held back (Input.Hold) at
// least: its change isn't published, so its status mustn't say Accepted.
func (r *resolution) reportShippedAsWas(cands []*candidate, used map[string]*bundlev1.RuleSet, previous map[string]*bundlev1.Policy) {
	if len(r.in.Hold) == 0 {
		return
	}
	was := map[string]*bundlev1.RuleSet{}
	for _, rs := range r.in.Previous.GetRuleSets() {
		was[rs.GetId()] = rs
	}
	binds := func(p *bundlev1.Policy, id string) bool {
		return slices.ContainsFunc(p.GetRuleSets(), func(b *bundlev1.RuleSetBinding) bool { return b.GetRuleSetId() == id })
	}
	for _, id := range slices.Sorted(maps.Keys(used)) {
		rs, now := used[id], r.ruleSets[id]
		if !strings.HasPrefix(id, "ClusterWAFRuleSet/") || r.heldRuleSets[id] || was[id] == nil || now == nil ||
			!proto.Equal(rs, was[id]) || proto.Equal(now, was[id]) {
			continue
		}
		var held []string
		for _, c := range cands {
			heldLike := c.held || c.failed && slices.ContainsFunc(c.policy.GetRuleSets(), func(b *bundlev1.RuleSetBinding) bool {
				return r.heldRuleSets[b.GetRuleSetId()]
			})
			if heldLike && (binds(c.policy, id) || binds(previous[c.policy.GetId()], id)) {
				held = append(held, "WAFPolicy "+c.policy.GetId())
			}
		}
		if len(held) == 0 {
			continue
		}
		slices.Sort(held)
		if len(held) > 3 {
			held = append(held[:3], fmt.Sprintf("%d more", len(held)-3))
		}
		r.out.RuleSetStatus[id] = Status{Reason: ReasonBundleTooLarge, Message: fmt.Sprintf(
			"not published: every policy that binds it keeps its previous version, and %s is held back (BundleTooLarge; see "+
				"its status), so it ships as it was until their change is published; its previous version stays in force",
			strings.Join(held, ", "))}
	}
}

// keptPrevious ends the message of a policy whose previous version stays.
const keptPrevious = "; the previous version of the policy stays in force"

// checkRules compiles a policy's rules with the rule sets it binds (from
// ruleSets), as checkPolicy does, but not its settings: those don't depend
// on the rule sets, and checkPolicy checked them.
func (r *resolution) checkRules(p *bundlev1.Policy, ruleSets map[string]*bundlev1.RuleSet) error {
	var bound []*bundlev1.RuleSet
	for _, b := range p.GetRuleSets() {
		if rs, ok := ruleSets[b.GetRuleSetId()]; ok {
			bound = append(bound, rs)
		}
	}
	if err := enginepolicy.CheckRuleSets(p, bound); err != nil {
		return err
	}
	if r.in.CheckPolicy == nil {
		return nil
	}
	return r.in.CheckPolicy(p, bound)
}

// reportOverlaps adds the routes the policy shares with policies of other
// namespaces to its status. A policy that doesn't apply to one of its
// routes is not Accepted; one that applies to them is, with
// ReasonRouteOverlap, so that both sides see the overlap.
func (c *candidate) reportOverlaps() {
	if len(c.overlaps) == 0 {
		return
	}
	slices.Sort(c.overlaps)
	msg := "routes that overlap routes of WAFPolicies in other namespaces, which the engine can't tell apart (a host served by two proxies or Gateways, or the same route): " +
		strings.Join(slices.Compact(c.overlaps), ", ")
	if c.failed {
		c.status.Message += "; " + msg
		return
	}
	if c.lost {
		c.status.Accepted = false
		c.status.Reason = ReasonRouteOverlap
	} else if c.status.Reason == ReasonAccepted {
		c.status.Reason = ReasonRouteOverlap
	}
	c.status.Message += "; " + msg
}

// checkPolicy compiles a policy with the rule sets it binds (from
// ruleSets), as the engine does: its settings always, its rules when
// Input.CheckPolicy is set. An error comes with its Accepted reason.
func (r *resolution) checkPolicy(p *bundlev1.Policy, ruleSets map[string]*bundlev1.RuleSet) (string, error) {
	var bound []*bundlev1.RuleSet
	for _, b := range p.GetRuleSets() {
		if rs, ok := ruleSets[b.GetRuleSetId()]; ok {
			bound = append(bound, rs)
		}
	}
	if err := enginepolicy.CheckSettings(p, bound); err != nil {
		return ReasonInvalidSpec, fmt.Errorf("the engine can't compile it: %w", err)
	}
	if r.in.CheckPolicy == nil {
		return "", nil
	}
	if err := r.in.CheckPolicy(p, bound); err != nil {
		return ReasonRuleSetsIncompatible, fmt.Errorf("its rule sets don't compile together: %w", err)
	}
	return "", nil
}

// overlaps settles the routes of different namespaces that overlap without
// being the same route (overlap.go): where the engine can't follow the
// proxy, the more specific route, which the engine picks, is left out
// unless its policy is the one the overlap goes to. owned reports whether
// a candidate's route is its own after the same-route precedence. It
// returns, by candidate, the route keys left out.
func (r *resolution) overlaps(cands []*candidate, pols []*bundlev1.Policy, owned func(int, *bundlev1.RouteMatch) bool) map[int]map[string]bool {
	type entry struct {
		i int
		m *bundlev1.RouteMatch
	}
	var entries []entry
	var routes []*bundlev1.RouteMatch
	for i, pol := range pols {
		seen := map[string]bool{}
		for _, m := range pol.GetRoutes() {
			if k := routeKey(m); !seen[k] && owned(i, m) {
				seen[k] = true
				entries = append(entries, entry{i, m})
				routes = append(routes, m)
			}
		}
	}
	removed := map[int]map[string]bool{}
	domains := func(e entry) map[string]bool {
		if cands[e.i].failed { // a previous version: its routes' domains are unknown
			return nil
		}
		return cands[e.i].domains[routeKey(e.m)]
	}
	overlapPairs(routes, func(x, y int) {
		a, b := entries[x], entries[y]
		ca, cb := cands[a.i], cands[b.i]
		if ca.key.Namespace == cb.key.Namespace || !routesOverlap(a.m, b.m) {
			return
		}
		spec := compareSpecificity(a.m, b.m)
		if spec != 0 && sameDomain(domains(a), domains(b)) {
			return // one proxy routes both, as the engine does
		}
		// The policy the overlap goes to: the stricter, else the older
		// (cands are oldest first).
		win, lose := a, b
		if dominates(pols[b.i], pols[a.i]) || !dominates(pols[a.i], pols[b.i]) && b.i < a.i {
			win, lose = b, a
		}
		// The route the engine picks in the overlap; on a tie, either.
		picked := a
		if spec > 0 {
			picked = b
		}
		if spec == 0 || picked == lose {
			k := routeKey(lose.m)
			if removed[lose.i] == nil {
				removed[lose.i] = map[string]bool{}
			}
			removed[lose.i][k] = true
		}
		cl, cw := cands[lose.i], cands[win.i]
		cl.lost = true
		cl.overlaps = append(cl.overlaps, fmt.Sprintf("%s: WAFPolicy %s applies to %s", describeRoute(lose.m), cw.policy.GetId(), describeRoute(win.m)))
		cw.overlaps = append(cw.overlaps, fmt.Sprintf("%s: this policy applies to it, not WAFPolicy %s's %s", describeRoute(win.m), cl.policy.GetId(), describeRoute(lose.m)))
	})
	return removed
}

func (c *candidate) fail(reason, message string) {
	if !c.failed {
		c.failed = true
		c.status = Status{Reason: reason, Message: message}
		return
	}
	c.status.Message += "; " + message
}

func (r *resolution) candidate(p *wafv1alpha1.WAFPolicy, ingresses map[types.NamespacedName]*networkingv1.Ingress,
	ingressRoutes map[types.NamespacedName]*unstructured.Unstructured, httpRoutes map[types.NamespacedName]*gatewayv1.HTTPRoute,
	virtualServices map[types.NamespacedName]*unstructured.Unstructured) *candidate {
	c := &candidate{
		obj:     p,
		key:     types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
		status:  Status{Accepted: true, Reason: ReasonAccepted, Message: PolicyValid},
		rank:    map[string]int{},
		domains: map[string]map[string]bool{},
	}
	c.policy = convertSpec(PolicyID(p.Namespace, p.Name), p.Spec)

	for _, b := range p.Spec.RuleSets {
		ns := b.Ref.Namespace
		if ns == "" {
			ns = p.Namespace
		}
		if b.Ref.Kind == "WAFRuleSet" && ns != p.Namespace {
			c.fail(ReasonInvalidRef, fmt.Sprintf("WAFRuleSet %s/%s: rule sets in other namespaces can't be used yet; use a ClusterWAFRuleSet", ns, b.Ref.Name))
			continue
		}
		id := RuleSetID(b.Ref.Kind, ns, b.Ref.Name)
		if _, ok := r.ruleSets[id]; !ok {
			msg := fmt.Sprintf("%s %s not found", b.Ref.Kind, b.Ref.Name)
			if st, ok := r.out.RuleSetStatus[id]; ok {
				msg = fmt.Sprintf("%s %s is not usable: %s", b.Ref.Kind, b.Ref.Name, st.Message)
			}
			c.fail(ReasonInvalidRef, msg)
		}
	}

	if l := p.Spec.IPLists; l != nil && (len(l.Allow) > 0 || len(l.Deny) > 0) {
		allow, errA := r.ipList(p.Namespace, l.Allow)
		deny, errD := r.ipList(p.Namespace, l.Deny)
		if err := cmp.Or(errA, errD); err != nil {
			c.fail(ReasonInvalidRef, err.Error())
		} else {
			c.policy.IpLists = &bundlev1.IPLists{Allow: allow, Deny: deny}
		}
	}

	var missing, unattached []string
	for _, t := range p.Spec.TargetRefs {
		switch t.Kind {
		case "Ingress":
			ing, ok := ingresses[types.NamespacedName{Namespace: p.Namespace, Name: t.Name}]
			if !ok {
				missing = append(missing, "Ingress "+t.Name)
				continue
			}
			c.addRoutes(rankIngress, ingressMatches(ing), ingressDomain(ing))
		case "IngressRoute":
			ir, ok := ingressRoutes[types.NamespacedName{Namespace: p.Namespace, Name: t.Name}]
			if !ok {
				missing = append(missing, "IngressRoute "+t.Name)
				continue
			}
			routes, err := ingressRouteMatches(ir)
			if err != nil {
				c.fail(ReasonTargetUnsupported, fmt.Sprintf("IngressRoute %s: %v", t.Name, err))
				continue
			}
			c.addRoutes(rankIngress, routes, objectDomain(t.Kind, p.Namespace, t.Name))
		case "HTTPRoute":
			hr, ok := httpRoutes[types.NamespacedName{Namespace: p.Namespace, Name: t.Name}]
			if !ok {
				missing = append(missing, "HTTPRoute "+t.Name)
				continue
			}
			gateways := AttachedGateways(hr)
			if len(gateways) == 0 && r.in.AssumeAttached {
				gateways = []string{"HTTPRoute " + p.Namespace + "/" + t.Name}
			}
			if len(gateways) == 0 {
				unattached = append(unattached, "HTTPRoute "+t.Name)
				continue
			}
			routes, err := httpRouteMatches(hr, t.SectionName)
			switch {
			case errors.Is(err, errNoRule):
				missing = append(missing, fmt.Sprintf("rule %s of HTTPRoute %s", t.SectionName, t.Name))
				continue
			case err != nil:
				c.fail(ReasonTargetUnsupported, fmt.Sprintf("HTTPRoute %s: %v", t.Name, err))
				continue
			}
			rank := rankHTTPRoute
			if t.SectionName != "" {
				rank = rankHTTPRouteRule
			}
			var domains []string
			for _, gw := range gateways {
				domains = append(domains, gatewayDomain(gw))
			}
			c.addRoutes(rank, routes, domains...)
		case "VirtualService":
			vs, ok := virtualServices[types.NamespacedName{Namespace: p.Namespace, Name: t.Name}]
			if !ok {
				missing = append(missing, "VirtualService "+t.Name)
				continue
			}
			routes, err := virtualServiceMatches(vs)
			if err != nil {
				c.fail(ReasonTargetUnsupported, fmt.Sprintf("VirtualService %s: %v", t.Name, err))
				continue
			}
			c.addRoutes(rankIngress, routes, objectDomain(t.Kind, p.Namespace, t.Name))
		default:
			c.fail(ReasonTargetUnsupported, fmt.Sprintf("%s %s: only Ingress, IngressRoute, HTTPRoute and VirtualService targets are resolved", t.Kind, t.Name))
		}
	}
	if len(missing) > 0 || len(unattached) > 0 {
		// A missing target is a route that doesn't exist (yet), not a reason
		// to fall back: the policy still applies to its other targets. So is
		// an HTTPRoute no Gateway accepted: no proxy routes it (yet).
		var msgs []string
		reason := ReasonInvalidRef
		if len(missing) > 0 {
			msgs = append(msgs, strings.Join(missing, ", ")+" not found")
		}
		if len(unattached) > 0 {
			msgs = append(msgs, strings.Join(unattached, ", ")+
				" not accepted by a Gateway of a proxy Inkwall integrates with (no Accepted parent in its status), so the policy doesn't apply to it")
			if len(missing) == 0 {
				reason = ReasonTargetNotAttached
			}
		}
		msg := strings.Join(msgs, "; ")
		if len(missing)+len(unattached) < len(p.Spec.TargetRefs) {
			msg += "; the policy applies to its other targets"
		}
		if c.failed {
			c.status.Message += "; " + msg
		} else {
			c.status = Status{Reason: reason, Message: msg}
		}
	}
	return c
}

func convertSpec(id string, s wafv1alpha1.WAFPolicySpec) *bundlev1.Policy {
	p := &bundlev1.Policy{Id: id, Mode: bundlev1.Mode_MODE_DETECT}
	if s.Mode == wafv1alpha1.PolicyBlock {
		p.Mode = bundlev1.Mode_MODE_BLOCK
	}
	switch s.FailureMode {
	case wafv1alpha1.FailOpen:
		p.FailureMode = bundlev1.FailureMode_FAILURE_MODE_OPEN
	case wafv1alpha1.FailClosed:
		p.FailureMode = bundlev1.FailureMode_FAILURE_MODE_CLOSED
	}
	if s.Timeout != nil {
		p.Timeout = durationpb.New(s.Timeout.Duration)
	}
	if s.Skip != nil {
		for _, sp := range s.Skip.Paths {
			p.SkipPaths = append(p.SkipPaths, string(sp))
		}
		for _, sp := range s.Skip.BodyPaths {
			p.SkipBodyPaths = append(p.SkipBodyPaths, string(sp))
		}
	}
	for _, b := range s.RuleSets {
		binding := &bundlev1.RuleSetBinding{RuleSetId: RuleSetID(b.Ref.Kind, cmp.Or(b.Ref.Namespace, namespaceOf(id)), b.Ref.Name)}
		if b.ParanoiaLevel != nil {
			binding.ParanoiaLevel = *b.ParanoiaLevel
		}
		if b.InboundAnomalyThreshold != nil {
			binding.InboundAnomalyThreshold = *b.InboundAnomalyThreshold
		}
		binding.Crs = crsSettings(b.CRS)
		p.RuleSets = append(p.RuleSets, binding)
	}
	for _, e := range s.Exclusions {
		ex := &bundlev1.Exclusion{}
		for _, id := range e.RuleIDs {
			ex.RuleIds = append(ex.RuleIds, uint32(id)) // #nosec G115 -- the CRD requires >= 1
		}
		if e.When != nil {
			ex.Path = string(e.When.Path)
			ex.Argument = e.When.Argument
			ex.ArgumentName = e.When.ArgumentName
			ex.Cookie = e.When.Cookie
			ex.Header = e.When.Header
		}
		if e.When.Target() {
			p.TargetExclusions = append(p.TargetExclusions, ex)
			continue
		}
		p.Exclusions = append(p.Exclusions, ex)
	}
	if b := s.Body; b != nil {
		body := &bundlev1.BodyConfig{Inspect: b.Inspect == nil || *b.Inspect, OnOversize: oversizeAction(b.OnOversize)}
		if b.MaxBytes != nil {
			body.MaxBytes = *b.MaxBytes
		}
		body.GrpcMessages = b.GRPCMessages == wafv1alpha1.GRPCMessagesInspect
		body.DenyGrpc = b.GRPC == wafv1alpha1.GRPCDeny
		p.Body = body
	}
	// Unset when not inspected: the bundles of policies without responses
	// stay as before 0.4.0.
	if r := s.Responses; r != nil && r.Inspect {
		resp := &bundlev1.ResponseConfig{Inspect: true, OnOversize: oversizeAction(r.OnOversize)}
		if r.MaxBytes != nil {
			resp.MaxBytes = *r.MaxBytes
		}
		p.Responses = resp
	}
	if w := s.WebSocket; w != nil && (len(w.AllowedOrigins) > 0 || len(w.RequiredHeaders) > 0) {
		ws := &bundlev1.WebSocketConfig{AllowMissingOrigin: w.AllowMissingOrigin}
		for _, o := range w.AllowedOrigins {
			ws.AllowedOrigins = append(ws.AllowedOrigins, string(o))
		}
		for _, h := range w.RequiredHeaders {
			ws.RequiredHeaders = append(ws.RequiredHeaders, string(h))
		}
		p.Websocket = ws
	}
	return p
}

func oversizeAction(a wafv1alpha1.OversizeAction) bundlev1.OversizeAction {
	switch a {
	case wafv1alpha1.OversizeAllow:
		return bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW
	case wafv1alpha1.OversizeDeny:
		return bundlev1.OversizeAction_OVERSIZE_ACTION_DENY
	}
	return bundlev1.OversizeAction_OVERSIZE_ACTION_UNSPECIFIED
}

func namespaceOf(policyID string) string {
	ns, _, _ := strings.Cut(policyID, "/")
	return ns
}

// ingressMatches expands an Ingress into route matches: one per host and
// path. ImplementationSpecific paths are treated as prefixes, as Traefik
// and ingress-nginx do. An Ingress with only a default backend matches any
// host and path; a default backend next to rules is not covered.
func ingressMatches(ing *networkingv1.Ingress) []*bundlev1.RouteMatch {
	var out []*bundlev1.RouteMatch
	if len(ing.Spec.Rules) == 0 && ing.Spec.DefaultBackend != nil {
		return []*bundlev1.RouteMatch{{Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}}}
	}
	for _, rule := range ing.Spec.Rules {
		host := strings.ToLower(rule.Host)
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			out = append(out, &bundlev1.RouteMatch{Host: host, Path: pathMatch(p)})
		}
	}
	return out
}

func pathMatch(p networkingv1.HTTPIngressPath) *bundlev1.PathMatch {
	value := p.Path
	if value == "" {
		value = "/"
	}
	if p.PathType != nil && *p.PathType == networkingv1.PathTypeExact {
		return &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT, Value: value}
	}
	// Element-wise prefix: a trailing slash makes no difference.
	value = path.Clean(value)
	return &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: value}
}

func targetKey(namespace string, t wafv1alpha1.TargetRef) string {
	return t.Kind + "/" + namespace + "/" + t.Name + "/" + t.SectionName
}

// routeKey identifies a route. An Ingress and an HTTPRoute wildcard of the
// same host are two routes: the HTTPRoute's also covers deeper subdomains.
func routeKey(m *bundlev1.RouteMatch) string {
	return fmt.Sprintf("%s|%t|%d|%s|%s", m.GetHost(), m.GetWildcardAnyDepth(), m.GetPath().GetType(), m.GetPath().GetValue(), strings.Join(m.GetMethods(), ","))
}

func describeRoute(m *bundlev1.RouteMatch) string {
	host := m.GetHost()
	if host == "" {
		host = "*"
	}
	return host + m.GetPath().GetValue()
}

// crsSettings is a binding's CRS settings in the bundle, nil when it sets
// none.
func crsSettings(c *wafv1alpha1.CRSSettings) *bundlev1.CRSSettings {
	if c.IsZero() {
		return nil
	}
	s := &bundlev1.CRSSettings{}
	for _, m := range c.AllowedMethods {
		s.AllowedMethods = append(s.AllowedMethods, string(m))
	}
	for _, t := range c.AllowedRequestContentTypes {
		s.AllowedRequestContentTypes = append(s.AllowedRequestContentTypes, string(t))
	}
	if c.DetectionParanoiaLevel != nil {
		s.DetectionParanoiaLevel = *c.DetectionParanoiaLevel
	}
	if c.OutboundAnomalyThreshold != nil {
		s.OutboundAnomalyThreshold = *c.OutboundAnomalyThreshold
	}
	return s
}

// ipList returns the entries of the WAFIPLists names, in namespace ns,
// without repeats; an error names a list that is missing or invalid.
func (r *resolution) ipList(ns string, names []wafv1alpha1.IPListName) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		i := slices.IndexFunc(r.in.IPLists, func(l wafv1alpha1.WAFIPList) bool { return l.Namespace == ns && l.Name == string(name) })
		if i < 0 {
			return nil, fmt.Errorf("WAFIPList %s not found", name)
		}
		var entries []string
		for _, e := range r.in.IPLists[i].Spec.Entries {
			entries = append(entries, string(e.CIDR))
		}
		if _, err := iplist.Parse(entries); err != nil {
			return nil, fmt.Errorf("WAFIPList %s: %w", name, err)
		}
		for _, e := range entries {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// CheckSpec compiles what the engine compiles of a policy's spec besides
// its rules and the objects it names (rule sets, IP lists), as the bundle
// builder checks it: for admission, so that a spec the bundle would leave
// out is refused when it is saved.
func CheckSpec(s wafv1alpha1.WAFPolicySpec) error {
	p := convertSpec("", s)
	p.RuleSets = nil // the webhook checks the CRS settings (checkCRS) and doesn't read rule sets
	return enginepolicy.CheckSettings(p, nil)
}
