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
	"fmt"
	"path"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
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
)

// PolicyValid is the Accepted message of a policy that resolved with
// nothing to report.
const PolicyValid = "the policy is valid"

// Input is the cluster state to resolve.
type Input struct {
	Policies        []wafv1alpha1.WAFPolicy
	Ingresses       []networkingv1.Ingress
	RuleSets        []wafv1alpha1.WAFRuleSet
	ClusterRuleSets []wafv1alpha1.ClusterWAFRuleSet
	// ConfigMaps rule sets read rules from (labeled RulesLabel).
	ConfigMaps []corev1.ConfigMap
	// Previous is the bundle in force; nil when there is none.
	Previous *bundlev1.Bundle
	// CheckRules checks SecLang read from a ConfigMap
	// (coraza.CheckUserRules); inline rules were checked at admission.
	CheckRules func(string) error
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

// candidate is a policy being resolved.
type candidate struct {
	obj    *wafv1alpha1.WAFPolicy
	key    types.NamespacedName
	policy *bundlev1.Policy
	status Status
	// failed means the policy falls back to its previous version.
	failed bool
}

func (r *resolution) resolvePolicies() {
	ingresses := map[types.NamespacedName]*networkingv1.Ingress{}
	for i := range r.in.Ingresses {
		ing := &r.in.Ingresses[i]
		ingresses[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}] = ing
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
		c := r.candidate(&policies[i], ingresses)
		for _, t := range c.obj.Spec.TargetRefs {
			k := targetKey(c.key.Namespace, t)
			if prev, ok := owner[k]; ok {
				c.fail(ReasonConflict, fmt.Sprintf("%s %s is also targeted by the older WAFPolicy %s, which applies to it",
					t.Kind, t.Name, prev.key.Name))
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

	used := map[string]*bundlev1.RuleSet{}
	routes := map[string]string{} // route -> policy id that has it
	for _, c := range cands {
		pol := c.policy
		usedRuleSets := r.ruleSets
		if c.failed {
			prev, ok := previous[c.policy.GetId()]
			if !ok {
				r.out.PolicyStatus[c.key] = c.status
				continue
			}
			c.status.Message += "; the previous version of the policy stays in force"
			pol = proto.Clone(prev).(*bundlev1.Policy)
			usedRuleSets = previousRuleSets
		}
		// A route of two policies (from two Ingresses with the same host
		// and path) goes to the older one.
		var kept []*bundlev1.RouteMatch
		var shadowed []string
		for _, m := range pol.GetRoutes() {
			k := routeKey(m)
			if other, ok := routes[k]; ok {
				shadowed = append(shadowed, fmt.Sprintf("%s (older policy %s)", describeRoute(m), other))
				continue
			}
			routes[k] = pol.GetId()
			kept = append(kept, m)
		}
		pol.Routes = kept
		if len(shadowed) > 0 && !c.failed {
			c.status.Message = fmt.Sprintf("%s; routes covered by an older policy, which applies to them: %s",
				c.status.Message, strings.Join(shadowed, ", "))
		}
		for _, b := range pol.GetRuleSets() {
			used[b.GetRuleSetId()] = usedRuleSets[b.GetRuleSetId()]
		}
		c.status.Applied = !c.failed
		r.out.Policies = append(r.out.Policies, pol)
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

func (c *candidate) fail(reason, message string) {
	if !c.failed {
		c.failed = true
		c.status = Status{Reason: reason, Message: message}
		return
	}
	c.status.Message += "; " + message
}

func (r *resolution) candidate(p *wafv1alpha1.WAFPolicy, ingresses map[types.NamespacedName]*networkingv1.Ingress) *candidate {
	c := &candidate{
		obj:    p,
		key:    types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
		status: Status{Accepted: true, Reason: ReasonAccepted, Message: PolicyValid},
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

	var missing []string
	for _, t := range p.Spec.TargetRefs {
		switch t.Kind {
		case "Ingress":
			ing, ok := ingresses[types.NamespacedName{Namespace: p.Namespace, Name: t.Name}]
			if !ok {
				missing = append(missing, "Ingress "+t.Name)
				continue
			}
			c.policy.Routes = append(c.policy.Routes, ingressRoutes(ing)...)
		default:
			c.fail(ReasonTargetUnsupported, fmt.Sprintf("%s %s: only Ingress targets are resolved so far", t.Kind, t.Name))
		}
	}
	if len(missing) > 0 {
		// A missing target is a route that doesn't exist (yet), not a reason
		// to fall back: the policy still applies to its other targets.
		msg := strings.Join(missing, ", ") + " not found"
		if len(missing) < len(p.Spec.TargetRefs) {
			msg += "; the policy applies to its other targets"
		}
		if c.failed {
			c.status.Message += "; " + msg
		} else {
			c.status = Status{Reason: ReasonInvalidRef, Message: msg}
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
		}
		p.Exclusions = append(p.Exclusions, ex)
	}
	if b := s.Body; b != nil {
		body := &bundlev1.BodyConfig{Inspect: b.Inspect == nil || *b.Inspect}
		if b.MaxBytes != nil {
			body.MaxBytes = *b.MaxBytes
		}
		switch b.OnOversize {
		case wafv1alpha1.OversizeAllow:
			body.OnOversize = bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW
		case wafv1alpha1.OversizeDeny:
			body.OnOversize = bundlev1.OversizeAction_OVERSIZE_ACTION_DENY
		}
		p.Body = body
	}
	return p
}

func namespaceOf(policyID string) string {
	ns, _, _ := strings.Cut(policyID, "/")
	return ns
}

// ingressRoutes expands an Ingress into route matches: one per host and
// path. ImplementationSpecific paths are treated as prefixes, as Traefik
// and ingress-nginx do. An Ingress with only a default backend matches any
// host and path; a default backend next to rules is not covered.
func ingressRoutes(ing *networkingv1.Ingress) []*bundlev1.RouteMatch {
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

func routeKey(m *bundlev1.RouteMatch) string {
	return fmt.Sprintf("%s|%d|%s|%s", m.GetHost(), m.GetPath().GetType(), m.GetPath().GetValue(), strings.Join(m.GetMethods(), ","))
}

func describeRoute(m *bundlev1.RouteMatch) string {
	host := m.GetHost()
	if host == "" {
		host = "*"
	}
	return host + m.GetPath().GetValue()
}
