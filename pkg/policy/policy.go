// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy enforces a bundle: each policy of the bundle gets its own
// pipeline (mode, failure mode, timeout, skip paths, rules, body settings),
// and each request is inspected by the policy of its route. A Holder swaps
// the active set atomically when a new bundle arrives.
package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// MaxBodyBytes is the largest body a policy may inspect, as WAFPolicy's
// body.maxBytes allows; adapters in bundle mode accept bodies up to it.
const MaxBodyBytes = 10 << 20

// Options are the engine-wide settings every policy shares.
type Options struct {
	// Admission bounds concurrent evaluations across all policies.
	Admission *pipeline.Admission
	// Observer is told about every verdict (metrics).
	Observer pipeline.Observer
	// MaxArgs is the argument limit (coraza.Config.MaxArgs).
	MaxArgs int
	// BodyLimit is the body inspected for a policy that doesn't set one.
	BodyLimit int64
	// OnMatch is called for every matching rule (coraza.Config.OnMatch).
	OnMatch func(types.MatchedRule)
	// Evaluators reuses compiled rule sets across bundles; nil compiles
	// every bundle from scratch.
	Evaluators *Evaluators
	// Stats counts each policy's requests, for the operator (nil: not
	// counted).
	Stats *events.Stats
}

// Policy is one compiled policy.
type Policy struct {
	ID        string
	pipeline  *pipeline.Pipeline
	bodyLimit int64 // 0: bodies are not inspected
	counter   *events.Counter
}

// Set is a compiled bundle. It is immutable and safe for concurrent use.
type Set struct {
	version   uint64
	suspended bool
	policies  []*Policy
	match     *matcher
}

var _ pipeline.Inspector = (*Set)(nil)

// Version is the bundle's version.
func (s *Set) Version() uint64 { return s.version }

// Policies returns the number of policies.
func (s *Set) Policies() int { return len(s.policies) }

// Lookup returns the policy for a request, or nil if no policy covers it.
func (s *Set) Lookup(r *request.Request) *Policy {
	return s.match.lookup(r.Host, r.RawURI, r.Method)
}

// Check implements pipeline.Inspector.
func (s *Set) Check(ctx context.Context, r *request.Request) pipeline.Verdict {
	if s.suspended {
		return pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonSuspended}
	}
	p := s.Lookup(r)
	if p == nil {
		return pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy}
	}
	v := p.pipeline.Check(ctx, r)
	v.Policy = p.ID
	p.counter.Observe(v)
	return v
}

// BodyLimit implements pipeline.Inspector: the policy's body limit, or 0
// when its bodies, or the route's, are not inspected.
func (s *Set) BodyLimit(r *request.Request, _ int64) int64 {
	if s.suspended {
		return 0
	}
	p := s.Lookup(r)
	if p == nil {
		return 0
	}
	return p.pipeline.BodyLimit(r, p.bodyLimit)
}

// Compile compiles a bundle. An error names the policy that failed: the
// engine then keeps the set it has (and reports the error to the operator).
func Compile(b *bundlev1.Bundle, o Options) (*Set, error) {
	ruleSets := map[string]*bundlev1.RuleSet{}
	for _, rs := range b.GetRuleSets() {
		ruleSets[rs.GetId()] = rs
	}
	set := &Set{version: b.GetVersion(), suspended: b.GetSuspended()}
	var routes []route
	used := map[[sha256.Size]byte]bool{}
	ids := map[string]bool{}
	for _, bp := range b.GetPolicies() {
		p, key, err := compilePolicy(bp, ruleSets, o)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", bp.GetId(), err)
		}
		used[key] = true
		ids[p.ID] = true
		if o.Stats != nil {
			p.counter = o.Stats.Counter(p.ID)
		}
		set.policies = append(set.policies, p)
		for _, m := range bp.GetRoutes() {
			routes = append(routes, newRoute(m, p))
		}
	}
	set.match = newMatcher(routes)
	if o.Evaluators != nil {
		o.Evaluators.retain(used)
	}
	if o.Stats != nil {
		o.Stats.Retain(ids)
	}
	return set, nil
}

func compilePolicy(bp *bundlev1.Policy, ruleSets map[string]*bundlev1.RuleSet, o Options) (*Policy, [sha256.Size]byte, error) {
	var key [sha256.Size]byte
	cfg := coraza.Config{MaxArgs: o.MaxArgs, OnMatch: o.OnMatch}

	// Rule sets: the built-in CRS (with its paranoia level and threshold)
	// and SecLang loaded after it, in order. No rule sets: the CRS with its
	// defaults. Rule sets but no built-in one: those rules alone.
	if len(bp.GetRuleSets()) > 0 {
		cfg.DisableCRS = true
		var directives []string
		for _, binding := range bp.GetRuleSets() {
			rs, ok := ruleSets[binding.GetRuleSetId()]
			if !ok {
				return nil, key, fmt.Errorf("rule set %s is not in the bundle", binding.GetRuleSetId())
			}
			switch src := rs.GetSource().(type) {
			case *bundlev1.RuleSet_Builtin:
				if src.Builtin != bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4 {
					return nil, key, fmt.Errorf("rule set %s: unknown built-in rule set %s", rs.GetId(), src.Builtin)
				}
				cfg.DisableCRS = false
				cfg.ParanoiaLevel = int(binding.GetParanoiaLevel())
				cfg.InboundAnomalyThreshold = int(binding.GetInboundAnomalyThreshold())
			case *bundlev1.RuleSet_Seclang:
				directives = append(directives, src.Seclang)
			default:
				return nil, key, fmt.Errorf("rule set %s has no source", rs.GetId())
			}
		}
		cfg.Directives = strings.Join(directives, "\n")
	}
	var exclusions []coraza.Exclusion
	for _, e := range bp.GetExclusions() {
		ex := coraza.Exclusion{Path: e.GetPath(), Argument: e.GetArgument()}
		for _, id := range e.GetRuleIds() {
			ex.RuleIDs = append(ex.RuleIDs, int(id))
		}
		exclusions = append(exclusions, ex)
	}

	bodyLimit := o.BodyLimit
	oversize := pipeline.OversizeAuto
	if body := bp.GetBody(); body != nil {
		if !body.GetInspect() {
			bodyLimit = 0
		} else if body.GetMaxBytes() > 0 {
			bodyLimit = body.GetMaxBytes()
		}
		switch body.GetOnOversize() {
		case bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW:
			oversize = pipeline.OversizeAllow
		case bundlev1.OversizeAction_OVERSIZE_ACTION_DENY:
			oversize = pipeline.OversizeDeny
		}
	}
	cfg.BodyLimit = int(bodyLimit)

	// The compiled rules, shared by every policy with the same key whatever
	// its exclusions, then this policy's exclusions on top.
	var shared *coraza.Evaluator
	var err error
	key = cfg.Key()
	if o.Evaluators != nil {
		shared, err = o.Evaluators.get(key, cfg)
	} else {
		shared, err = coraza.New(cfg)
	}
	if err != nil {
		return nil, key, err
	}
	eval, err := shared.WithExclusions(exclusions)
	if err != nil {
		return nil, key, err
	}

	routes, err := router.New(bp.GetSkipPaths(), bp.GetSkipBodyPaths())
	if err != nil {
		return nil, key, err
	}
	pc := pipeline.Config{
		Mode:      pipeline.ModeDetect,
		Admission: o.Admission,
		Oversize:  oversize,
		Observer:  o.Observer,
		Routes:    routes,
	}
	if bp.GetMode() == bundlev1.Mode_MODE_BLOCK {
		pc.Mode = pipeline.ModeBlock
	}
	switch bp.GetFailureMode() {
	case bundlev1.FailureMode_FAILURE_MODE_OPEN:
		pc.FailureMode = pipeline.FailOpen
	case bundlev1.FailureMode_FAILURE_MODE_CLOSED:
		pc.FailureMode = pipeline.FailClosed
	}
	if t := bp.GetTimeout(); t != nil {
		pc.Timeout = t.AsDuration()
	}
	return &Policy{ID: bp.GetId(), pipeline: pipeline.New(eval, pc), bodyLimit: bodyLimit}, key, nil
}

// Evaluators caches compiled rule sets by configuration (coraza.Config.Key,
// without exclusions): policies with the same rules share one (a Coraza WAF
// with the CRS holds megabytes) whatever their exclusions, and an unchanged
// policy isn't recompiled when a new bundle arrives. Cached evaluators have
// no exclusions.
type Evaluators struct {
	mu    sync.Mutex
	cache map[[sha256.Size]byte]*coraza.Evaluator
}

// NewEvaluators returns an empty cache.
func NewEvaluators() *Evaluators {
	return &Evaluators{cache: map[[sha256.Size]byte]*coraza.Evaluator{}}
}

func (e *Evaluators) get(key [sha256.Size]byte, cfg coraza.Config) (*coraza.Evaluator, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ev, ok := e.cache[key]; ok {
		return ev, nil
	}
	// Shared by every policy with this key: none's exclusions.
	cfg.Exclusions = nil
	ev, err := coraza.New(cfg)
	if err != nil {
		return nil, err
	}
	e.cache[key] = ev
	return ev, nil
}

// retain drops the rule sets the latest set doesn't use.
func (e *Evaluators) retain(used map[[sha256.Size]byte]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.cache {
		if !used[k] {
			delete(e.cache, k)
		}
	}
}

// Len returns the number of cached rule sets.
func (e *Evaluators) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cache)
}

// Holder holds the active Set, swapped atomically: Check runs entirely on
// the set it loaded. (An adapter's BodyLimit and Check calls may straddle a
// swap; the request is then inspected by the new set, with the body read to
// the old set's limit.) Before the first set it allows every request, with
// ReasonNoPolicy, or denies it with DenyBeforeFirst.
type Holder struct {
	set atomic.Pointer[Set]
	// DenyBeforeFirst rejects requests with 503 until the first set is
	// stored, instead of letting them through uninspected.
	DenyBeforeFirst bool
}

var _ pipeline.Inspector = (*Holder)(nil)

// Store makes s the active set.
func (h *Holder) Store(s *Set) { h.set.Store(s) }

// Load returns the active set, nil before the first.
func (h *Holder) Load() *Set { return h.set.Load() }

// Check implements pipeline.Inspector.
func (h *Holder) Check(ctx context.Context, r *request.Request) pipeline.Verdict {
	s := h.set.Load()
	if s == nil {
		if h.DenyBeforeFirst {
			return pipeline.Verdict{Action: pipeline.ActionDeny, Status: http.StatusServiceUnavailable, Reason: pipeline.ReasonNoPolicy}
		}
		return pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy}
	}
	return s.Check(ctx, r)
}

// BodyLimit implements pipeline.Inspector.
func (h *Holder) BodyLimit(r *request.Request, max int64) int64 {
	s := h.set.Load()
	if s == nil {
		return 0
	}
	return s.BodyLimit(r, max)
}
