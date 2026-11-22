// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy enforces a bundle: each policy of the bundle gets its own
// pipeline (mode, failure mode, timeout, skip paths, rules, body settings),
// and each request is inspected by the policy of its route. A Holder swaps
// the active set atomically when a new bundle arrives.
package policy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/iplist"
	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// MaxBodyBytes is the largest body a policy may inspect, as WAFPolicy's
// body.maxBytes allows; adapters in bundle mode accept bodies up to it.
const MaxBodyBytes = 10 << 20

// DefaultResponseBytes is the response body a policy that inspects
// responses inspects when it sets no limit, as for request bodies: the CRS
// response rules cost about 0.3 ms per KiB of HTML (BenchmarkEvaluateExchange),
// so Coraza's recommended 512 KiB would take most of the default deadline.
// A policy may inspect up to MaxBodyBytes.
const DefaultResponseBytes = 64 << 10

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
	// RateLimits holds every policy's rate limit buckets, across bundles
	// (nil: a bundle with rate limits doesn't compile).
	RateLimits *ratelimit.Store
	// IgnoreRateLimits compiles the policies' rate limits, so an error is
	// still one, but doesn't apply them: for inkwallctl test, which checks
	// one request at a time.
	IgnoreRateLimits bool
	// LLMMetrics, if set, count the LLM endpoints' bodies and checks.
	LLMMetrics *llm.Metrics
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
	probeKey  []byte
	redaction *events.Redaction
	policies  []*Policy
	match     *matcher
	observer  pipeline.Observer // told about the verdicts no policy's pipeline gives
	// geoNamed: the bundle names a country table (design 0011 §4.5);
	// geoTable is the table the set enforces with: the named one, the
	// previous bundle's while the named one hasn't arrived, or nil.
	geoNamed bool
	geoTable *geo.Table
}

var _ pipeline.Inspector = (*Set)(nil)

// WithGeo returns a set that shares every compiled policy with s and
// differs only in its country table: named is whether the bundle names
// one, t the table to enforce with (nil: none held). A table that arrives
// after its bundle makes a new set this way, swapped in like any other, so
// a request never sees a bundle with another bundle's table.
func (s *Set) WithGeo(named bool, t *geo.Table) *Set {
	c := *s
	c.geoNamed, c.geoTable = named, t
	return &c
}

// GeoTable returns the country table the set enforces with, and whether
// its bundle names one.
func (s *Set) GeoTable() (*geo.Table, bool) { return s.geoTable, s.geoNamed }

// ProbeKey is the key of the operator's HAProxy probe, nil if the bundle
// has none.
func (s *Set) ProbeKey() []byte { return s.probeKey }

// Version is the bundle's version.
func (s *Set) Version() uint64 { return s.version }

// Policies returns the number of policies.
func (s *Set) Policies() int { return len(s.policies) }

// Lookup returns the policy for a request, or nil if no policy covers it:
// the policy of its decoded, cleaned path, when the forms of its path
// select several (policiesFor).
func (s *Set) Lookup(r *request.Request) *Policy {
	return s.match.lookup(r.Host, r.RawURI, r.Method)
}

// policiesFor appends to buf the policies r is inspected with: none when
// no policy covers it, or each policy the forms of its path select
// (matcher.policies), those in block mode first. A request inspected by
// several gets the strictest of their verdicts.
func (s *Set) policiesFor(r *request.Request, buf []*Policy) []*Policy {
	ps := s.match.policies(r.Host, r.RawURI, r.Method, buf)
	if len(ps) > 1 {
		slices.SortStableFunc(ps, func(a, b *Policy) int {
			return cmp.Compare(b.pipeline.Mode(), a.pipeline.Mode())
		})
	}
	return ps
}

// limit is how much of r's body p reads: its LLM endpoints' limit on one
// of them, its body limit otherwise (0: none).
func (p *Policy) limit(r *request.Request) int64 {
	if n := p.pipeline.LLMBodyLimit(r); n > 0 {
		return n
	}
	return p.bodyLimit
}

// view returns r as p inspects it when r's body was read for another
// policy too: without its body when p inspects none, cut at p's limit.
func (p *Policy) view(r *request.Request) *request.Request {
	limit := p.limit(r)
	if limit > 0 && int64(len(r.Body)) <= limit || limit == 0 && r.Body == nil && !r.BodyTruncated {
		return r
	}
	v := *r
	if limit == 0 {
		v.Body, v.BodyTruncated = nil, false
	} else {
		v.Body, v.BodyTruncated = r.Body[:limit], true
	}
	return &v
}

// Check implements pipeline.Inspector.
func (s *Set) Check(ctx context.Context, r *request.Request) pipeline.Verdict {
	if s.suspended {
		return observe(s.observer, pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonSuspended})
	}
	var buf [4]*Policy
	ps := s.policiesFor(r, buf[:0])
	if len(ps) == 0 {
		return observe(s.observer, pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy})
	}
	if len(ps) == 1 {
		// The policy's pipeline names it on the verdict and tells the Observer.
		v := ps[0].pipeline.Check(ctx, r)
		ps[0].counter.Observe(v)
		return v
	}
	if p := rateLimited(ps, r); p != nil {
		v := p.pipeline.Check(ctx, p.view(r))
		p.counter.Observe(v)
		return v
	}
	var out pipeline.Verdict
	for i, p := range ps {
		v := p.pipeline.Check(ctx, p.view(r))
		p.counter.Observe(v)
		if i == 0 || pipeline.Stricter(v, out) {
			out = v
		}
		if out.Action == pipeline.ActionDeny {
			break
		}
	}
	return out
}

var _ pipeline.ExchangeInspector = (*Set)(nil)

// CheckExchange implements pipeline.ExchangeInspector. The response's
// verdict names the policy and is counted as its own denied or detected
// request, not as another allowed one. A request inspected by several
// policies has its response inspected by each that inspects responses.
func (s *Set) CheckExchange(ctx context.Context, r *request.Request) (pipeline.Verdict, *pipeline.Exchange) {
	if s.suspended {
		return observe(s.observer, pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonSuspended}), nil
	}
	var buf [4]*Policy
	ps := s.policiesFor(r, buf[:0])
	if len(ps) == 0 {
		return observe(s.observer, pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy}), nil
	}
	if p := rateLimited(ps, r); p != nil && len(ps) > 1 {
		v := p.pipeline.Check(ctx, p.view(r))
		p.counter.Observe(v)
		return v, nil
	}
	var out pipeline.Verdict
	var xs []*pipeline.Exchange
	for i, p := range ps {
		pr := r
		if len(ps) > 1 {
			pr = p.view(r)
		}
		v, x := p.pipeline.CheckExchange(ctx, pr)
		p.counter.Observe(v)
		if x != nil {
			x.OnVerdict(func(v pipeline.Verdict) {
				if v.Action != pipeline.ActionAllow {
					p.counter.Observe(v)
				}
			})
			xs = append(xs, x)
		}
		if i == 0 || pipeline.Stricter(v, out) {
			out = v
		}
		if out.Action == pipeline.ActionDeny {
			for _, x := range xs {
				x.Close()
			}
			return out, nil
		}
	}
	return out, pipeline.JoinExchanges(xs)
}

var _ pipeline.GRPCStreamInspector = (*Set)(nil)

// GRPCStream implements pipeline.GRPCStreamInspector: r's policy's, if it
// inspects r's messages one by one (#315). Each message's verdict is
// counted as the policy's, as a request's. A call the forms of whose path
// select several policies isn't streamed: each inspects it buffered.
func (s *Set) GRPCStream(r *request.Request) pipeline.GRPCStream {
	if s.suspended {
		return nil
	}
	var buf [4]*Policy
	ps := s.policiesFor(r, buf[:0])
	if len(ps) != 1 {
		return nil
	}
	p := ps[0]
	if p.pipeline.GRPCStream(r) == nil {
		return nil
	}
	return countedStream{p}
}

// countedStream is a policy's GRPCStream whose verdicts its counter sees.
type countedStream struct{ p *Policy }

func (c countedStream) CheckGRPCMessage(ctx context.Context, call *request.Request, ev streams.Event, n int) pipeline.Verdict {
	v := c.p.pipeline.CheckGRPCMessage(ctx, call, ev, n)
	c.p.counter.Observe(v)
	return v
}

func (c countedStream) Mode() pipeline.Mode { return c.p.pipeline.Mode() }

// rateLimited is the policy of ps that BodyLimit found r over one of the
// rate limits of, nil if none: it answers r (429) first, so the others'
// rules don't run on a body that wasn't read, nor a 403 of theirs replace
// the 429.
func rateLimited(ps []*Policy, r *request.Request) *Policy {
	for _, p := range ps {
		if p.pipeline.RateLimited(r) {
			return p
		}
	}
	return nil
}

// BodyLimit implements pipeline.Inspector: the policy's body limit, at
// most max (the adapter's own) when max is positive, or 0 when its bodies,
// or the route's, are not inspected. A request inspected by several
// policies is read to the largest of their limits.
func (s *Set) BodyLimit(r *request.Request, max int64) int64 {
	if s.suspended {
		return 0
	}
	var buf [4]*Policy
	var limit int64
	for _, p := range s.policiesFor(r, buf[:0]) {
		l := p.limit(r)
		if max > 0 {
			l = min(l, max)
		}
		if l = p.pipeline.BodyLimit(r, l); l > limit {
			limit = l
		}
		// Over one of its rate limits: Check denies here, without the
		// body, and charges no later policy.
		if p.pipeline.RateLimited(r) {
			return 0
		}
	}
	return limit
}

// Compile compiles a bundle. An error names the policy that failed: the
// engine then keeps the set it has (and reports the error to the operator).
func Compile(b *bundlev1.Bundle, o Options) (*Set, error) {
	ruleSets := map[string]*bundlev1.RuleSet{}
	for _, rs := range b.GetRuleSets() {
		ruleSets[rs.GetId()] = rs
	}
	set := &Set{version: b.GetVersion(), suspended: b.GetSuspended(), probeKey: bytes.Clone(b.GetProbeKey()),
		redaction: events.NewRedaction(b.GetEvents()), observer: o.Observer}
	var routes []route
	used := map[[sha256.Size]byte]bool{}
	ids := map[string]bool{}
	live := ratelimit.NewLive()
	deny, err := denyResponse(b.GetDenyResponse())
	if err != nil {
		return nil, fmt.Errorf("deny response: %w", err)
	}
	for _, bp := range b.GetPolicies() {
		p, key, err := compilePolicy(bp, ruleSets, o, live, deny)
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

func compilePolicy(bp *bundlev1.Policy, ruleSets map[string]*bundlev1.RuleSet, o Options, live *ratelimit.Live, deny *pipeline.DenyResponse) (*Policy, [sha256.Size]byte, error) {
	var key [sha256.Size]byte
	cfg, crs, err := rulesConfig(bp, ruleSets, o)
	if err != nil {
		return nil, key, err
	}
	var exclusions []coraza.Exclusion
	for _, e := range append(bp.GetExclusions(), bp.GetTargetExclusions()...) {
		ex := coraza.Exclusion{Path: e.GetPath(), Argument: e.GetArgument(),
			ArgumentName: e.GetArgumentName(), Cookie: e.GetCookie(), Header: e.GetHeader()}
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
		} else if n := body.GetMaxBytes(); n > 0 {
			// The CRD bounds it, but a bundle from elsewhere may not.
			bodyLimit = min(n, MaxBodyBytes)
		}
		oversize = oversizeAction(body.GetOnOversize())
	}

	var responses pipeline.ResponseConfig
	if rc := bp.GetResponses(); rc.GetInspect() {
		responses.Inspect = true
		responses.MaxBytes = DefaultResponseBytes
		if n := rc.GetMaxBytes(); n > 0 {
			responses.MaxBytes = min(n, MaxBodyBytes)
		}
		responses.Oversize = oversizeAction(rc.GetOnOversize())
		responses.Streams = rc.GetStreams()
	}
	// Coraza's body limits are compiled in, so every policy gets the largest
	// any may have, for one rule set: the pipeline gives the rules no more
	// of a body than the policy's own limit (and none of a truncated
	// request body). Same for the CRS settings, which are set on each
	// transaction. bodyLimit is MaxBodyBytes at most, or the engine's
	// default (o.BodyLimit), so the largest is the same for every policy.
	engineLimit := int(max(MaxBodyBytes, o.BodyLimit))
	cfg.BodyLimit = engineLimit
	cfg.ResponseBodyLimit = engineLimit

	// The compiled rules, shared by every policy with the same key whatever
	// its CRS settings and exclusions, then this policy's on top.
	var shared *coraza.Evaluator
	key = cfg.Key()
	if o.Evaluators != nil {
		shared, err = o.Evaluators.get(key, cfg)
	} else {
		shared, err = coraza.New(cfg)
	}
	if err != nil {
		return nil, key, err
	}
	eval, err := shared.WithCRS(crs)
	if err != nil {
		return nil, key, err
	}
	if eval, err = eval.WithExclusions(exclusions); err != nil {
		return nil, key, err
	}

	routes, err := router.New(bp.GetSkipPaths(), bp.GetSkipBodyPaths())
	if err != nil {
		return nil, key, err
	}
	var ws *pipeline.WebSocketRules
	if w := bp.GetWebsocket(); w != nil {
		ws, err = pipeline.CompileWebSocket(pipeline.WebSocketConfig{
			AllowedOrigins:     w.GetAllowedOrigins(),
			AllowMissingOrigin: w.GetAllowMissingOrigin(),
			RequiredHeaders:    w.GetRequiredHeaders(),
		})
		if err != nil {
			return nil, key, fmt.Errorf("websocket: %w", err)
		}
	}
	pc := pipeline.Config{
		Mode:           pipeline.ModeDetect,
		Admission:      o.Admission,
		Oversize:       oversize,
		Observer:       o.Observer,
		Policy:         bp.GetId(),
		Routes:         routes,
		WebSocket:      ws,
		Responses:      responses,
		GRPCMessages:   bp.GetBody().GetGrpcMessages(),
		GRPCPerMessage: bp.GetBody().GetGrpcPerMessage(),
		DenyGRPC:       bp.GetBody().GetDenyGrpc(),
	}
	if l := bp.GetIpLists(); l != nil {
		if pc.IPAllow, err = iplist.Parse(l.GetAllow()); err != nil {
			return nil, key, fmt.Errorf("IP allow list: %w", err)
		}
		if pc.IPDeny, err = iplist.Parse(l.GetDeny()); err != nil {
			return nil, key, fmt.Errorf("IP deny list: %w", err)
		}
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
	if pc.RateLimits, err = pipeline.CompileRateLimits(o.RateLimits, live, bp.GetId(), rateLimits(bp)); err != nil {
		return nil, key, err
	}
	if o.IgnoreRateLimits {
		pc.RateLimits = nil
	}
	if pc.LLM, err = pipeline.CompileLLM(llmConfig(bp, bodyLimit > 0, o.LLMMetrics)); err != nil {
		return nil, key, err
	}
	// The policy's own denial, or the bundle's.
	if pc.DenyResponse, err = denyResponse(bp.GetDenyResponse()); err != nil {
		return nil, key, fmt.Errorf("deny response: %w", err)
	}
	if pc.DenyResponse == nil {
		pc.DenyResponse = deny
	}
	return &Policy{ID: bp.GetId(), pipeline: pipeline.New(eval, pc), bodyLimit: bodyLimit}, key, nil
}

// denyResponse compiles a bundle's DenyResponse; nil for none.
func denyResponse(d *bundlev1.DenyResponse) (*pipeline.DenyResponse, error) {
	if d == nil {
		return nil, nil
	}
	return pipeline.CompileDenyResponse(d.GetContentType(), d.GetBody())
}

// rulesConfig is the rules a policy compiles to: its rule sets in order,
// and its CRS settings.
func rulesConfig(bp *bundlev1.Policy, ruleSets map[string]*bundlev1.RuleSet, o Options) (coraza.Config, coraza.CRSSettings, error) {
	cfg := coraza.Config{MaxArgs: o.MaxArgs, OnMatch: o.OnMatch}
	var crs coraza.CRSSettings

	// Rule sets: the built-in CRS (with its paranoia level and threshold)
	// and SecLang loaded after it, or before it when the binding says so
	// (#423), each in order. No rule sets: the CRS with its defaults. Rule
	// sets but no built-in one: those rules alone, the ones placed before
	// the CRS first.
	if len(bp.GetRuleSets()) > 0 {
		cfg.DisableCRS = true
		var before, directives []string
		for _, binding := range bp.GetRuleSets() {
			rs, ok := ruleSets[binding.GetRuleSetId()]
			if !ok {
				return cfg, crs, fmt.Errorf("rule set %s is not in the bundle", binding.GetRuleSetId())
			}
			switch src := rs.GetSource().(type) {
			case *bundlev1.RuleSet_Builtin:
				if src.Builtin != bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4 {
					return cfg, crs, fmt.Errorf("rule set %s: unknown built-in rule set %s", rs.GetId(), src.Builtin)
				}
				cfg.DisableCRS = false
				crs = coraza.CRSSettings{
					ParanoiaLevel:              int(binding.GetParanoiaLevel()),
					InboundAnomalyThreshold:    int(binding.GetInboundAnomalyThreshold()),
					AllowedMethods:             binding.GetCrs().GetAllowedMethods(),
					AllowedRequestContentTypes: binding.GetCrs().GetAllowedRequestContentTypes(),
					DetectionParanoiaLevel:     int(binding.GetCrs().GetDetectionParanoiaLevel()),
					OutboundAnomalyThreshold:   int(binding.GetCrs().GetOutboundAnomalyThreshold()),
				}
			case *bundlev1.RuleSet_Seclang:
				if binding.GetPlacement() == bundlev1.RuleSetPlacement_RULE_SET_PLACEMENT_BEFORE_CRS {
					before = append(before, src.Seclang)
				} else {
					directives = append(directives, src.Seclang)
				}
			default:
				return cfg, crs, fmt.Errorf("rule set %s has no source", rs.GetId())
			}
		}
		cfg.DirectivesBeforeCRS = strings.Join(before, "\n")
		cfg.Directives = strings.Join(directives, "\n")
	}
	return cfg, crs, nil
}

// RuleChecker checks that a policy's rule sets compile together, as
// Compile compiles them: rule sets that are valid alone may not be (the
// same rule ID in two). It remembers each combination's result, not the
// compiled rules.
type RuleChecker struct {
	mu   sync.Mutex
	errs map[[sha256.Size]byte]error
}

// NewRuleChecker returns a RuleChecker that has checked nothing.
func NewRuleChecker() *RuleChecker {
	return &RuleChecker{errs: map[[sha256.Size]byte]error{}}
}

// Check compiles the rules of policy bp, whose rule sets are among
// ruleSets. A policy without SecLang rule sets runs only the built-in rules
// and isn't compiled.
func (c *RuleChecker) Check(bp *bundlev1.Policy, ruleSets []*bundlev1.RuleSet) error {
	byID := map[string]*bundlev1.RuleSet{}
	seclang := false
	for _, rs := range ruleSets {
		byID[rs.GetId()] = rs
	}
	for _, b := range bp.GetRuleSets() {
		if _, ok := byID[b.GetRuleSetId()].GetSource().(*bundlev1.RuleSet_Seclang); ok {
			seclang = true
		}
	}
	if !seclang {
		return nil
	}
	cfg, _, err := rulesConfig(bp, byID, Options{})
	if err != nil {
		return err
	}
	cfg.BodyLimit, cfg.ResponseBodyLimit = MaxBodyBytes, MaxBodyBytes
	key := cfg.Key()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err, ok := c.errs[key]; ok {
		return err
	}
	_, err = coraza.New(cfg)
	c.errs[key] = err
	return err
}

func oversizeAction(a bundlev1.OversizeAction) pipeline.OversizeAction {
	switch a {
	case bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW:
		return pipeline.OversizeAllow
	case bundlev1.OversizeAction_OVERSIZE_ACTION_DENY:
		return pipeline.OversizeDeny
	}
	return pipeline.OversizeAuto
}

// Evaluators caches compiled rule sets by configuration (coraza.Config.Key,
// without exclusions and CRS settings): policies with the same rules share
// one (a Coraza WAF with the CRS holds megabytes) whatever their exclusions,
// paranoia level, threshold and body limits, and an unchanged policy isn't
// recompiled when a new bundle arrives. Cached evaluators have no
// exclusions, and the CRS settings of the policy that compiled them.
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
	// Observer, if set, is told about the verdicts before the first set
	// (metrics); a set tells its own Options.Observer.
	Observer pipeline.Observer
}

var _ pipeline.Inspector = (*Holder)(nil)

// Store makes s the active set.
func (h *Holder) Store(s *Set) { h.set.Store(s) }

// ProbeKey is the active set's probe key, nil before the first set.
func (h *Holder) ProbeKey() []byte {
	if s := h.set.Load(); s != nil {
		return s.probeKey
	}
	return nil
}

// Redaction is the active set's events redaction, nil before the first
// set or without one.
func (h *Holder) Redaction() *events.Redaction {
	if s := h.set.Load(); s != nil {
		return s.redaction
	}
	return nil
}

// Load returns the active set, nil before the first.
func (h *Holder) Load() *Set { return h.set.Load() }

// Check implements pipeline.Inspector.
func (h *Holder) Check(ctx context.Context, r *request.Request) pipeline.Verdict {
	s := h.set.Load()
	if s == nil {
		if h.DenyBeforeFirst {
			return observe(h.Observer, pipeline.Verdict{Action: pipeline.ActionDeny, Status: http.StatusServiceUnavailable, Reason: pipeline.ReasonNoPolicy})
		}
		return observe(h.Observer, pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy})
	}
	return s.Check(ctx, r)
}

// observe tells o, if set, about v, a verdict no policy's pipeline gave
// (which tells its Observer itself), and returns it.
func observe(o pipeline.Observer, v pipeline.Verdict) pipeline.Verdict {
	if o != nil {
		o.ObserveVerdict(v)
	}
	return v
}

var _ pipeline.ExchangeInspector = (*Holder)(nil)

// CheckExchange implements pipeline.ExchangeInspector.
func (h *Holder) CheckExchange(ctx context.Context, r *request.Request) (pipeline.Verdict, *pipeline.Exchange) {
	s := h.set.Load()
	if s == nil {
		return h.Check(ctx, r), nil
	}
	return s.CheckExchange(ctx, r)
}

var _ pipeline.GRPCStreamInspector = (*Holder)(nil)

// GRPCStream implements pipeline.GRPCStreamInspector: the active set's,
// nil before the first. Without it an engine in bundle mode would buffer
// every gRPC call whatever its policy's grpcStreams (#646).
func (h *Holder) GRPCStream(r *request.Request) pipeline.GRPCStream {
	s := h.set.Load()
	if s == nil {
		return nil
	}
	return s.GRPCStream(r)
}

// BodyLimit implements pipeline.Inspector.
func (h *Holder) BodyLimit(r *request.Request, max int64) int64 {
	s := h.set.Load()
	if s == nil {
		return 0
	}
	return s.BodyLimit(r, max)
}

// llmFormats are the bundle's formats in the pipeline's terms; another is
// llm.FormatUnknown, checked as every format.
var llmFormats = map[bundlev1.LLMFormat]llm.Format{
	bundlev1.LLMFormat_LLM_FORMAT_OPENAI_CHAT:        llm.OpenAIChat,
	bundlev1.LLMFormat_LLM_FORMAT_OPENAI_RESPONSES:   llm.OpenAIResponses,
	bundlev1.LLMFormat_LLM_FORMAT_OPENAI_EMBEDDINGS:  llm.OpenAIEmbeddings,
	bundlev1.LLMFormat_LLM_FORMAT_ANTHROPIC_MESSAGES: llm.AnthropicMessages,
}

var llmRoles = map[bundlev1.LLMRole]llm.Role{
	bundlev1.LLMRole_LLM_ROLE_SYSTEM:    llm.RoleSystem,
	bundlev1.LLMRole_LLM_ROLE_DEVELOPER: llm.RoleDeveloper,
	bundlev1.LLMRole_LLM_ROLE_USER:      llm.RoleUser,
	bundlev1.LLMRole_LLM_ROLE_ASSISTANT: llm.RoleAssistant,
	bundlev1.LLMRole_LLM_ROLE_TOOL:      llm.RoleTool,
}

// llmConfig is a policy's LLM endpoints, as the pipeline takes them; nil
// for none. bodies: the policy's rules read bodies (body.inspect). Its
// exclusions of the LLM checks' rule IDs, with a path or none (not those
// narrowed to an argument, a cookie or a header), turn those checks off.
func llmConfig(bp *bundlev1.Policy, bodies bool, metrics *llm.Metrics) *pipeline.LLMConfig {
	l := bp.GetLlm()
	if l == nil {
		return nil
	}
	cfg := &pipeline.LLMConfig{MaxBodyBytes: min(l.GetMaxBodyBytes(), MaxBodyBytes), RuleSetBody: l.GetRuleSetBody(),
		RulesReadBodies: bodies, Metrics: metrics}
	for _, e := range l.GetEndpoints() {
		cfg.Endpoints = append(cfg.Endpoints, pipeline.LLMEndpoint{Paths: e.GetPaths(), Format: llmFormats[e.GetFormat()]})
	}
	if rc := l.GetRequest(); rc != nil {
		c := llm.Config{Models: rc.GetModels(), MaxPromptBytes: rc.GetMaxPromptBytes(), MaxMessages: rc.GetMaxMessages(),
			MaxOutputTokens: rc.GetMaxOutputTokens(), RequireOutputTokens: rc.GetRequireOutputTokens(), MaxChoices: rc.GetMaxChoices()}
		for _, ro := range rc.GetClientRoles() {
			if r, ok := llmRoles[ro]; ok {
				c.ClientRoles = append(c.ClientRoles, r)
			}
		}
		switch rc.GetTools() {
		case bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_NONE:
			c.Tools = llm.ToolsNone
		case bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_LISTED:
			c.Tools, c.ToolNames = llm.ToolsListed, rc.GetToolNames()
		case bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_UNSPECIFIED:
		default:
			// Of a newer operator: allow none, the strictest.
			c.Tools = llm.ToolsNone
		}
		cfg.Checks, cfg.Detect = c, rc.GetDetect()
	}
	for _, e := range bp.GetExclusions() {
		if e.GetArgument() != "" || e.GetArgumentName() != "" || e.GetCookie() != "" || e.GetHeader() != "" {
			continue // narrowed to a part of the request, which the checks don't read by
		}
		var checks llm.CheckSet
		for _, id := range e.GetRuleIds() {
			if c, ok := llm.CheckOf(int(id)); ok {
				checks = checks.With(c)
			}
		}
		if checks != 0 {
			cfg.Exclusions = append(cfg.Exclusions, pipeline.LLMExclusion{Path: e.GetPath(), Checks: checks})
		}
	}
	return cfg
}

// rateLimits is a policy's rate limits, as the pipeline takes them.
func rateLimits(bp *bundlev1.Policy) []pipeline.RateLimitConfig {
	var out []pipeline.RateLimitConfig
	for _, l := range bp.GetRateLimits() {
		c := pipeline.RateLimitConfig{
			Name:       l.GetName(),
			Requests:   int64(l.GetRequests()),
			Period:     l.GetPeriod().AsDuration(),
			Burst:      int64(l.GetBurst()),
			Header:     l.GetKey().GetHeader().GetName(),
			IPv6Prefix: int(l.GetKey().GetClientIp().GetIpv6PrefixLength()),
			Paths:      l.GetPaths(),
			Methods:    l.GetMethods(),
			Detect:     l.GetDetect(),
		}
		out = append(out, c)
	}
	return out
}
