// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// DefaultLLMBodyBytes is the body read on an LLM endpoint when the policy
// sets no limit (spec.llm.maxBodyBytes).
const DefaultLLMBodyBytes = 1 << 20

// MaxLLMEndpoints is the most endpoints a policy has.
const MaxLLMEndpoints = 8

// LLMConfig is a policy's LLM endpoints (design 0012): their request
// bodies are parsed and checked (pkg/llm) before the rules, which skip
// them unless RuleSetBody.
type LLMConfig struct {
	Endpoints []LLMEndpoint
	// MaxBodyBytes is the body read on an endpoint; 0: DefaultLLMBodyBytes.
	MaxBodyBytes int64
	// RuleSetBody gives the rules the endpoints' bodies too, request and
	// response, when RulesReadBodies.
	RuleSetBody bool
	// RulesReadBodies is whether the policy's rules read bodies at all
	// (body.inspect): the endpoints' are read for the LLM checks either
	// way.
	RulesReadBodies bool
	// Checks are the request checks.
	Checks llm.Config
	// Detect logs the requests that fail a check instead of denying them.
	Detect bool
	// Exclusions turn checks off (by their rule IDs), on a path or all.
	Exclusions []LLMExclusion
	// Metrics, if set, count the bodies read and the checks failed.
	Metrics *llm.Metrics
}

// LLMEndpoint is paths that serve one LLM API.
type LLMEndpoint struct {
	// Paths are exact paths or prefixes ending in "*", as rate limits'.
	Paths []string
	// Format is the API's; llm.FormatUnknown checks requests as every
	// format the engine knows.
	Format llm.Format
}

// LLMExclusion turns checks off on Path (an exact path or a prefix ending
// in "*", as exclusions' paths; empty: every path).
type LLMExclusion struct {
	Path   string
	Checks llm.CheckSet
}

// LLM is a policy's compiled LLM endpoints. It is immutable.
type LLM struct {
	endpoints []llmEndpoint
	// all are the formats of every endpoint: an ambiguous path is checked
	// as each.
	all       formatSet
	maxBody   int64
	rulesBody bool
	rules     *llm.Rules
	detect    bool
	off       llm.CheckSet
	pathOff   []llmPathOff
	metrics   *llm.Metrics
}

type llmEndpoint struct {
	paths   []limitPath
	formats formatSet
}

type llmPathOff struct {
	path   string
	prefix bool
	checks llm.CheckSet
}

// formatSet is a set of formats, by bit.
type formatSet uint8

// allFormats are the formats the engine knows.
var allFormats = func() (s formatSet) {
	for _, f := range llm.Formats {
		s |= 1 << f
	}
	return s
}()

// CompileLLM compiles a policy's LLM endpoints; nil for none.
func CompileLLM(cfg *LLMConfig) (*LLM, error) {
	if cfg == nil {
		return nil, nil
	}
	if len(cfg.Endpoints) == 0 || len(cfg.Endpoints) > MaxLLMEndpoints {
		return nil, fmt.Errorf("%d LLM endpoints, want 1 to %d", len(cfg.Endpoints), MaxLLMEndpoints)
	}
	rules, err := llm.Compile(cfg.Checks)
	if err != nil {
		return nil, fmt.Errorf("LLM checks: %w", err)
	}
	l := &LLM{maxBody: cfg.MaxBodyBytes, rulesBody: cfg.RuleSetBody && cfg.RulesReadBodies, rules: rules,
		detect: cfg.Detect, metrics: cfg.Metrics}
	if l.maxBody <= 0 {
		l.maxBody = DefaultLLMBodyBytes
	}
	seen := map[limitPath]bool{}
	for _, e := range cfg.Endpoints {
		ep := llmEndpoint{formats: 1 << e.Format}
		if e.Format == llm.FormatUnknown || e.Format > llm.Formats[len(llm.Formats)-1] {
			// A format of a newer operator: checked as every format known.
			ep.formats = allFormats
		}
		if len(e.Paths) == 0 {
			return nil, fmt.Errorf("an LLM endpoint without paths")
		}
		for _, p := range e.Paths {
			lp, err := compileLimitPath(p)
			if err != nil {
				return nil, fmt.Errorf("LLM endpoint: %w", err)
			}
			// The CRD makes paths unique across endpoints; the engine
			// doesn't trust the bundle for it.
			if seen[lp] {
				return nil, fmt.Errorf("LLM endpoint path %q twice", p)
			}
			seen[lp] = true
			ep.paths = append(ep.paths, lp)
		}
		l.all |= ep.formats
		l.endpoints = append(l.endpoints, ep)
	}
	for _, x := range cfg.Exclusions {
		if x.Path == "" {
			l.off |= x.Checks
			continue
		}
		path, prefix := strings.CutSuffix(x.Path, "*")
		l.pathOff = append(l.pathOff, llmPathOff{path: path, prefix: prefix, checks: x.Checks})
	}
	return l, nil
}

// formats returns the formats r is checked as, none for a path of no
// endpoint or a request that sends no body (a GET); see endpoint.
func (l *LLM) formats(r *request.Request) formatSet {
	f, _ := l.endpoint(r)
	return f
}

// endpoint returns the formats r is checked as, and whether its body is
// the LLM checks' alone (the rules skip it with ruleSetBody: Skip). A path
// that can't be read one way (percent-encoding, ";", "//", dot segments,
// fullwidth letters) is read every way an application or proxy may read
// it: it is checked as the formats of every reading that is an endpoint,
// and the rules keep its body unless every reading is one. A path no
// reading of which is an endpoint isn't one: the rules read its body as
// any route's. Of an exact path and prefixes that match, the exact one
// wins, then the longest prefix.
func (l *LLM) endpoint(r *request.Request) (formatSet, bool) {
	if l == nil {
		return 0, false
	}
	if len(r.Body) == 0 && !r.BodyTruncated {
		switch strings.ToUpper(r.Method) {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
			return 0, false
		}
	}
	path, ambiguous := limitPathOf(r.RawURI)
	if !ambiguous {
		f := l.match(path)
		return f, f != 0
	}
	var union formatSet
	every := true
	for _, reading := range pathReadings(r.RawURI) {
		f := l.match(reading)
		union |= f
		every = every && f != 0
	}
	return union, every && union != 0
}

// pathReadings are the ways a path that can't be read one way may be
// read, in lower case: as sent, percent-decoded once and twice, and each
// of those normalised (backslashes as slashes, ";" parameters dropped,
// fullwidth forms folded to ASCII, repeated slashes and dot segments
// resolved).
func pathReadings(rawURI string) []string {
	raw, _, _ := strings.Cut(rawURI, "?")
	bases := []string{raw}
	for b := raw; ; {
		d, err := url.PathUnescape(b)
		if err != nil || d == b || len(bases) == 3 {
			break
		}
		bases = append(bases, d)
		b = d
	}
	var out []string
	for _, b := range bases {
		out = append(out, strings.ToLower(b), strings.ToLower(normalPath(b)))
	}
	return out
}

// normalPath is p as a lenient application routes it.
func normalPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	var b strings.Builder
	param := false
	for _, c := range p {
		switch {
		case c == '/':
			param = false
		case c == ';':
			param = true
		case param:
			continue
		case c >= 0xFF01 && c <= 0xFF5E:
			c -= 0xFEE0
		}
		if !param {
			b.WriteRune(c)
		}
	}
	clean := path.Clean("/" + b.String())
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean
}

// match returns the formats of the endpoint path, a plain lower-case one,
// belongs to; none for no endpoint.
func (l *LLM) match(path string) formatSet {
	var best formatSet
	bestLen := -1
	for _, e := range l.endpoints {
		for _, lp := range e.paths {
			switch {
			case !lp.prefix && trimSlash(path) == lp.value:
				return e.formats
			case lp.prefix && strings.HasPrefix(path, lp.value) && len(lp.value) > bestLen:
				best, bestLen = e.formats, len(lp.value)
			}
		}
	}
	return best
}

// offFor returns the checks exclusions turn off for rawURI: those on every
// path, and those of the path, when it is plain (as for the rules'
// exclusions, an ambiguous path gets no path exclusion).
func (l *LLM) offFor(rawURI string) llm.CheckSet {
	off := l.off
	if len(l.pathOff) == 0 {
		return off
	}
	path, ok := router.UnambiguousPath(rawURI)
	if !ok {
		return off
	}
	for _, x := range l.pathOff {
		if x.prefix && strings.HasPrefix(path, x.path) || !x.prefix && path == x.path {
			off |= x.checks
		}
	}
	return off
}

// LLMVerdict is, with ReasonLLM, the LLM check a request failed, and
// where: never the prompt's text.
type LLMVerdict struct {
	Format llm.Format
	Check  llm.Check
	// Model is the model the request named, at most 128 bytes.
	Model string
	// MessageIndex is the message or tool the check is about, -1 for the
	// request or a top-level field; Role its role.
	MessageIndex int
	Role         llm.Role
	// Offset is where in the body the check failed.
	Offset int
	// EstimatedTokens are the request's tokens as charged at request time.
	EstimatedTokens int64
}

// encodedBody reports whether a request's body is encoded: the engine
// doesn't decode request bodies, so it can't parse one.
func encodedBody(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for c := range strings.SplitSeq(v, ",") {
			if c = strings.TrimSpace(c); c != "" && !strings.EqualFold(c, "identity") {
				return true
			}
		}
	}
	return false
}

// checkLLM parses r's body as each of formats and runs the checks of each:
// the first check failed, nil for none. A body must parse as every one of
// formats (more than one only for a path read several ways): the
// application may read it as any, and a body two parsers read differently
// is how a prompt gets past one.
func (l *LLM) checkLLM(r *request.Request, formats formatSet) *LLMVerdict {
	off := l.offFor(r.RawURI)
	var first llm.Format
	for _, f := range llm.Formats {
		if formats&(1<<f) != 0 {
			first = f
			break
		}
	}
	if encodedBody(r.Headers) {
		l.metrics.Read(first, llm.PhaseRequest, true, 0)
		if off.Has(llm.CheckMalformed) {
			return nil
		}
		return &LLMVerdict{Format: first, Check: llm.CheckMalformed, MessageIndex: -1}
	}
	var req llm.Request
	var found *LLMVerdict
	for _, f := range llm.Formats {
		if formats&(1<<f) == 0 {
			continue
		}
		start := time.Now()
		ok := llm.Parse(r.Body, f, &req)
		l.metrics.Read(f, llm.PhaseRequest, !ok, time.Since(start))
		fd := l.rules.Check(r.Body, &req, off)
		if fd.Check == llm.CheckNone {
			if ok && f == first {
				l.metrics.Tokens(llm.TokensEstimated, l.rules.EstimatedTokens(&req))
			}
			continue
		}
		if found == nil || found.Check != llm.CheckMalformed && fd.Check == llm.CheckMalformed {
			v := &LLMVerdict{Format: f, Check: fd.Check, MessageIndex: fd.MessageIndex, Role: fd.Role, Offset: fd.Offset}
			if ok {
				m := req.Model()
				v.Model = string(m[:min(len(m), 128)])
				v.EstimatedTokens = l.rules.EstimatedTokens(&req)
			}
			found = v
		}
	}
	return found
}

// LLMBodyLimit returns the body to read for r on one of the policy's LLM
// endpoints (spec.llm.maxBodyBytes), 0 for a request on none.
func (p *Pipeline) LLMBodyLimit(r *request.Request) int64 {
	if p.llm == nil {
		return 0
	}
	// No body yet: a request that sends one is read whatever its method.
	probe := *r
	probe.BodyTruncated = true
	if p.llm.formats(&probe) == 0 {
		return 0
	}
	return p.llm.maxBody
}

// llmSkipsBodies reports whether r is on an LLM endpoint whose bodies the
// rules don't read (ruleSetBody: Skip), its response's included.
func (p *Pipeline) llmSkipsBodies(r *request.Request) bool {
	if p.llm == nil || p.llm.rulesBody {
		return false
	}
	_, alone := p.llm.endpoint(r)
	return alone
}

// llmVerdict is the verdict of a request that failed an LLM check in
// block mode: deny, with the check's status.
func (p *Pipeline) llmVerdict(lv *LLMVerdict, action Action) Verdict {
	id := lv.Check.RuleID()
	v := Verdict{Action: action, Reason: ReasonLLM, LLM: lv, RuleIDs: []int{id},
		Matches: []rules.Match{{RuleID: id, Variable: "LLM"}}}
	if action == ActionDeny {
		v.Status, v.InterruptingRuleID = lv.Check.Status(), id
	}
	action2 := llm.ActionLog
	if action == ActionDeny {
		action2 = llm.ActionDeny
	}
	p.llm.metrics.Failed(lv.Check, action2)
	return v
}

// llmDetected adds lv, a check a request failed in detect mode (or on a
// request.mode: Detect policy), to v, the rules' verdict, when nothing
// else decided it.
func (p *Pipeline) llmDetected(v Verdict, lv *LLMVerdict) Verdict {
	if lv == nil {
		return v
	}
	if v.Reason != ReasonNone {
		p.llm.metrics.Failed(lv.Check, llm.ActionLog)
		return v
	}
	d := p.llmVerdict(lv, ActionLog)
	v.Action, v.Reason, v.LLM = ActionLog, ReasonLLM, lv
	v.RuleIDs = append(v.RuleIDs, d.RuleIDs...)
	v.Matches = append(v.Matches, d.Matches...)
	return v
}
