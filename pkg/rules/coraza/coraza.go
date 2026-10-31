// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package coraza implements rules.Evaluator with OWASP Coraza and the OWASP
// Core Rule Set (CRS), which is embedded in the binary.
package coraza

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// Defaults follow CRS recommendations for a first deployment.
const (
	DefaultParanoiaLevel           = 1
	DefaultInboundAnomalyThreshold = 5
	// DefaultMaxArgs matches Coraza's own default argument limit.
	DefaultMaxArgs = 1000
)

// RuleGroups maps the CRS attack families that can be disabled to their
// rule ID prefix. Disabling a family the application cannot be vulnerable to
// (for example "php" for a Go service) removes its rules from every request.
var RuleGroups = map[string]int{
	"scanner":          913,
	"lfi":              930,
	"rfi":              931,
	"rce":              932,
	"php":              933,
	"generic":          934, // Node.js, Ruby, Perl, SSRF and other generic attacks
	"xss":              941,
	"sqli":             942,
	"session-fixation": 943,
	"java":             944,
}

// Config configures the evaluator.
type Config struct {
	// ParanoiaLevel is the CRS blocking paranoia level, 1 (default) to 4.
	// Higher levels detect more and produce more false positives.
	ParanoiaLevel int
	// InboundAnomalyThreshold is the CRS inbound anomaly score at which a
	// request is blocked. Defaults to 5 (one critical match).
	InboundAnomalyThreshold int
	// MaxArgs is the maximum number of arguments per source (query, body,
	// path). Requests with more are rejected with 400 by rules 200004
	// (phase 1) and 200005 (phase 2) before any CRS argument rule runs, so
	// padding a request with arguments is cheap to reject and cannot hide a
	// payload past the limit. Zero means DefaultMaxArgs.
	MaxArgs int
	// DirectivesBeforeCRS are SecLang directives loaded before CRS. CRS
	// runtime rule exclusions (rules using ctl:ruleRemoveById and similar)
	// must be placed here.
	DirectivesBeforeCRS string
	// Directives are SecLang directives loaded after CRS, for custom rules
	// and configure-time exclusions (SecRuleRemoveById, SecRuleUpdateTargetById).
	Directives string
	// BodyLimit, if positive, sets Coraza's request body limits
	// (SecRequestBodyLimit and SecRequestBodyInMemoryLimit) to the largest
	// body the caller will pass, so bodies within the caller's limit are
	// neither rejected by Coraza nor buffered to temporary files.
	BodyLimit int
	// DisabledRuleGroups lists CRS attack families (keys of RuleGroups) to
	// remove. Only disable families the protected application cannot be
	// vulnerable to.
	DisabledRuleGroups []string
	// DisableCRS loads only the directives, without the Core Rule Set.
	DisableCRS bool
	// Exclusions turn rules off, everywhere or for a path or an argument.
	// They are applied to each transaction, not compiled into the rules, so
	// they are not part of Key: Evaluator.WithExclusions gives configs that
	// differ only in exclusions one compiled rule set.
	Exclusions []Exclusion
	// OnMatch, if set, is called for every rule that matches and logs. It
	// runs on the request path and must be fast and safe for concurrent use.
	OnMatch func(types.MatchedRule)
}

// Key identifies the rules cfg compiles to: equal keys, equal rule sets.
// OnMatch and Exclusions are not part of it.
func (cfg Config) Key() [sha256.Size]byte {
	h := sha256.New()
	fmt.Fprintf(h, "pl=%d\nthreshold=%d\nargs=%d\nbody=%d\ncrs=%v\ngroups=%q\n",
		cfg.ParanoiaLevel, cfg.InboundAnomalyThreshold, cfg.MaxArgs, cfg.BodyLimit, !cfg.DisableCRS, cfg.DisabledRuleGroups)
	// Lengths first, so no text can pass for a boundary.
	fmt.Fprintf(h, "before=%d\n%s\nafter=%d\n%s", len(cfg.DirectivesBeforeCRS), cfg.DirectivesBeforeCRS, len(cfg.Directives), cfg.Directives)
	var k [sha256.Size]byte
	h.Sum(k[:0])
	return k
}

// Exclusion turns rules off where they cause false positives.
type Exclusion struct {
	// RuleIDs are the rules to turn off.
	RuleIDs []int
	// Path limits the exclusion to an exact path ("/search") or a prefix
	// ("/api/*"), in the router's syntax. Empty: every path.
	Path string
	// Argument limits it to one query or body argument (ARGS:<argument>),
	// in the rule and the rules chained to it. Empty: the whole rule.
	Argument string
}

// Paths and argument names end up inside SecLang directives: only plain
// characters, as the WAFPolicy CRD allows, so they can't change a directive.
var (
	exclusionPath     = regexp.MustCompile(`^/[A-Za-z0-9._~/:@!$&'()+,=-]*\*?$`)
	exclusionArgument = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)
)

// exclusions are compiled Exclusions. Coraza's ctl actions
// (ctl:ruleRemoveById, ctl:ruleRemoveTargetById) apply them to one
// transaction, before phase 1, so one compiled rule set serves policies with
// different exclusions. They are immutable once in an Evaluator.
type exclusions struct {
	// Everywhere: rules off, and arguments the rules don't look at.
	rules   []int
	targets []target
	paths   []pathExclusion
}

type target struct {
	rule int
	arg  string // lower case, as ctl:ruleRemoveTargetById stores it
}

// pathExclusion applies on a path. It is decided on REQUEST_FILENAME, as the
// SecRule it replaces was:
//
//	SecRule REQUEST_FILENAME "@streq <path>" "phase:1,t:none,ctl:..."
//	SecRule REQUEST_FILENAME "@beginsWith <prefix>" "phase:1,t:none,chain"
//	  SecRule REQUEST_FILENAME "!@rx (?:^|/)\.\.?(?:/|$)|//" "t:none,ctl:..."
type pathExclusion struct {
	path    string
	prefix  bool
	rules   []int
	targets []target
}

// dotSegments is the @rx above, with the (?sm) flags Coraza's @rx adds. A
// prefix exclusion only applies to a path without dot segments or empty
// segments: "/api/../admin" starts with "/api/" but a proxy routes it to
// "/admin", so it must not get /api's exclusions. An exact path can't
// contain them and still equal a clean path.
var dotSegments = regexp.MustCompile(`(?sm)(?:^|/)\.\.?(?:/|$)|//`)

func (p *pathExclusion) matches(filename string) bool {
	if p.prefix {
		return strings.HasPrefix(filename, p.path) && !dotSegments.MatchString(filename)
	}
	return filename == p.path
}

// setupRules are the phase 1 rules that ran before the path exclusion
// rules when those were compiled in (coraza.conf-recommended's body
// processor rules, the phase 1 argument limit, Inkwall's CRS settings).
// Their ctl actions came too late to turn these off, so a path exclusion
// still doesn't: a path can't, say, switch off JSON body parsing and with it
// the inspection of JSON arguments.
var setupRules = map[int]bool{
	200000: true, 200001: true, 200006: true, 200004: true,
	idParanoiaLevel: true, idAnomalyThreshold: true,
}

// compileExclusions checks and compiles exclusions.
func compileExclusions(list []Exclusion) (*exclusions, error) {
	x := &exclusions{}
	for i, e := range list {
		if len(e.RuleIDs) == 0 {
			return nil, fmt.Errorf("exclusion %d: no rule IDs", i)
		}
		for _, r := range e.RuleIDs {
			if r <= 0 {
				return nil, fmt.Errorf("exclusion %d: rule ID %d", i, r)
			}
		}
		if e.Path != "" && !exclusionPath.MatchString(e.Path) {
			return nil, fmt.Errorf("exclusion %d: path %q is not a plain path pattern", i, e.Path)
		}
		if e.Argument != "" && !exclusionArgument.MatchString(e.Argument) {
			return nil, fmt.Errorf("exclusion %d: argument %q has characters other than letters, digits and _.-[]", i, e.Argument)
		}
		ids, targets := &x.rules, &x.targets
		if e.Path != "" {
			path, prefix := strings.CutSuffix(e.Path, "*")
			x.paths = append(x.paths, pathExclusion{path: path, prefix: prefix})
			p := &x.paths[len(x.paths)-1]
			ids, targets = &p.rules, &p.targets
		}
		for _, r := range e.RuleIDs {
			switch {
			case e.Path != "" && setupRules[r]:
			case e.Argument == "":
				*ids = append(*ids, r)
			default:
				*targets = append(*targets, target{rule: r, arg: strings.ToLower(e.Argument)})
			}
		}
	}
	if len(x.rules) == 0 && len(x.targets) == 0 && len(x.paths) == 0 {
		return nil, nil
	}
	return x, nil
}

func (x *exclusions) hasTargets() bool {
	if x == nil {
		return false
	}
	if len(x.targets) > 0 {
		return true
	}
	for i := range x.paths {
		if len(x.paths[i].targets) > 0 {
			return true
		}
	}
	return false
}

// ruleRemover is what Coraza's ctl actions call on a transaction. Coraza
// doesn't export it in types.Transaction, but its transactions have it; New
// fails if they stop having it.
type ruleRemover interface {
	RemoveRuleByID(id int)
	RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string, keyRx *regexp.Regexp)
}

var errNoRuleRemoval = errors.New("this Coraza version's transactions can't turn rules off (RemoveRuleByID, RemoveRuleTargetByID)")

// apply turns the exclusions on for tx, after ProcessURI (which sets
// REQUEST_FILENAME) and before ProcessRequestHeaders (phase 1).
func (x *exclusions) apply(tx types.Transaction) error {
	rm, ok := tx.(ruleRemover)
	if !ok {
		return errNoRuleRemoval
	}
	remove := func(ids []int, targets []target) {
		for _, r := range ids {
			rm.RemoveRuleByID(r)
		}
		for _, t := range targets {
			rm.RemoveRuleTargetByID(t.rule, variables.Args, t.arg, nil)
		}
	}
	remove(x.rules, x.targets)
	if len(x.paths) == 0 {
		return nil
	}
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return errNoRuleRemoval
	}
	filename := st.Variables().RequestFilename().Get()
	for i := range x.paths {
		if p := &x.paths[i]; p.matches(filename) {
			remove(p.rules, p.targets)
		}
	}
	return nil
}

// argsNegation finds SecLang that negates ARGS targets itself
// ("ARGS|!ARGS:q", SecRuleUpdateTargetById 942100 "!ARGS:q"), conservatively.
// Coraza 3.8.1 adds a transaction's target exclusions
// (ctl:ruleRemoveTargetById) to the rule's own negations in place: when that
// slice has spare capacity, concurrent transactions overwrite each other's
// exclusions, and a request can get another request's. Rules from Inkwall and
// the CRS negate no ARGS targets, so their rules take target exclusions per
// transaction. Rules that do never do: a policy with argument exclusions gets
// rule sets of its own with them compiled in (argsVariants).
var argsNegation = regexp.MustCompile(`(?i)!\s*args`)

// Evaluator evaluates requests with a compiled Coraza WAF and its
// exclusions. It is safe for concurrent use.
type Evaluator struct {
	waf        coraza.WAF
	exclusions *exclusions // nil: none
	// base is the compiled rules without exclusions: waf, unless the
	// argument exclusions are compiled in (variants).
	base coraza.WAF
	// private is set when the rules negate ARGS targets themselves
	// (argsNegation).
	private *privateRules
	// variants, if set, replace waf: the rules with the argument
	// exclusions compiled in.
	variants *argsVariants
}

// privateRules are rules that negate ARGS targets themselves.
type privateRules struct {
	cfg Config
	ids map[int]bool // the rules cfg compiles to
}

var _ rules.Evaluator = (*Evaluator)(nil)

// New compiles the rule set described by cfg.
func New(cfg Config) (*Evaluator, error) {
	list := cfg.Exclusions
	cfg.Exclusions = nil
	if _, err := compileExclusions(list); err != nil {
		return nil, err
	}
	var private *privateRules
	if argsNegation.MatchString(cfg.DirectivesBeforeCRS) || argsNegation.MatchString(cfg.Directives) {
		private = &privateRules{cfg: cfg, ids: map[int]bool{}}
	}
	var observe func(types.RuleMetadata)
	if private != nil {
		observe = func(r types.RuleMetadata) { private.ids[r.ID()] = true }
	}
	waf, err := compile(cfg, observe)
	if err != nil {
		return nil, err
	}
	if private != nil && len(private.ids) == 0 {
		return nil, errors.New("this Coraza version doesn't list the rules it compiles")
	}
	e := &Evaluator{waf: waf, base: waf, private: private}
	return e.WithExclusions(list)
}

func compile(cfg Config, observe func(types.RuleMetadata)) (coraza.WAF, error) {
	directives, err := buildDirectives(cfg)
	if err != nil {
		return nil, err
	}
	wafCfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives)
	if cfg.OnMatch != nil {
		wafCfg = wafCfg.WithErrorCallback(cfg.OnMatch)
	}
	if observe != nil {
		wafCfg = experimental.WAFConfigWithRuleObserver(wafCfg, observe)
	}
	waf, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	return waf, nil
}

// WithExclusions returns an evaluator with e's compiled rules and the
// exclusions list instead of e's. It compiles no rules, so policies that
// differ only in exclusions share one rule set; except when e's rules negate
// ARGS targets themselves and list excludes arguments (see argsNegation).
func (e *Evaluator) WithExclusions(list []Exclusion) (*Evaluator, error) {
	x, err := compileExclusions(list)
	if err != nil {
		return nil, err
	}
	ev := &Evaluator{waf: e.base, base: e.base, private: e.private}
	if e.private != nil && x.hasTargets() {
		if ev.variants, err = e.private.variants(x); err != nil {
			return nil, err
		}
		if len(x.rules) == 0 && len(x.paths) == 0 {
			x = nil
		}
	}
	if x != nil {
		tx := ev.waf.NewTransaction()
		_, ok := tx.(ruleRemover)
		_, hasState := tx.(plugintypes.TransactionState)
		_ = tx.Close()
		if !ok || !hasState {
			return nil, errNoRuleRemoval
		}
	}
	ev.exclusions = x
	return ev, nil
}

// argsVariants are the rule sets of a policy whose rules negate ARGS targets
// themselves (argsNegation) and that has argument exclusions. No argument
// exclusion is applied per transaction: each rule set has the ones
// everywhere and those of one set of path exclusions compiled in, as
// SecRuleUpdateTargetById after the user's rules (which, unlike
// ctl:ruleRemoveTargetById, leaves chained rules alone). A request gets the
// rule set for the path exclusions it is on.
type argsVariants struct {
	everywhere []target
	paths      []pathExclusion // those with argument exclusions
	wafs       map[string]coraza.WAF
}

// variants compiles the rule sets for x's argument exclusions, and takes
// them out of x.
func (p *privateRules) variants(x *exclusions) (*argsVariants, error) {
	v := &argsVariants{everywhere: x.targets, wafs: map[string]coraza.WAF{}}
	x.targets = nil
	for i := range x.paths {
		if px := &x.paths[i]; len(px.targets) > 0 {
			v.paths = append(v.paths, pathExclusion{path: px.path, prefix: px.prefix, targets: px.targets})
			px.targets = nil
		}
	}
	x.paths = slices.DeleteFunc(x.paths, func(px pathExclusion) bool { return len(px.rules) == 0 })
	// The sets of path exclusions a request can be on: none; those a path
	// equal to an exact one is on; and, for a clean path whose longest
	// matching prefix is a given one, that prefix and the shorter ones it
	// starts with.
	sets := [][]target{nil}
	for _, a := range v.paths {
		var set []target
		for _, b := range v.paths {
			if a.prefix && b.prefix && strings.HasPrefix(a.path, b.path) || !a.prefix && b.matches(a.path) {
				set = append(set, b.targets...)
			}
		}
		sets = append(sets, set)
	}
	for _, set := range sets {
		targets := v.targets(set)
		k := targetsKey(targets)
		if _, ok := v.wafs[k]; ok {
			continue
		}
		cfg := p.cfg
		var b strings.Builder
		b.WriteString(cfg.Directives)
		for _, t := range targets {
			// A rule that isn't there is ignored, as by
			// ctl:ruleRemoveTargetById.
			if p.ids[t.rule] {
				fmt.Fprintf(&b, "\nSecRuleUpdateTargetById %d \"!ARGS:%s\"", t.rule, t.arg)
			}
		}
		cfg.Directives = b.String()
		waf, err := compile(cfg, nil)
		if err != nil {
			return nil, err
		}
		v.wafs[k] = waf
	}
	return v, nil
}

// targets returns the exclusions everywhere and set, sorted and without
// duplicates.
func (v *argsVariants) targets(set []target) []target {
	all := append(slices.Clone(v.everywhere), set...)
	slices.SortFunc(all, func(a, b target) int {
		if a.rule != b.rule {
			return a.rule - b.rule
		}
		return strings.Compare(a.arg, b.arg)
	})
	return slices.Compact(all)
}

func targetsKey(targets []target) string {
	var b strings.Builder
	for _, t := range targets {
		fmt.Fprintf(&b, "%d|%s\n", t.rule, t.arg)
	}
	return b.String()
}

// waf returns the rule set for a request with REQUEST_FILENAME filename.
func (v *argsVariants) waf(filename string) (coraza.WAF, error) {
	var set []target
	for i := range v.paths {
		if v.paths[i].matches(filename) {
			set = append(set, v.paths[i].targets...)
		}
	}
	waf, ok := v.wafs[targetsKey(v.targets(set))]
	if !ok {
		return nil, fmt.Errorf("no rule set for the argument exclusions on %q", filename)
	}
	return waf, nil
}

// wafFor returns the rule set for r.
func (e *Evaluator) wafFor(r *request.Request) (coraza.WAF, error) {
	if e.variants == nil {
		return e.waf, nil
	}
	// REQUEST_FILENAME as Coraza decodes it, from a transaction that runs
	// no rules.
	tx := e.base.NewTransaction()
	tx.ProcessURI(r.RawURI, r.Method, r.Proto)
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		_ = tx.Close()
		return nil, errNoRuleRemoval
	}
	filename := st.Variables().RequestFilename().Get()
	_ = tx.Close()
	return e.variants.waf(filename)
}

func buildDirectives(cfg Config) (string, error) {
	pl := cfg.ParanoiaLevel
	if pl == 0 {
		pl = DefaultParanoiaLevel
	}
	if pl < 1 || pl > 4 {
		return "", fmt.Errorf("paranoia level %d out of range 1-4", pl)
	}
	threshold := cfg.InboundAnomalyThreshold
	if threshold == 0 {
		threshold = DefaultInboundAnomalyThreshold
	}
	if threshold < 1 {
		return "", fmt.Errorf("inbound anomaly threshold %d must be positive", threshold)
	}
	maxArgs := cfg.MaxArgs
	if maxArgs == 0 {
		maxArgs = DefaultMaxArgs
	}
	if maxArgs < 0 {
		return "", fmt.Errorf("max args %d must not be negative", cfg.MaxArgs)
	}
	var removeGroups []int
	for _, g := range cfg.DisabledRuleGroups {
		prefix, ok := RuleGroups[g]
		if !ok {
			return "", fmt.Errorf("unknown rule group %q (known: %s)", g, strings.Join(RuleGroupNames(), ", "))
		}
		removeGroups = append(removeGroups, prefix)
	}

	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	// Coraza drops arguments past SecArgumentsLimit from ARGS and relies on
	// rules 200004/200005 to reject such requests, but the
	// coraza.conf-recommended bundled with coraza-coreruleset lacks them, so
	// arguments past the limit were silently not inspected. The rules are
	// copied from Coraza 3.8.1's coraza.conf-recommended (Apache-2.0).
	fmt.Fprintf(&b, "SecArgumentsLimit %d\n", maxArgs)
	if cfg.BodyLimit > 0 {
		fmt.Fprintf(&b, "SecRequestBodyLimit %d\nSecRequestBodyInMemoryLimit %d\n", cfg.BodyLimit, cfg.BodyLimit)
	}
	b.WriteString(argumentLimitRules)
	// Enforce, and leave audit logging to Inkwall's own event pipeline.
	b.WriteString("SecRuleEngine On\n")
	b.WriteString("SecAuditEngine Off\n")
	// Coraza's regex prefilter (SecRxPreFilter) is deliberately left off: with
	// Coraza 3.8.1 it misses CRS regression tests 942220-2 and 932311-7. Only
	// re-enable it once the CRS suite (test/crs) passes with it on.
	if !cfg.DisableCRS {
		// Inkwall's CRS settings come before the user's pre-CRS directives so
		// that a user rule setting the same variables (globally or per path)
		// wins. They use Inkwall's own ID range, so users can keep CRS's
		// documented setup IDs (900000, 900110, ...).
		fmt.Fprintf(&b,
			"SecAction \"id:%d,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", idParanoiaLevel, pl)
		fmt.Fprintf(&b,
			"SecAction \"id:%d,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", idAnomalyThreshold, threshold)
	}
	if cfg.DirectivesBeforeCRS != "" {
		b.WriteString(cfg.DirectivesBeforeCRS)
		b.WriteString("\n")
	}
	if !cfg.DisableCRS {
		b.WriteString("Include @crs-setup.conf.example\n")
		b.WriteString("Include @owasp_crs/*.conf\n")
		for _, prefix := range removeGroups {
			fmt.Fprintf(&b, "SecRuleRemoveById %d000-%d999\n", prefix, prefix)
		}
	}
	if cfg.Directives != "" {
		b.WriteString(cfg.Directives)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Evaluate runs the request through phases 1 and 2 (headers and body).
func (e *Evaluator) Evaluate(_ context.Context, r *request.Request) (rules.Result, error) {
	waf, err := e.wafFor(r)
	if err != nil {
		return rules.Result{}, err
	}
	var tx types.Transaction
	if r.ID != "" {
		tx = waf.NewTransactionWithID(r.ID)
	} else {
		tx = waf.NewTransaction()
	}
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if tx.IsRuleEngineOff() {
		return rules.Result{}, nil
	}

	client := ""
	if r.ClientIP.IsValid() {
		client = r.ClientIP.String()
	}
	tx.ProcessConnection(client, 0, "", 0)
	tx.ProcessURI(r.RawURI, r.Method, r.Proto)
	if e.exclusions != nil {
		if err := e.exclusions.apply(tx); err != nil {
			return rules.Result{}, err
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(hostname(r.Host))
	}
	for name, values := range r.Headers {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return result(tx, it), nil
	}
	// A truncated body is never inspected: a prefix of JSON, XML or
	// multipart fails to parse (and rules 200002/200003 would deny it), and
	// the pipeline decides what happens to oversized bodies.
	if len(r.Body) > 0 && !r.BodyTruncated {
		it, _, err := tx.WriteRequestBody(r.Body)
		if err != nil {
			return rules.Result{}, fmt.Errorf("write request body: %w", err)
		}
		if it != nil {
			return result(tx, it), nil
		}
	}
	// Phase 2 runs even without a body: CRS evaluates the anomaly score there.
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return rules.Result{}, fmt.Errorf("process request body: %w", err)
	}
	return result(tx, it), nil
}

func result(tx types.Transaction, it *types.Interruption) rules.Result {
	var res rules.Result
	if it != nil {
		res.Interrupted = true
		res.Status = it.Status
		res.RuleID = it.RuleID
	}
	for _, mr := range tx.MatchedRules() {
		if !reportable(mr, it) {
			continue
		}
		id := mr.Rule().ID()
		res.MatchedRuleIDs = append(res.MatchedRuleIDs, id)
		// Where it matched: the first variable with data.
		for _, md := range mr.MatchedDatas() {
			if md.Variable().Name() == "UNKNOWN" {
				continue
			}
			variable := md.Variable().Name()
			if k := md.Key(); k != "" {
				variable += ":" + k
			}
			res.Matches = append(res.Matches, rules.Match{RuleID: id, Variable: variable, Value: md.Value()})
			break
		}
	}
	res.AnomalyScore = anomalyScore(tx)
	return res
}

// anomalyScore reads the CRS inbound anomaly score, which CRS sums in
// TX:blocking_inbound_anomaly_score (0 without CRS).
func anomalyScore(tx types.Transaction) int {
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return 0
	}
	vals := st.Variables().TX().Get("blocking_inbound_anomaly_score")
	if len(vals) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(vals[0])
	return n
}

// Inkwall's internal rules use IDs 7700000-7709999, outside the ranges CRS
// and Coraza use, so they never collide with user or CRS rules.
const (
	idParanoiaLevel    = 7700001
	idAnomalyThreshold = 7700002

	internalIDMin = 7700000
	internalIDMax = 7709999
	// crsIDMin and crsIDMax bound the IDs reserved for OWASP CRS.
	crsIDMin = 900000
	crsIDMax = 999999
	// corazaIDMin and corazaIDMax bound coraza.conf-recommended's rules.
	corazaIDMin = 200000
	corazaIDMax = 200099
)

// argumentLimitRules reject requests whose arguments exceed
// SecArgumentsLimit, from Coraza 3.8.1's coraza.conf-recommended.
const argumentLimitRules = `SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" \
    "id:'200004',phase:1,t:none,log,deny,status:400,msg:'Argument limit reached; request rejected (GET/PATH args)'"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" \
    "id:'200005',phase:2,t:none,log,deny,status:400,msg:'Argument limit reached; request rejected (POST args)'"
`

// RuleGroupNames returns the names in RuleGroups, sorted.
func RuleGroupNames() []string {
	return slices.Sorted(maps.Keys(RuleGroups))
}

// CRSRuleIDs returns the IDs of the embedded CRS's rules, sorted. Tools use
// it to expand ID ranges into exclusions.
var CRSRuleIDs = sync.OnceValues(func() ([]int, error) {
	var ids []int
	_, err := compile(Config{}, func(r types.RuleMetadata) {
		if inRange(r.ID(), crsIDMin, crsIDMax) {
			ids = append(ids, r.ID())
		}
	})
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("this Coraza version doesn't list the rules it compiles")
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
})

// reportable decides whether a matched rule is reported. CRS and Coraza
// setup, initialization and flow-control rules "match" on every request, so
// only these are reported:
//   - the rule that interrupted the request;
//   - detection rules, which carry a severity;
//   - custom rules (outside the CRS, Coraza and Inkwall ID ranges) that
//     matched request data, including rules that only add anomaly score.
//     SecAction directives match no variable ("UNKNOWN") and are skipped.
func reportable(mr types.MatchedRule, it *types.Interruption) bool {
	id := mr.Rule().ID()
	if it != nil && id == it.RuleID {
		return true
	}
	if hasSeverity(mr.Rule().Severity()) {
		return true
	}
	if inRange(id, crsIDMin, crsIDMax) || inRange(id, corazaIDMin, corazaIDMax) || inRange(id, internalIDMin, internalIDMax) {
		return false
	}
	for _, md := range mr.MatchedDatas() {
		if md.Variable().Name() != "UNKNOWN" {
			return true
		}
	}
	return false
}

func inRange(id, lo, hi int) bool { return id >= lo && id <= hi }

func hasSeverity(s types.RuleSeverity) bool {
	return s >= types.RuleSeverityEmergency && s <= types.RuleSeverityDebug
}

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
