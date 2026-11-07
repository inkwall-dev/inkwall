// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package coraza implements rules.Evaluator with OWASP Coraza and the OWASP
// Core Rule Set (CRS), which is embedded in the binary.
package coraza

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
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
	"github.com/inkwall-dev/inkwall/pkg/router"
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
	// Higher levels detect more and produce more false positives. It is set
	// on each transaction (CRSSettings), so it is not part of Key.
	ParanoiaLevel int
	// InboundAnomalyThreshold is the CRS inbound anomaly score at which a
	// request is blocked. Defaults to 5 (one critical match). Set on each
	// transaction, as ParanoiaLevel.
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
	// (SecRequestBodyLimit and SecRequestBodyInMemoryLimit) above the
	// largest body the caller will pass, so bodies within the caller's limit
	// are neither rejected by Coraza nor buffered to temporary files. It is
	// compiled in, so callers that enforce their own limits (as policies do)
	// should pass the largest of them all, for one rule set.
	BodyLimit int
	// ResponseBodyLimit, if positive, sets Coraza's response body limit
	// (SecResponseBodyLimit) above the largest response body the caller
	// will pass, so the whole of it is inspected. Compiled in, as BodyLimit.
	ResponseBodyLimit int
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
// OnMatch, Exclusions and the CRS settings (CRS) are not part of it: they
// are applied to each transaction.
func (cfg Config) Key() [sha256.Size]byte {
	h := sha256.New()
	fmt.Fprintf(h, "args=%d\nbody=%d\nresponse=%d\ncrs=%v\ngroups=%q\n",
		cfg.MaxArgs, cfg.BodyLimit, cfg.ResponseBodyLimit, !cfg.DisableCRS, cfg.DisabledRuleGroups)
	// Lengths first, so no text can pass for a boundary.
	fmt.Fprintf(h, "before=%d\n%s\nafter=%d\n%s", len(cfg.DirectivesBeforeCRS), cfg.DirectivesBeforeCRS, len(cfg.Directives), cfg.Directives)
	var k [sha256.Size]byte
	h.Sum(k[:0])
	return k
}

// CRS returns cfg's CRS settings, with the CRS's defaults for those Config
// doesn't have (Evaluator.WithCRS sets them).
func (cfg Config) CRS() CRSSettings {
	return CRSSettings{ParanoiaLevel: cfg.ParanoiaLevel, InboundAnomalyThreshold: cfg.InboundAnomalyThreshold}
}

// CRSSettings are the CRS's own settings, as TX variables. They are set on
// each transaction before phase 1, not compiled into the rules: the CRS's
// initialization (REQUEST-901) only sets the variables still unset, so one
// compiled rule set serves every value, and SecLang that sets them (before
// or after the CRS, globally or per path) still wins, as it runs later.
// Zero values are the defaults.
type CRSSettings struct {
	// ParanoiaLevel is tx.blocking_paranoia_level, 1 (default) to 4.
	ParanoiaLevel int
	// InboundAnomalyThreshold is tx.inbound_anomaly_score_threshold,
	// DefaultInboundAnomalyThreshold by default.
	InboundAnomalyThreshold int
	// AllowedMethods is tx.allowed_methods: the request methods rule 911100
	// allows, instead of the CRS's GET, HEAD, POST and OPTIONS. Empty: the
	// CRS's.
	AllowedMethods []string
	// AllowedRequestContentTypes is tx.allowed_request_content_type: the
	// media types (without parameters) rule 920420 allows, instead of the
	// CRS's. Empty: the CRS's. Compared case-insensitively.
	AllowedRequestContentTypes []string
	// DetectionParanoiaLevel is tx.detection_paranoia_level: the rules above
	// ParanoiaLevel and up to it run and score, but never block; a request
	// they would have blocked is Result.Detected. 0: ParanoiaLevel.
	DetectionParanoiaLevel int
	// OutboundAnomalyThreshold is tx.outbound_anomaly_score_threshold, the
	// response anomaly score at which a response is blocked. 0: the CRS's
	// (4).
	OutboundAnomalyThreshold int
}

// MaxCRSListItems bounds AllowedMethods and AllowedRequestContentTypes.
const MaxCRSListItems = 64

var (
	// methodToken is an HTTP method (RFC 9110 token) of up to 32
	// characters, without "|", which the CRS's lists use as a delimiter.
	methodToken = regexp.MustCompile("^[!#$%&'*+.^_`~0-9A-Za-z-]{1,32}$")
	// mediaType is a type/subtype (RFC 9110), without parameters or "|".
	mediaType = regexp.MustCompile("^[!#$%&'*+.^_`~0-9A-Za-z-]{1,64}/[!#$%&'*+.^_`~0-9A-Za-z-]{1,64}$")
)

// Validate checks s as the engine does: the webhook refuses what an engine
// would.
func (s CRSSettings) Validate() error {
	_, err := s.vars()
	return err
}

// txVar is a TX variable set on each transaction.
type txVar struct{ name, value string }

// vars checks s and returns its TX variables.
func (s CRSSettings) vars() ([]txVar, error) {
	pl := cmp.Or(s.ParanoiaLevel, DefaultParanoiaLevel)
	if pl < 1 || pl > 4 {
		return nil, fmt.Errorf("paranoia level %d out of range 1-4", pl)
	}
	threshold := cmp.Or(s.InboundAnomalyThreshold, DefaultInboundAnomalyThreshold)
	if threshold < 1 {
		return nil, fmt.Errorf("inbound anomaly threshold %d must be positive", threshold)
	}
	vars := []txVar{
		{"blocking_paranoia_level", strconv.Itoa(pl)},
		{"inbound_anomaly_score_threshold", strconv.Itoa(threshold)},
	}
	if d := s.DetectionParanoiaLevel; d != 0 {
		if d < pl || d > 4 {
			return nil, fmt.Errorf("detection paranoia level %d out of range %d (the paranoia level) to 4", d, pl)
		}
		vars = append(vars, txVar{"detection_paranoia_level", strconv.Itoa(d)})
	}
	if t := s.OutboundAnomalyThreshold; t != 0 {
		if t < 1 {
			return nil, fmt.Errorf("outbound anomaly threshold %d must be positive", t)
		}
		vars = append(vars, txVar{"outbound_anomaly_score_threshold", strconv.Itoa(t)})
	}
	if len(s.AllowedMethods) > MaxCRSListItems || len(s.AllowedRequestContentTypes) > MaxCRSListItems {
		return nil, fmt.Errorf("more than %d allowed methods or content types", MaxCRSListItems)
	}
	if len(s.AllowedMethods) > 0 {
		for _, m := range s.AllowedMethods {
			if !methodToken.MatchString(m) {
				return nil, fmt.Errorf("allowed method %q is not an HTTP method", m)
			}
		}
		// Rule 911100: REQUEST_METHOD "!@within %{tx.allowed_methods}".
		vars = append(vars, txVar{"allowed_methods", strings.Join(s.AllowedMethods, " ")})
	}
	if len(s.AllowedRequestContentTypes) > 0 {
		var b strings.Builder
		for i, t := range s.AllowedRequestContentTypes {
			if !mediaType.MatchString(t) {
				return nil, fmt.Errorf("allowed request content type %q is not a media type (type/subtype, without parameters)", t)
			}
			if i > 0 {
				b.WriteByte(' ')
			}
			// Rule 920420: "|type|", lower case, "@within" the list.
			b.WriteString("|" + strings.ToLower(t) + "|")
		}
		vars = append(vars, txVar{"allowed_request_content_type", b.String()})
	}
	return vars, nil
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
	// At most one of Argument, ArgumentName, Cookie and Header is set.
	Argument string
	// ArgumentName limits it to one argument's name (ARGS_NAMES:<name>).
	ArgumentName string
	// Cookie limits it to one request cookie (REQUEST_COOKIES:<name>).
	Cookie string
	// Header limits it to one request header (REQUEST_HEADERS:<name>).
	Header string
}

// target returns the collection and key e limits its rules to, "" for
// none.
func (e Exclusion) target() (variableName, string, error) {
	var v variableName
	var key string
	n := 0
	for _, c := range []struct {
		v     variableName
		value string
	}{{varArgs, e.Argument}, {varArgsNames, e.ArgumentName}, {varCookies, e.Cookie}, {varHeaders, e.Header}} {
		if c.value != "" {
			v, key = c.v, c.value
			n++
		}
	}
	switch {
	case n > 1:
		return "", "", errors.New("more than one of argument, argument name, cookie and header")
	case n == 1 && !exclusionName.MatchString(key):
		return "", "", fmt.Errorf("%s %q has characters other than letters, digits and _.-[]", v.what(), key)
	}
	return v, key, nil
}

// Paths and names end up inside SecLang directives: only plain characters,
// as the WAFPolicy CRD allows, so they can't change a directive.
var (
	exclusionPath = regexp.MustCompile(`^/[A-Za-z0-9._~/:@!$&'()+,=-]*\*?$`)
	exclusionName = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)
)

// variableName is a collection an exclusion can name, as SecLang spells it.
type variableName string

const (
	varArgs      variableName = "ARGS"
	varArgsNames variableName = "ARGS_NAMES"
	varCookies   variableName = "REQUEST_COOKIES"
	varHeaders   variableName = "REQUEST_HEADERS"
)

func (v variableName) variable() variables.RuleVariable {
	switch v {
	case varArgsNames:
		return variables.ArgsNames
	case varCookies:
		return variables.RequestCookies
	case varHeaders:
		return variables.RequestHeaders
	}
	return variables.Args
}

func (v variableName) what() string {
	switch v {
	case varArgsNames:
		return "argument name"
	case varCookies:
		return "cookie"
	case varHeaders:
		return "header"
	}
	return "argument"
}

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
	rule     int
	variable variableName
	key      string // lower case, as Coraza compares keys
}

// pathExclusion applies on a path: a request path equal to path, or, for a
// prefix, starting with it. It is decided on the path as received, and only
// when that path is unambiguous (router.UnambiguousPath, as for skip paths):
// "/api/../admin", "/api/..;/admin", "/api/%2e%2e/admin" and
// "/api/%252e%252e/admin" start with "/api/" but a proxy or an application
// may route them to "/admin", so they get no exclusions of "/api/*". A path
// that isn't plain gets no path exclusion at all: more rules, never fewer.
type pathExclusion struct {
	path    string
	prefix  bool
	rules   []int
	targets []target
}

// matches reports whether p applies on a plain path from
// router.UnambiguousPath.
func (p *pathExclusion) matches(path string) bool {
	if p.prefix {
		return strings.HasPrefix(path, p.path)
	}
	return path == p.path
}

// exclusionRequestPath returns the path path exclusions are decided on, or "" when
// rawURI's path is ambiguous, which no path exclusion matches.
func exclusionRequestPath(rawURI string) string {
	p, _ := router.UnambiguousPath(rawURI)
	return p
}

// setupRules are the phase 1 rules that ran before the path exclusion
// rules when those were compiled in (coraza.conf-recommended's body
// processor rules, the phase 1 argument limit, Inkwall's CRS settings).
// Their ctl actions came too late to turn these off, so a path exclusion
// still doesn't: a path can't, say, switch off JSON body parsing and with it
// the inspection of JSON arguments.
var setupRules = map[int]bool{
	200000: true, 200001: true, 200006: true, 200004: true,
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
		variable, key, err := e.target()
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
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
			case key == "":
				*ids = append(*ids, r)
			default:
				*targets = append(*targets, target{rule: r, variable: variable, key: strings.ToLower(key)})
			}
		}
	}
	if len(x.rules) == 0 && len(x.targets) == 0 && len(x.paths) == 0 {
		return nil, nil
	}
	return x, nil
}

// empty reports whether x turns nothing off.
func (x *exclusions) empty() bool {
	return len(x.rules) == 0 && len(x.targets) == 0 && len(x.paths) == 0
}

// ruleRemover is what Coraza's ctl actions call on a transaction. Coraza
// doesn't export it in types.Transaction, but its transactions have it; New
// fails if they stop having it.
type ruleRemover interface {
	RemoveRuleByID(id int)
	RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string, keyRx *regexp.Regexp)
}

var (
	errNoRuleRemoval = errors.New("this Coraza version's transactions can't turn rules off (RemoveRuleByID, RemoveRuleTargetByID)")
	errNoTxState     = errors.New("this Coraza version's transactions don't expose their variables")
)

// apply turns the exclusions on for tx, a request for rawURI, before
// ProcessRequestHeaders (phase 1).
func (x *exclusions) apply(tx types.Transaction, rawURI string) error {
	rm, ok := tx.(ruleRemover)
	if !ok {
		return errNoRuleRemoval
	}
	remove := func(ids []int, targets []target) {
		for _, r := range ids {
			rm.RemoveRuleByID(r)
		}
		for _, t := range targets {
			rm.RemoveRuleTargetByID(t.rule, t.variable.variable(), t.key, nil)
		}
	}
	remove(x.rules, x.targets)
	path := exclusionRequestPath(rawURI)
	if path == "" {
		return nil
	}
	for i := range x.paths {
		if p := &x.paths[i]; p.matches(path) {
			remove(p.rules, p.targets)
		}
	}
	return nil
}

// negationPatterns find SecLang that negates targets of a collection itself
// ("REQUEST_HEADERS|!REQUEST_HEADERS:Referer", SecRuleUpdateTargetById 942100
// "!ARGS:q"), conservatively (ARGS covers ARGS_NAMES and ARGS_GET...).
// Coraza 3.8.1 adds a transaction's target exclusions
// (ctl:ruleRemoveTargetById) to the rule's own negations of that collection
// in place: when that slice has spare capacity, concurrent transactions
// overwrite each other's exclusions, and a request can get another request's.
// So a target exclusion is applied per transaction only on a rule that
// negates nothing of its collection; on one that does, a policy gets rule
// sets of its own with it compiled in (targetVariants). Which CRS rules
// negate what is parsed from its files (crsNegations); any negation of a
// collection in the user's SecLang counts for every rule.
var negationPatterns = map[variableName]*regexp.Regexp{
	varArgs:      regexp.MustCompile(`(?i)!\s*args`),
	varArgsNames: regexp.MustCompile(`(?i)!\s*args`),
	varCookies:   regexp.MustCompile(`(?i)!\s*request_cookies`),
	varHeaders:   regexp.MustCompile(`(?i)!\s*request_headers`),
}

// ruleMetadata is what Coraza tells of each rule it compiles.
type ruleMetadata = types.RuleMetadata

// negations are the rules that negate targets of each collection
// themselves.
type negations struct {
	// all: every rule may (the user's SecLang negates the collection).
	all   map[variableName]bool
	rules map[variableName]map[int]bool
}

// has reports whether t's rule negates targets of t's collection.
func (n *negations) has(t target) bool {
	return n.all[t.variable] || n.rules[t.variable][t.rule]
}

// userNegations are the collections the user's SecLang negates anywhere. An
// Include may load anything: every collection.
func userNegations(cfg Config) map[variableName]bool {
	all := map[variableName]bool{}
	text := cfg.DirectivesBeforeCRS + "\n" + cfg.Directives
	include := regexp.MustCompile(`(?im)^\s*Include\b`).MatchString(text)
	for v, rx := range negationPatterns {
		all[v] = include || rx.MatchString(text)
	}
	return all
}

// crsNegations parses the CRS and coraza.conf-recommended for the rules
// that negate each collection. A chained rule's negations count for the
// rule that starts the chain, as Coraza applies its target exclusions to the
// whole chain.
var crsNegations = sync.OnceValues(func() (*negations, error) {
	n := &negations{rules: map[variableName]map[int]bool{}}
	for v := range negationPatterns {
		n.rules[v] = map[int]bool{}
	}
	id := regexp.MustCompile(`\bid:'?(\d+)`)
	err := fs.WalkDir(coreruleset.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") && !strings.HasSuffix(path, ".example") && !strings.HasSuffix(path, "-recommended") {
			return err
		}
		data, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}
		parent := 0
		for _, directive := range seclangDirectives(string(data)) {
			name, rest, _ := strings.Cut(directive, " ")
			var ids []int
			switch strings.ToLower(name) {
			case "secrule", "secaction":
				if m := id.FindStringSubmatch(directive); m != nil {
					parent, _ = strconv.Atoi(m[1])
				}
				ids = []int{parent}
			case "secruleupdatetargetbyid":
				// SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:..."
				// (or a range, 932240-932249).
				lo, hi, _ := strings.Cut(strings.Fields(rest)[0], "-")
				first, err1 := strconv.Atoi(lo)
				last, err2 := strconv.Atoi(cmp.Or(hi, lo))
				if err1 != nil || err2 != nil || last < first || last-first > 10000 {
					return fmt.Errorf("%s: can't read the rule IDs of %s", path, directive)
				}
				for r := first; r <= last; r++ {
					ids = append(ids, r)
				}
			}
			for v, rx := range negationPatterns {
				if !rx.MatchString(directive) {
					continue
				}
				if len(ids) == 0 || ids[0] == 0 {
					return fmt.Errorf("%s: a negation outside a rule Inkwall can name: %s", path, directive)
				}
				for _, r := range ids {
					n.rules[v][r] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse the CRS: %w", err)
	}
	return n, nil
})

// seclangDirectives splits SecLang into directives, joining continued
// lines and leaving out comments.
func seclangDirectives(text string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if cur.Len() == 0 && (t == "" || strings.HasPrefix(t, "#")) {
			continue
		}
		if c, ok := strings.CutSuffix(t, "\\"); ok {
			cur.WriteString(c + " ")
			continue
		}
		cur.WriteString(t)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Evaluator evaluates requests with a compiled Coraza WAF and its
// exclusions. It is safe for concurrent use.
type Evaluator struct {
	waf        coraza.WAF
	exclusions *exclusions // nil: none
	// base is the compiled rules without exclusions: waf, unless the
	// argument exclusions are compiled in (variants).
	base coraza.WAF
	// private is what compiling target exclusions in needs (nil only for
	// an Evaluator not made by New).
	private *privateRules
	// variants, if set, replace waf: the rules with the target exclusions
	// on rules that negate their collection compiled in.
	variants *targetVariants
	// crs is set when the rules include the CRS; tx are then the CRS
	// settings set on each transaction.
	crs bool
	tx  []txVar
}

// privateRules are what an Evaluator needs to compile target exclusions in.
type privateRules struct {
	cfg       Config
	ids       map[int]bool // the rules cfg compiles to
	negations *negations
}

var _ rules.Evaluator = (*Evaluator)(nil)

// New compiles the rule set described by cfg.
func New(cfg Config) (*Evaluator, error) {
	list := cfg.Exclusions
	cfg.Exclusions = nil
	if _, err := compileExclusions(list); err != nil {
		return nil, err
	}
	neg := &negations{all: userNegations(cfg)}
	if !cfg.DisableCRS {
		crs, err := crsNegations()
		if err != nil {
			return nil, err
		}
		neg.rules = crs.rules
	}
	private := &privateRules{cfg: cfg, ids: map[int]bool{}, negations: neg}
	waf, err := compile(cfg, func(r types.RuleMetadata) { private.ids[r.ID()] = true })
	if err != nil {
		return nil, err
	}
	if len(private.ids) == 0 && (cfg.Directives != "" || cfg.DirectivesBeforeCRS != "" || !cfg.DisableCRS) {
		return nil, errors.New("this Coraza version doesn't list the rules it compiles")
	}
	e := &Evaluator{waf: waf, base: waf, private: private, crs: !cfg.DisableCRS}
	if e.crs {
		tx := waf.NewTransaction()
		_, ok := tx.(plugintypes.TransactionState)
		_ = tx.Close()
		if !ok {
			return nil, errNoTxState
		}
	}
	if e, err = e.WithCRS(cfg.CRS()); err != nil {
		return nil, err
	}
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
// differ only in exclusions share one rule set; except for target exclusions
// on rules that negate their collection themselves (see negationPatterns).
func (e *Evaluator) WithExclusions(list []Exclusion) (*Evaluator, error) {
	x, err := compileExclusions(list)
	if err != nil {
		return nil, err
	}
	ev := &Evaluator{waf: e.base, base: e.base, private: e.private, crs: e.crs, tx: e.tx}
	if e.private != nil && x != nil {
		if ev.variants, err = e.private.variants(x); err != nil {
			return nil, err
		}
		if x.empty() {
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

// WithCRS returns an evaluator with e's rules and exclusions and the CRS
// settings s instead of e's. It compiles nothing: policies that differ only in
// their CRS settings share one rule set. Without the CRS, s is checked and
// has no effect.
func (e *Evaluator) WithCRS(s CRSSettings) (*Evaluator, error) {
	vars, err := s.vars()
	if err != nil {
		return nil, err
	}
	ev := *e
	ev.tx = nil
	if e.crs {
		ev.tx = vars
	}
	return &ev, nil
}

// setCRS sets the CRS settings on tx, before phase 1.
func (e *Evaluator) setCRS(tx types.Transaction) error {
	if len(e.tx) == 0 {
		return nil
	}
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return errNoTxState
	}
	m := st.Variables().TX()
	for _, v := range e.tx {
		m.Set(v.name, []string{v.value})
	}
	return nil
}

// targetVariants are the rule sets of a policy with target exclusions on
// rules that negate their collection themselves (see negationPatterns).
// Those exclusions are not applied per transaction: each rule set has the
// ones everywhere and those of one set of path exclusions compiled in, as
// SecRuleUpdateTargetById after the user's rules (which, unlike
// ctl:ruleRemoveTargetById, leaves chained rules alone). A request gets the
// rule set for the path exclusions it is on. The other target exclusions
// are still applied per transaction.
type targetVariants struct {
	everywhere []target
	paths      []pathExclusion // those with such target exclusions
	wafs       map[string]coraza.WAF
}

// variants compiles the rule sets for x's target exclusions on rules that
// negate their collection, and takes those out of x; nil if it has none.
func (p *privateRules) variants(x *exclusions) (*targetVariants, error) {
	// Most policies have no such exclusion: find out without allocating.
	needed := slices.ContainsFunc(x.targets, p.negations.has)
	for i := 0; !needed && i < len(x.paths); i++ {
		needed = slices.ContainsFunc(x.paths[i].targets, p.negations.has)
	}
	if !needed {
		return nil, nil
	}
	split := func(ts []target) (keep, out []target) {
		for _, t := range ts {
			if p.negations.has(t) {
				out = append(out, t)
			} else {
				keep = append(keep, t)
			}
		}
		return keep, out
	}
	v := &targetVariants{wafs: map[string]coraza.WAF{}}
	x.targets, v.everywhere = split(x.targets)
	for i := range x.paths {
		px := &x.paths[i]
		var out []target
		if px.targets, out = split(px.targets); len(out) > 0 {
			v.paths = append(v.paths, pathExclusion{path: px.path, prefix: px.prefix, targets: out})
		}
	}
	if len(v.everywhere) == 0 && len(v.paths) == 0 {
		return nil, nil
	}
	x.paths = slices.DeleteFunc(x.paths, func(px pathExclusion) bool { return len(px.rules) == 0 && len(px.targets) == 0 })
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
				fmt.Fprintf(&b, "\nSecRuleUpdateTargetById %d \"!%s:%s\"", t.rule, t.variable, t.key)
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
func (v *targetVariants) targets(set []target) []target {
	all := append(slices.Clone(v.everywhere), set...)
	slices.SortFunc(all, func(a, b target) int {
		if a.rule != b.rule {
			return a.rule - b.rule
		}
		if a.variable != b.variable {
			return strings.Compare(string(a.variable), string(b.variable))
		}
		return strings.Compare(a.key, b.key)
	})
	return slices.Compact(all)
}

func targetsKey(targets []target) string {
	var b strings.Builder
	for _, t := range targets {
		fmt.Fprintf(&b, "%d|%s|%s\n", t.rule, t.variable, t.key)
	}
	return b.String()
}

// waf returns the rule set for a request with path, from
// exclusionRequestPath ("" matches no path exclusion).
func (v *targetVariants) waf(path string) (coraza.WAF, error) {
	var set []target
	for i := range v.paths {
		if path != "" && v.paths[i].matches(path) {
			set = append(set, v.paths[i].targets...)
		}
	}
	waf, ok := v.wafs[targetsKey(v.targets(set))]
	if !ok {
		return nil, fmt.Errorf("no rule set for the argument exclusions on %q", path)
	}
	return waf, nil
}

// wafFor returns the rule set for r.
func (e *Evaluator) wafFor(r *request.Request) (coraza.WAF, error) {
	if e.variants == nil {
		return e.waf, nil
	}
	return e.variants.waf(exclusionRequestPath(r.RawURI))
}

func buildDirectives(cfg Config) (string, error) {
	if _, err := cfg.CRS().vars(); err != nil {
		return "", err
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
	// One byte over the limit, as Coraza rejects a body that reaches it.
	if cfg.BodyLimit > 0 {
		fmt.Fprintf(&b, "SecRequestBodyLimit %d\nSecRequestBodyInMemoryLimit %d\n", cfg.BodyLimit+1, cfg.BodyLimit+1)
	}
	// The response bodies the rules read are those the adapters buffer
	// (rules.ResponseBodyTypes): JSON and XML APIs too, not only
	// coraza.conf-recommended's text/plain, text/html and text/xml. One
	// byte over the limit, as Coraza flags a body that reaches it.
	fmt.Fprintf(&b, "SecResponseBodyMimeType %s\n", strings.Join(rules.ResponseBodyTypes, " "))
	if cfg.ResponseBodyLimit > 0 {
		fmt.Fprintf(&b, "SecResponseBodyLimit %d\n", cfg.ResponseBodyLimit+1)
	}
	b.WriteString(argumentLimitRules)
	// Enforce, and leave audit logging to Inkwall's own event pipeline.
	b.WriteString("SecRuleEngine On\n")
	// Detect mode with responses (EvaluateExchangeDetecting): the
	// transaction runs DetectionOnly, so a request the rules would
	// interrupt goes on to its response. The first phase 1 rule, so every
	// other one runs under it.
	fmt.Fprintf(&b, "SecRule TX:%s \"@eq 1\" \"id:%d,phase:1,pass,nolog,t:none,ctl:ruleEngine=DetectionOnly\"\n", txDetect, idDetect)
	b.WriteString("SecAuditEngine Off\n")
	// Coraza's regex prefilter (SecRxPreFilter) is deliberately left off: with
	// Coraza 3.8.1 it misses CRS regression tests 942220-2 and 932311-7. Only
	// re-enable it once the CRS suite (test/crs) passes with it on.
	// Inkwall's CRS settings aren't directives: they are set on each
	// transaction (CRSSettings), before any rule runs.
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
	res, tx, err := e.evaluate(r, false)
	if tx != nil {
		closeTx(tx)
	}
	return res, err
}

var _ rules.ExchangeEvaluator = (*Evaluator)(nil)

// EvaluateExchange implements rules.ExchangeEvaluator: the transaction
// stays open for the response, unless the request was interrupted.
func (e *Evaluator) EvaluateExchange(_ context.Context, r *request.Request) (rules.Result, rules.Exchange, error) {
	res, tx, err := e.evaluate(r, false)
	if err != nil || res.Interrupted || tx == nil {
		if tx != nil {
			closeTx(tx)
		}
		return res, nil, err
	}
	return res, &exchange{tx: tx, seen: len(tx.MatchedRules())}, nil
}

var _ rules.DetectingEvaluator = (*Evaluator)(nil)

// txDetect is the TX variable that runs a transaction DetectionOnly.
const txDetect = "inkwall_detect"

// EvaluateExchangeDetecting implements rules.DetectingEvaluator (#360): the
// transaction runs DetectionOnly, so the rules never interrupt it; the
// result reports the interruption they would have made (Coraza's first),
// and the exchange is kept for the response whatever the request scored.
// Rules keep running after that point, so a would-be interrupted request
// may list more matches than in block mode.
func (e *Evaluator) EvaluateExchangeDetecting(_ context.Context, r *request.Request) (rules.Result, rules.Exchange, error) {
	res, tx, err := e.evaluate(r, true)
	if err != nil || tx == nil {
		if tx != nil {
			closeTx(tx)
		}
		return res, nil, err
	}
	if tx.IsInterrupted() {
		// Interrupted all the same (a rule that sets the engine back On):
		// as EvaluateExchange.
		closeTx(tx)
		return res, nil, nil
	}
	return res, &exchange{tx: tx, seen: len(tx.MatchedRules()), detect: true}, nil
}

// detectionOnlyInterruption is the interruption a DetectionOnly
// transaction would have made, nil if none.
func detectionOnlyInterruption(tx types.Transaction) *types.Interruption {
	if d, ok := tx.(interface{ DetectionOnlyInterruption() *types.Interruption }); ok {
		return d.DetectionOnlyInterruption()
	}
	return nil
}

func closeTx(tx types.Transaction) {
	tx.ProcessLogging()
	_ = tx.Close()
}

// evaluate runs phases 1 and 2, and returns the transaction (nil if none
// was made), which the caller closes.
func (e *Evaluator) evaluate(r *request.Request, detect bool) (rules.Result, types.Transaction, error) {
	waf, err := e.wafFor(r)
	if err != nil {
		return rules.Result{}, nil, err
	}
	var tx types.Transaction
	if r.ID != "" {
		tx = waf.NewTransactionWithID(r.ID)
	} else {
		tx = waf.NewTransaction()
	}

	if tx.IsRuleEngineOff() {
		return rules.Result{}, tx, nil
	}

	client := ""
	if r.ClientIP.IsValid() {
		client = r.ClientIP.String()
	}
	tx.ProcessConnection(client, 0, "", 0)
	tx.ProcessURI(r.RawURI, r.Method, r.Proto)
	if err := e.setCRS(tx); err != nil {
		return rules.Result{}, tx, err
	}
	if detect {
		st, ok := tx.(plugintypes.TransactionState)
		if !ok {
			return rules.Result{}, tx, errNoTxState
		}
		st.Variables().TX().Set(txDetect, []string{"1"})
	}
	if e.exclusions != nil {
		if err := e.exclusions.apply(tx, r.RawURI); err != nil {
			return rules.Result{}, tx, err
		}
	}
	if r.GRPC {
		// The pipeline found a gRPC call: its content type is allowed, and
		// its body isn't inspected (below).
		rm, ok := tx.(ruleRemover)
		if !ok {
			return rules.Result{}, tx, errNoRuleRemoval
		}
		rm.RemoveRuleByID(idCRSContentType)
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
		return result(tx, it, 0, inbound), tx, nil
	}
	// A truncated body is never inspected: a prefix of JSON, XML or
	// multipart fails to parse (and rules 200002/200003 would deny it), and
	// the pipeline decides what happens to oversized bodies.
	// Nor is a gRPC call's: binary protobuf, which CRS would parse as a
	// form.
	for _, a := range r.GRPCText {
		tx.AddPostRequestArgument(a.Name, a.Value)
	}
	for _, a := range r.WebSocketText {
		tx.AddPostRequestArgument(a.Name, a.Value)
	}
	if len(r.Body) > 0 && !r.BodyTruncated && !r.GRPC {
		it, _, err := tx.WriteRequestBody(r.Body)
		if err != nil {
			return rules.Result{}, tx, fmt.Errorf("write request body: %w", err)
		}
		if it != nil {
			return result(tx, it, 0, inbound), tx, nil
		}
	}
	// Phase 2 runs even without a body: CRS evaluates the anomaly score there.
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return rules.Result{}, tx, fmt.Errorf("process request body: %w", err)
	}
	if detect && it == nil {
		it = detectionOnlyInterruption(tx)
	}
	return result(tx, it, 0, inbound), tx, nil
}

// exchange is a transaction kept open for the response.
type exchange struct {
	tx types.Transaction
	// seen is how many rules matched the request: the response's result
	// lists the others.
	seen int
	done bool
	// detect: the transaction runs DetectionOnly (EvaluateExchangeDetecting).
	detect bool
}

var errResponseTwice = errors.New("response evaluated twice")

// EvaluateResponse runs phases 3 and 4 (response headers and body). Phase 4
// runs even without a body: CRS evaluates the outbound anomaly score there.
// A truncated body is inspected, unlike a request's: data leakage rules
// read a prefix as well as the whole.
func (x *exchange) EvaluateResponse(_ context.Context, resp *request.Response) (rules.Result, error) {
	if x.done {
		return rules.Result{}, errResponseTwice
	}
	x.done = true
	tx := x.tx
	if tx.IsRuleEngineOff() {
		return rules.Result{}, nil
	}
	for name, values := range resp.Headers {
		for _, v := range values {
			tx.AddResponseHeader(name, v)
		}
	}
	if it := tx.ProcessResponseHeaders(resp.Status, resp.Proto); it != nil {
		return result(tx, it, x.seen, outbound), nil
	}
	if len(resp.Body) > 0 && tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
		it, _, err := tx.WriteResponseBody(resp.Body)
		if err != nil {
			return rules.Result{}, fmt.Errorf("write response body: %w", err)
		}
		if it != nil {
			return result(tx, it, x.seen, outbound), nil
		}
	}
	it, err := tx.ProcessResponseBody()
	if err != nil {
		return rules.Result{}, fmt.Errorf("process response body: %w", err)
	}
	if x.detect && it == nil {
		it = wouldInterrupt(tx, x.seen)
	}
	return result(tx, it, x.seen, outbound), nil
}

// wouldInterrupt is the interruption a rule that matched after the first
// skip would have made, in a DetectionOnly transaction: Coraza keeps only
// the first (the request's), and marks no matched rule disruptive then, so
// the response's is found among the matched rules by their disruptive
// action (deny, drop, redirect), as the CRS's outbound evaluation (959100)
// has. Nil if none.
func wouldInterrupt(tx types.Transaction, skip int) *types.Interruption {
	matched := tx.MatchedRules()
	for _, mr := range matched[min(skip, len(matched)):] {
		if disruptiveAction.MatchString(mr.Rule().Raw()) {
			return &types.Interruption{RuleID: mr.Rule().ID(), Action: "deny"}
		}
	}
	return nil
}

// disruptiveAction finds a disruptive action in a rule's SecLang.
var disruptiveAction = regexp.MustCompile(`(?i)[",]\s*'?(deny|drop|redirect)\b`)

// Close implements rules.Exchange.
func (x *exchange) Close() {
	if x.tx != nil {
		closeTx(x.tx)
		x.tx = nil
	}
}

// scores names the TX variables of a CRS anomaly score (0 without CRS):
// the one that blocks, the one at the detection paranoia level, and their
// threshold.
type scores struct{ blocking, detection, threshold string }

var (
	inbound  = scores{"blocking_inbound_anomaly_score", "detection_inbound_anomaly_score", "inbound_anomaly_score_threshold"}
	outbound = scores{"blocking_outbound_anomaly_score", "detection_outbound_anomaly_score", "outbound_anomaly_score_threshold"}
)

// result is the outcome of tx, with the rules that matched after the first
// skip and the anomaly score in TX:score.
func result(tx types.Transaction, it *types.Interruption, skip int, score scores) rules.Result {
	var res rules.Result
	if it != nil {
		res.Interrupted = true
		res.Status = it.Status
		res.RuleID = it.RuleID
	}
	matched := tx.MatchedRules()
	for _, mr := range matched[min(skip, len(matched)):] {
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
	res.AnomalyScore = txInt(tx, score.blocking)
	// Rules above the blocking paranoia level, up to the detection level,
	// would have blocked: detected. Only when the levels differ, so a rule
	// set that turned the blocking evaluation (949110) off isn't reported.
	res.Detected = it == nil && txInt(tx, "detection_paranoia_level") > txInt(tx, "blocking_paranoia_level") &&
		txInt(tx, score.threshold) > 0 && txInt(tx, score.detection) >= txInt(tx, score.threshold)
	return res
}

// txInt reads TX:name as an integer, 0 if unset.
func txInt(tx types.Transaction, name string) int {
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return 0
	}
	vals := st.Variables().TX().Get(name)
	if len(vals) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(vals[0])
	return n
}

// Inkwall's internal rules use IDs 7700000-7709999, outside the ranges CRS
// and Coraza use, so they never collide with user or CRS rules.
const (
	internalIDMin = 7700000
	// idDetect switches a transaction to DetectionOnly when TX:txDetect is
	// 1 (EvaluateExchangeDetecting).
	idDetect      = 7700010
	internalIDMax = 7709999
	// idCRSContentType is CRS's rule for content types the policy
	// doesn't allow (tx.allowed_request_content_type).
	idCRSContentType = 920420

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
