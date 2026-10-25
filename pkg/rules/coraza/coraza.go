// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package coraza implements rules.Evaluator with OWASP Coraza and the OWASP
// Core Rule Set (CRS), which is embedded in the binary.
package coraza

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

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
	// They are rendered as SecLang after the Core Rule Set (everywhere, or
	// for an argument) or before it (for a path, decided per request).
	Exclusions []Exclusion
	// OnMatch, if set, is called for every rule that matches and logs. It
	// runs on the request path and must be fast and safe for concurrent use.
	OnMatch func(types.MatchedRule)
}

// Key identifies the rules cfg compiles to: equal keys, equal rule sets.
// OnMatch is not part of it.
func (cfg Config) Key() [sha256.Size]byte {
	h := sha256.New()
	fmt.Fprintf(h, "pl=%d\nthreshold=%d\nargs=%d\nbody=%d\ncrs=%v\ngroups=%q\n",
		cfg.ParanoiaLevel, cfg.InboundAnomalyThreshold, cfg.MaxArgs, cfg.BodyLimit, !cfg.DisableCRS, cfg.DisabledRuleGroups)
	for _, e := range cfg.Exclusions {
		fmt.Fprintf(h, "exclusion=%v|%q|%q\n", e.RuleIDs, e.Path, e.Argument)
	}
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
	// Argument limits it to one query or body argument. Empty: the whole
	// rule.
	Argument string
}

// Paths and argument names end up inside SecLang directives: only plain
// characters, as the WAFPolicy CRD allows, so they can't change a directive.
var (
	exclusionPath     = regexp.MustCompile(`^/[A-Za-z0-9._~/:@!$&'()+,=-]*\*?$`)
	exclusionArgument = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)
)

// renderExclusions returns the directives for exclusions: those loaded
// before CRS (decided per request) and after it (configure time).
func renderExclusions(exclusions []Exclusion) (before, after string, err error) {
	var b, a strings.Builder
	id := idExclusionMin
	for i, e := range exclusions {
		if len(e.RuleIDs) == 0 {
			return "", "", fmt.Errorf("exclusion %d: no rule IDs", i)
		}
		for _, r := range e.RuleIDs {
			if r <= 0 {
				return "", "", fmt.Errorf("exclusion %d: rule ID %d", i, r)
			}
		}
		if e.Path != "" && !exclusionPath.MatchString(e.Path) {
			return "", "", fmt.Errorf("exclusion %d: path %q is not a plain path pattern", i, e.Path)
		}
		if e.Argument != "" && !exclusionArgument.MatchString(e.Argument) {
			return "", "", fmt.Errorf("exclusion %d: argument %q has characters other than letters, digits and _.-[]", i, e.Argument)
		}
		switch {
		case e.Path == "" && e.Argument == "":
			a.WriteString("SecRuleRemoveById")
			for _, r := range e.RuleIDs {
				fmt.Fprintf(&a, " %d", r)
			}
			a.WriteString("\n")
		case e.Path == "":
			for _, r := range e.RuleIDs {
				fmt.Fprintf(&a, "SecRuleUpdateTargetById %d \"!ARGS:%s\"\n", r, e.Argument)
			}
		default:
			if id > idExclusionMax {
				return "", "", fmt.Errorf("more than %d path exclusions", idExclusionMax-idExclusionMin+1)
			}
			// REQUEST_FILENAME is the decoded path. A prefix exclusion only
			// applies to a path without dot segments or empty segments:
			// "/api/../admin" starts with "/api/" but a proxy routes it to
			// "/admin", so it must not get /api's exclusions. An exact path
			// can't contain them and still equal a clean path.
			if p, ok := strings.CutSuffix(e.Path, "*"); ok {
				fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@beginsWith %s\" \"id:%d,phase:1,pass,t:none,nolog,chain\"\n", p, id)
				b.WriteString("SecRule REQUEST_FILENAME \"!@rx (?:^|/)\\.\\.?(?:/|$)|//\" \"t:none")
			} else {
				fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@streq %s\" \"id:%d,phase:1,pass,t:none,nolog", e.Path, id)
			}
			for _, r := range e.RuleIDs {
				if e.Argument == "" {
					fmt.Fprintf(&b, ",ctl:ruleRemoveById=%d", r)
				} else {
					fmt.Fprintf(&b, ",ctl:ruleRemoveTargetById=%d;ARGS:%s", r, e.Argument)
				}
			}
			b.WriteString("\"\n")
			id++
		}
	}
	return b.String(), a.String(), nil
}

// Evaluator evaluates requests with a compiled Coraza WAF. It is safe for
// concurrent use.
type Evaluator struct {
	waf coraza.WAF
}

var _ rules.Evaluator = (*Evaluator)(nil)

// New compiles the rule set described by cfg.
func New(cfg Config) (*Evaluator, error) {
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
	waf, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	return &Evaluator{waf: waf}, nil
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
	exclBefore, exclAfter, err := renderExclusions(cfg.Exclusions)
	if err != nil {
		return "", err
	}
	b.WriteString(exclBefore)
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
	// After the user's rules, so exclusions apply to them too.
	b.WriteString(exclAfter)
	return b.String(), nil
}

// Evaluate runs the request through phases 1 and 2 (headers and body).
func (e *Evaluator) Evaluate(_ context.Context, r *request.Request) (rules.Result, error) {
	var tx types.Transaction
	if r.ID != "" {
		tx = e.waf.NewTransactionWithID(r.ID)
	} else {
		tx = e.waf.NewTransaction()
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
		if reportable(mr, it) {
			res.MatchedRuleIDs = append(res.MatchedRuleIDs, mr.Rule().ID())
		}
	}
	return res
}

// Inkwall's internal rules use IDs 7700000-7709999, outside the ranges CRS
// and Coraza use, so they never collide with user or CRS rules.
const (
	idParanoiaLevel    = 7700001
	idAnomalyThreshold = 7700002
	// Path exclusions, one rule each.
	idExclusionMin = 7701000
	idExclusionMax = 7709999

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
