// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package coraza implements rules.Evaluator with OWASP Coraza and the OWASP
// Core Rule Set (CRS), which is embedded in the binary.
package coraza

import (
	"context"
	"fmt"
	"mime"
	"net"
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
)

// Config configures the evaluator.
type Config struct {
	// ParanoiaLevel is the CRS blocking paranoia level, 1 (default) to 4.
	// Higher levels detect more and produce more false positives.
	ParanoiaLevel int
	// InboundAnomalyThreshold is the CRS inbound anomaly score at which a
	// request is blocked. Defaults to 5 (one critical match).
	InboundAnomalyThreshold int
	// MaxArgs sets the CRS limit on the number of request arguments
	// (tx.max_num_args). Requests with more arguments match rule 920380, a
	// critical match that blocks at the default threshold. Zero leaves the
	// limit unset. Combined with a body size limit, it detects padding meant
	// to push a payload past what is inspected.
	MaxArgs int
	// Directives are extra SecLang directives loaded after CRS, for custom
	// rules and rule exclusions.
	Directives string
	// DisableCRS loads only Directives, without the Core Rule Set.
	DisableCRS bool
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
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
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
	if cfg.MaxArgs < 0 {
		return "", fmt.Errorf("max args %d must not be negative", cfg.MaxArgs)
	}

	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	// Enforce, and leave audit logging to Inkwall's own event pipeline.
	b.WriteString("SecRuleEngine On\n")
	b.WriteString("SecAuditEngine Off\n")
	b.WriteString("SecRxPreFilter On\n")
	if !cfg.DisableCRS {
		b.WriteString("Include @crs-setup.conf.example\n")
		fmt.Fprintf(&b,
			"SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", pl)
		fmt.Fprintf(&b,
			"SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", threshold)
		if cfg.MaxArgs > 0 {
			fmt.Fprintf(&b,
				"SecAction \"id:900300,phase:1,pass,t:none,nolog,setvar:tx.max_num_args=%d\"\n", cfg.MaxArgs)
		}
		b.WriteString("Include @owasp_crs/*.conf\n")
	}
	if cfg.Directives != "" {
		b.WriteString(cfg.Directives)
		b.WriteString("\n")
	}
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
	unparsablePrefix := r.BodyTruncated && needsCompleteBody(r.Headers.Get("Content-Type"))
	if len(r.Body) > 0 && !unparsablePrefix {
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
		// CRS setup, initialization and flow-control rules "match" on every
		// request; only detection rules carry a severity. The interrupting
		// rule is always reported. Custom rules need a severity to be
		// reported when they only contribute to a score.
		id := mr.Rule().ID()
		if !hasSeverity(mr.Rule().Severity()) && (it == nil || id != it.RuleID) {
			continue
		}
		res.MatchedRuleIDs = append(res.MatchedRuleIDs, id)
	}
	return res
}

// needsCompleteBody reports whether a body of this content type can only be
// parsed whole. A truncated JSON, XML or multipart prefix fails to parse, and
// the recommended rules then deny the request (rules 200002 and 200003), so
// such prefixes are not inspected at all. URL-encoded and plain-text
// prefixes are still inspected.
func needsCompleteBody(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch {
	case mt == "application/json", strings.HasSuffix(mt, "+json"),
		mt == "application/xml", mt == "text/xml", strings.HasSuffix(mt, "+xml"),
		strings.HasPrefix(mt, "multipart/"):
		return true
	}
	return false
}

func hasSeverity(s types.RuleSeverity) bool {
	return s >= types.RuleSeverityEmergency && s <= types.RuleSeverityDebug
}

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
