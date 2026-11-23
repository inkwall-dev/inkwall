// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Phase is what a metric counts: a request, or (later) a response.
type Phase uint8

const (
	// PhaseRequest is a request's body.
	PhaseRequest Phase = iota
	numPhases
)

func (p Phase) label() string { return "request" }

// Action is what became of a request that failed a check.
type Action uint8

const (
	// ActionDeny is a request denied.
	ActionDeny Action = iota
	// ActionLog is a request logged and let through (Detect).
	ActionLog
	numActions
)

func (a Action) label() string {
	if a == ActionDeny {
		return "deny"
	}
	return "log"
}

// TokenKind is what inkwall_llm_tokens_total counts.
type TokenKind uint8

const (
	// TokensEstimated are the tokens charged at request time.
	TokensEstimated TokenKind = iota
	// TokensSettledInput and TokensSettledOutput are the tokens a response
	// reported using.
	TokensSettledInput
	// TokensSettledOutput are the output tokens a response reported.
	TokensSettledOutput
	numTokenKinds
)

func (k TokenKind) label() string {
	switch k {
	case TokensSettledInput:
		return "settled_input"
	case TokensSettledOutput:
		return "settled_output"
	}
	return "estimated"
}

// Metrics are the LLM checks' metrics, labelled only by bounded values:
// the format, the phase, the check, the action. Its methods are safe for
// concurrent use and don't allocate; a nil Metrics records nothing.
type Metrics struct {
	requests  [numFormats][numPhases]prometheus.Counter
	malformed [numFormats][numPhases]prometheus.Counter
	checks    [numChecks][numActions]prometheus.Counter
	tokens    [numTokenKinds]prometheus.Counter
	inspect   [numPhases]prometheus.Observer

	collectors []prometheus.Collector
}

// NewMetrics returns the metrics, to register (Collectors).
func NewMetrics() *Metrics {
	m := &Metrics{}
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_llm_requests_total",
		Help: "Requests (and responses) read on the policies' LLM endpoints (spec.llm), by format and phase.",
	}, []string{"format", "phase"})
	malformed := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_llm_malformed_total",
		Help: "Bodies on LLM endpoints the parser refused (llm-malformed): invalid JSON or UTF-8, too deep, a field of another type or twice, an encoded body.",
	}, []string{"format", "phase"})
	checks := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_llm_checks_total",
		Help: "LLM checks that failed, by check and action: deny, or log (Detect).",
	}, []string{"check", "action"})
	tokens := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_llm_tokens_total",
		Help: "Tokens of the requests on LLM endpoints: estimated at request time (prompt bytes / 3 plus the output limit), to size token-weighted rate limits.",
	}, []string{"kind"})
	inspect := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "inkwall_llm_inspect_seconds",
		Help:    "Time reading and checking bodies on LLM endpoints, by phase.",
		Buckets: []float64{.00001, .00003, .0001, .0003, .001, .003, .01, .03},
	}, []string{"phase"})
	for f := Format(0); f < numFormats; f++ {
		if f == FormatUnknown {
			continue
		}
		for ph := Phase(0); ph < numPhases; ph++ {
			m.requests[f][ph] = requests.WithLabelValues(f.label(), ph.label())
			m.malformed[f][ph] = malformed.WithLabelValues(f.label(), ph.label())
		}
	}
	for _, c := range Checks {
		for a := Action(0); a < numActions; a++ {
			m.checks[c][a] = checks.WithLabelValues(c.String(), a.label())
		}
	}
	for k := TokenKind(0); k < numTokenKinds; k++ {
		m.tokens[k] = tokens.WithLabelValues(k.label())
	}
	for ph := Phase(0); ph < numPhases; ph++ {
		m.inspect[ph] = inspect.WithLabelValues(ph.label())
	}
	m.collectors = []prometheus.Collector{requests, malformed, checks, tokens, inspect}
	return m
}

// Collectors returns the metrics' collectors.
func (m *Metrics) Collectors() []prometheus.Collector { return m.collectors }

// Read counts a body read as f, malformed or not, and the time it took.
func (m *Metrics) Read(f Format, ph Phase, malformed bool, took time.Duration) {
	if m == nil || f == FormatUnknown || f >= numFormats {
		return
	}
	m.requests[f][ph].Inc()
	if malformed {
		m.malformed[f][ph].Inc()
	}
	m.inspect[ph].Observe(took.Seconds())
}

// Failed counts a check failed, and what became of the request.
func (m *Metrics) Failed(c Check, a Action) {
	if m == nil || c == CheckNone || c >= numChecks {
		return
	}
	m.checks[c][a].Inc()
}

// Tokens counts tokens of kind k.
func (m *Metrics) Tokens(k TokenKind, n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.tokens[k].Add(float64(n))
}
