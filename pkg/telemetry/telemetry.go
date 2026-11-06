// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry exposes engine metrics in the Prometheus format and the
// admin endpoints (/metrics, /healthz, /readyz).
package telemetry

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// Bounds on the series of labels whose values the engine doesn't choose.
const (
	// maxRuleSeries bounds inkwall_rule_matches_total's rule IDs: they come
	// from the loaded rules, but a rule set may hold many, and bundles
	// change. Past it, matches count under rule_id="other".
	maxRuleSeries = 2000
	// DefaultMaxPolicies bounds inkwall_policy_requests_total's policies;
	// past it, requests count under policy="other".
	DefaultMaxPolicies = 500
)

// Kinds of inkwall_adapter_errors_total.
const (
	// ErrInvalidRequest: a request the adapter can't read (a malformed
	// forward-auth, check, ext_proc or SPOE request, or a proxied request
	// with an invalid target or Host), refused without inspection.
	ErrInvalidRequest = "invalid_request"
	// ErrProtocol: a stream or connection that breaks the adapter's
	// protocol (ext_proc, SPOE), closed.
	ErrProtocol = "protocol"
)

// Metrics records verdicts. It implements pipeline.Observer. Its methods
// are safe on a nil *Metrics, which records nothing.
type Metrics struct {
	registry  *prometheus.Registry
	requests  *prometheus.CounterVec
	duration  prometheus.Histogram
	responses *prometheus.CounterVec
	respTime  prometheus.Histogram

	ruleMatches    *prometheus.CounterVec
	policyRequests *prometheus.CounterVec // nil unless enabled
	adapterErrors  *prometheus.CounterVec
	wsMessages     *prometheus.CounterVec
	wsConnections  prometheus.Gauge
	wsViolations   *prometheus.CounterVec

	labels      prometheus.Labels
	mu          sync.Mutex
	rules       map[int]string // rule ID -> its label value
	policies    map[string]bool
	maxPolicies int
}

var _ pipeline.Observer = (*Metrics)(nil)

// NewMetrics returns metrics for one adapter (for example "proxy"), with Go
// runtime and process collectors registered.
func NewMetrics(adapter string) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	labels := prometheus.Labels{"adapter": adapter}
	m := &Metrics{
		registry: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_requests_total",
			Help:        "Requests checked, by action (allow, deny, log) and reason (none, rule, timeout, error, canceled, overload, oversize, skipped, no-policy, suspended, websocket). Reasons timeout, error and overload mean the request was not inspected.",
			ConstLabels: labels,
		}, []string{"action", "reason"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "inkwall_check_duration_seconds",
			Help:        "Time spent checking a request, including queueing for an evaluation slot.",
			ConstLabels: labels,
			// 50µs to ~0.8s.
			Buckets: prometheus.ExponentialBuckets(50e-6, 2, 15),
		}),
		responses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_responses_total",
			Help:        "Responses checked, for policies that inspect responses, by action (allow, deny, log) and reason, as inkwall_requests_total. Reason oversize means part or all of the body was not inspected.",
			ConstLabels: labels,
		}, []string{"action", "reason"}),
		respTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "inkwall_response_check_duration_seconds",
			Help:        "Time spent checking a response, including queueing for an evaluation slot.",
			ConstLabels: labels,
			Buckets:     prometheus.ExponentialBuckets(50e-6, 2, 15),
		}),
		ruleMatches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_rule_matches_total",
			Help:        "Rules that matched, by rule ID and the verdict's action (allow, deny, log); every rule that matched counts, score-only ones included. At most 2000 rule IDs, then rule_id=\"other\".",
			ConstLabels: labels,
		}, []string{"rule_id", "action"}),
		adapterErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_adapter_errors_total",
			Help:        "Requests the adapter refused without inspecting them, by kind: invalid_request (one it can't read, answered 400 or denied), protocol (a stream or connection that breaks the protocol, closed).",
			ConstLabels: labels,
		}, []string{"kind"}),
		wsMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_websocket_messages_total",
			Help:        "WebSocket messages inspected (the engine's proxy with --websocket-messages), by action (allow, deny, log). Not counted in inkwall_requests_total.",
			ConstLabels: labels,
		}, []string{"action"}),
		wsConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "inkwall_websocket_connections",
			Help:        "WebSocket connections the engine's proxy holds open.",
			ConstLabels: labels,
		}),
		wsViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "inkwall_websocket_violations_total",
			Help:        "WebSocket messages the proxy couldn't inspect or that broke the protocol, by the close code it would send (1002 protocol error, 1003 binary message refused, 1007 text not UTF-8, 1009 too big).",
			ConstLabels: labels,
		}, []string{"code"}),
		rules:  map[int]string{},
		labels: labels,
	}
	reg.MustRegister(m.requests, m.duration, m.responses, m.respTime,
		m.ruleMatches, m.adapterErrors, m.wsMessages, m.wsConnections, m.wsViolations)
	return m
}

// EnablePolicyMetrics adds inkwall_policy_requests_total, requests by
// policy, for at most max distinct policies (DefaultMaxPolicies when 0 or
// less); past them, requests count under policy="other". Call it before
// the engine serves.
func (m *Metrics) EnablePolicyMetrics(max int) {
	if max <= 0 {
		max = DefaultMaxPolicies
	}
	m.maxPolicies = max
	m.policies = map[string]bool{}
	m.policyRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "inkwall_policy_requests_total",
		Help:        "Requests checked, by policy (namespace/name; none when no policy covers the request; other past the cap of distinct policies), action and reason, as inkwall_requests_total.",
		ConstLabels: m.labels,
	}, []string{"policy", "action", "reason"})
	m.registry.MustRegister(m.policyRequests)
}

// ObserveVerdict records one verdict.
func (m *Metrics) ObserveVerdict(v pipeline.Verdict) {
	action := v.Action.String()
	for _, id := range v.RuleIDs {
		m.ruleMatches.WithLabelValues(m.ruleLabel(id), action).Inc()
	}
	switch {
	case v.WebSocketMessage:
		m.wsMessages.WithLabelValues(action).Inc()
	case v.Response:
		m.responses.WithLabelValues(action, v.Reason.String()).Inc()
		m.respTime.Observe(v.Duration.Seconds())
	default:
		m.requests.WithLabelValues(action, v.Reason.String()).Inc()
		m.duration.Observe(v.Duration.Seconds())
		if m.policyRequests != nil {
			m.policyRequests.WithLabelValues(m.policyLabel(v.Policy), action, v.Reason.String()).Inc()
		}
	}
}

// ruleLabel is a rule ID's label value: "other" past maxRuleSeries IDs.
func (m *Metrics) ruleLabel(id int) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.rules[id]; ok {
		return l
	}
	l := "other"
	if len(m.rules) < maxRuleSeries {
		l = strconv.Itoa(id)
		m.rules[id] = l
	}
	return l
}

// policyLabel is a policy's label value: "none" without one, "other"
// past maxPolicies policies.
func (m *Metrics) policyLabel(policy string) string {
	if policy == "" {
		return "none"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policies[policy] {
		return policy
	}
	if len(m.policies) < m.maxPolicies {
		m.policies[policy] = true
		return policy
	}
	return "other"
}

// AdapterError counts a request the adapter refused without inspecting
// it, by kind (ErrInvalidRequest, ErrProtocol).
func (m *Metrics) AdapterError(kind string) {
	if m == nil {
		return
	}
	m.adapterErrors.WithLabelValues(kind).Inc()
}

// WebSocketOpened counts an open WebSocket connection; the returned
// function, called when it closes (more than once is fine), uncounts it.
func (m *Metrics) WebSocketOpened() (closed func()) {
	if m == nil {
		return func() {}
	}
	m.wsConnections.Inc()
	var once sync.Once
	return func() { once.Do(m.wsConnections.Dec) }
}

// WebSocketViolation counts a WebSocket message the proxy couldn't
// inspect or that broke the protocol, by its close code.
func (m *Metrics) WebSocketViolation(code int) {
	if m == nil {
		return
	}
	m.wsViolations.WithLabelValues(strconv.Itoa(code)).Inc()
}

// Register adds collectors, such as the bundle agent's, to the engine's
// metrics.
func (m *Metrics) Register(cs ...prometheus.Collector) {
	m.registry.MustRegister(cs...)
}

// WatchAdmission exports evaluation slot usage, so saturation (and with it,
// shed requests) is visible before it happens.
func (m *Metrics) WatchAdmission(p *pipeline.Admission) {
	m.registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_evaluations_in_flight",
			Help: "Evaluations running now, including ones that timed out and are still finishing.",
		}, func() float64 { return float64(p.InFlight()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_evaluation_slots",
			Help: "Maximum concurrent evaluations; requests beyond it are shed with reason overload.",
		}, func() float64 { return float64(p.Capacity()) }),
	)
}

// WatchRuleSets exports the number of compiled rule sets in memory, as n
// reports it.
func (m *Metrics) WatchRuleSets(n func() int) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "inkwall_rule_sets",
		Help: "Compiled rule sets in memory: one per distinct rule configuration of the bundle's policies (1 with a policy from flags).",
	}, func() float64 { return float64(n()) }))
}

// AdminHandler serves /metrics, /healthz (the process is alive) and /readyz
// (the engine has loaded its rules and can serve; ready is called per probe).
func (m *Metrics) AdminHandler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeStatus(w, http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready != nil && !ready() {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		writeStatus(w, http.StatusOK)
	})
	return mux
}

func writeStatus(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(strconv.Itoa(code) + " " + http.StatusText(code) + "\n"))
}
