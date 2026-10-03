// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry exposes engine metrics in the Prometheus format and the
// admin endpoints (/metrics, /healthz, /readyz).
package telemetry

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// Metrics records verdicts. It implements pipeline.Observer.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration prometheus.Histogram
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
			Help:        "Requests checked, by action (allow, deny, log) and reason (none, rule, timeout, error, canceled, overload, oversize). Reasons timeout, error and overload mean the request was not inspected.",
			ConstLabels: labels,
		}, []string{"action", "reason"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "inkwall_check_duration_seconds",
			Help:        "Time spent checking a request, including queueing for an evaluation slot.",
			ConstLabels: labels,
			// 50µs to ~0.8s.
			Buckets: prometheus.ExponentialBuckets(50e-6, 2, 15),
		}),
	}
	reg.MustRegister(m.requests, m.duration)
	return m
}

// ObserveVerdict records one verdict.
func (m *Metrics) ObserveVerdict(v pipeline.Verdict) {
	m.requests.WithLabelValues(v.Action.String(), v.Reason.String()).Inc()
	m.duration.Observe(v.Duration.Seconds())
}

// WatchPipeline exports the pipeline's evaluation slot usage, so saturation
// (and with it, shed requests) is visible before it happens.
func (m *Metrics) WatchPipeline(p *pipeline.Pipeline) {
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
