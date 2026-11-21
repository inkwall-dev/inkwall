// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// The export's metrics (design 0010 §8), per replica; sink is bounded by
// the 4 sinks.
var (
	exportedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_operator_events_exported_total",
		Help: "Security events an export sink accepted, from this replica.",
	}, []string{"sink"})
	exportDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_operator_events_export_dropped_total",
		Help: "Security events an export sink never got: buffer_full (dropped from a full buffer before the sink sent them), rejected (refused by the sink: a 4xx or OTLP partial success), too_large (a single event the sink refused as too large).",
	}, []string{"sink", "reason"})
	exportFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_operator_events_export_failures_total",
		Help: "Failed requests to an export sink, retried or not, by kind: network, tls, timeout, auth, throttled, server, client.",
	}, []string{"sink", "kind"})
	exportPending = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_events_export_pending",
		Help: "Security events in this replica's export buffer that the sink hasn't had accepted yet.",
	}, []string{"sink"})
	exportBufferBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_events_export_buffer_bytes",
		Help: "The size of this replica's export buffer, in memory and on disk.",
	})
	exportLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_events_export_last_success_timestamp_seconds",
		Help: "When an export sink last accepted a request from this replica (0: never).",
	}, []string{"sink"})
	exportDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "inkwall_operator_events_export_request_duration_seconds",
		Help:    "Time per request to an export sink, retries apart.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
	}, []string{"sink"})
)

func init() {
	metrics.Registry.MustRegister(exportedTotal, exportDropped, exportFailures, exportPending, exportBufferBytes, exportLastSuccess, exportDuration)
}

// The label values the counters start with, so a rate is 0, not absent.
var (
	dropReasons  = []string{DropBufferFull, DropRejected, DropTooLarge}
	failureKinds = []string{kindNetwork, kindTLS, kindTimeout, kindAuth, kindThrottled, kindServer, kindClient}
)

// PrometheusMetrics reports to the operator's metrics registry.
type PrometheusMetrics struct{}

// Start makes a sink's series, at 0.
func (PrometheusMetrics) Start(sink string) {
	exportedTotal.WithLabelValues(sink)
	for _, r := range dropReasons {
		exportDropped.WithLabelValues(sink, r)
	}
	for _, k := range failureKinds {
		exportFailures.WithLabelValues(sink, k)
	}
	exportPending.WithLabelValues(sink)
	exportLastSuccess.WithLabelValues(sink)
}

// Exported counts the events a sink accepted.
func (PrometheusMetrics) Exported(sink string, n int) {
	exportedTotal.WithLabelValues(sink).Add(float64(n))
}

// Dropped counts the events a sink never got, by reason.
func (PrometheusMetrics) Dropped(sink, reason string, n int) {
	exportDropped.WithLabelValues(sink, reason).Add(float64(n))
}

// Failed counts a failed request, by kind.
func (PrometheusMetrics) Failed(sink, kind string) { exportFailures.WithLabelValues(sink, kind).Inc() }

// Duration observes a request's time.
func (PrometheusMetrics) Duration(sink string, d time.Duration) {
	exportDuration.WithLabelValues(sink).Observe(d.Seconds())
}

// Succeeded sets when the sink last accepted a request.
func (PrometheusMetrics) Succeeded(sink string, at time.Time) {
	exportLastSuccess.WithLabelValues(sink).Set(float64(at.UnixNano()) / 1e9)
}

// Pending sets the events the sink hasn't had accepted.
func (PrometheusMetrics) Pending(sink string, n uint64) {
	exportPending.WithLabelValues(sink).Set(float64(n))
}

// BufferBytes sets the export buffer's size.
func (PrometheusMetrics) BufferBytes(n int64) { exportBufferBytes.Set(float64(n)) }

// Forget removes a removed sink's series.
func (PrometheusMetrics) Forget(sink string) {
	exportedTotal.DeleteLabelValues(sink)
	exportDropped.DeletePartialMatch(prometheus.Labels{"sink": sink})
	exportFailures.DeletePartialMatch(prometheus.Labels{"sink": sink})
	exportPending.DeleteLabelValues(sink)
	exportLastSuccess.DeleteLabelValues(sink)
	exportDuration.DeleteLabelValues(sink)
}
