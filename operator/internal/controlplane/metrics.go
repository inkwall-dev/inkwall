// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	eventsForwarded = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "inkwall_operator_events_forwarded_total",
		Help: "Security events this replica sent to the control plane (resends included).",
	})
	eventsBuffered = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_events_buffered",
		Help: "Security events in this replica's buffer, not yet acknowledged by the control plane.",
	})
	eventsForwardErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "inkwall_operator_events_buffer_errors_total",
		Help: "Batches of security events this replica couldn't write to its buffer (dropped, and counted in the next batch).",
	})
)

func init() {
	metrics.Registry.MustRegister(eventsForwarded, eventsBuffered, eventsForwardErrors)
}
