// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import "github.com/prometheus/client_golang/prometheus"

const (
	evictionsHelp = "Rate limit entries reused for a new key: idle (a full bucket, or a limit no longer in the bundle: nothing lost) or active (the bucket closest to full: its state forgotten; the table is too small, or a client is cycling keys)."
	skippedHelp   = "Requests a rate limit couldn't count: no_key, no valid client address."
	exceededHelp  = "Requests over a rate limit: deny, or log for a Detect limit (also when a rule decided the request)."
)

// Collectors returns the Store's metrics. None is labelled by limit or key:
// both are unbounded.
func (s *Store) Collectors() []prometheus.Collector {
	read := func(f func() uint64) func() float64 { return func() float64 { return float64(f()) } }
	return []prometheus.Collector{
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_rate_limit_keys",
			Help: "Rate limit buckets held, full ones included until their entry is reused.",
		}, func() float64 { return float64(s.Keys()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_rate_limit_key_capacity",
			Help: "The rate limit table's capacity, after the memory cap.",
		}, func() float64 { return float64(s.Capacity()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_evictions_total", Help: evictionsHelp, ConstLabels: prometheus.Labels{"kind": "idle"},
		}, read(s.evictIdle.Load)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_evictions_total", Help: evictionsHelp, ConstLabels: prometheus.Labels{"kind": "active"},
		}, read(s.evictActive.Load)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_skipped_total", Help: skippedHelp, ConstLabels: prometheus.Labels{"reason": "no_key"},
		}, read(s.skippedNoKey.Load)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_exceeded_total", Help: exceededHelp, ConstLabels: prometheus.Labels{"action": "deny"},
		}, read(s.overDeny.Load)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_exceeded_total", Help: exceededHelp, ConstLabels: prometheus.Labels{"action": "log"},
		}, read(s.overLog.Load)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_events_dropped_total",
			Help: "Rate limit security events left out by the per-limit or engine-wide event cap (the requests are still counted).",
		}, func() float64 { return float64(s.EventsDropped()) }),
	}
}
