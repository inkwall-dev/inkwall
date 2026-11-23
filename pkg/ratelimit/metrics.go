// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import "github.com/prometheus/client_golang/prometheus"

const (
	evictionsHelp = "Rate limit entries reused for a new key: idle (a full bucket, or a limit no longer in the bundle: nothing lost), active (the bucket in use closest to full for its limit, not one over its limit or limited recently, protected: its state forgotten) or over_share (every entry was protected: one of a limit holding more than its share of the 8 slots, its state forgotten). Active or over_share: the table is too small, or a client is cycling keys."
	overflowHelp  = "Requests of new rate limit keys no entry could be found for: every entry near the key's hash was protected and no limit held more than its share. A Block limit counts them in one of its 256 overflow buckets, by the key's hash; a Detect limit lets them through uncounted. The table is too small for the clients being limited, or a client is cycling keys."
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
			Name: "inkwall_rate_limit_evictions_total", Help: evictionsHelp, ConstLabels: prometheus.Labels{"kind": "over_share"},
		}, read(s.EvictionsOverShare)),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_overflow_total", Help: overflowHelp,
		}, read(s.Overflows)),
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
