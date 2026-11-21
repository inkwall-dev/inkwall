// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import "github.com/prometheus/client_golang/prometheus"

// Collectors returns the Store's metrics. None is labelled by limit or key:
// both are unbounded.
func (s *Store) Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_rate_limit_keys",
			Help: "Rate limit buckets held, full ones included until their entry is reused.",
		}, func() float64 { return float64(s.Keys()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_rate_limit_key_capacity",
			Help: "The rate limit table's capacity, after the memory cap.",
		}, func() float64 { return float64(s.Capacity()) }),
		counterFunc("inkwall_rate_limit_evictions_total",
			"Rate limit entries reused for a new key: idle (a full bucket, or a limit no longer in the bundle: nothing lost) or active (the bucket closest to full: its state forgotten; the table is too small, or a client is cycling keys).",
			"kind", map[string]func() uint64{
				"idle":   func() uint64 { idle, _ := s.Evictions(); return idle },
				"active": func() uint64 { _, active := s.Evictions(); return active },
			}),
		counterFunc("inkwall_rate_limit_skipped_total",
			"Requests a rate limit couldn't count: no_key, no valid client address.",
			"reason", map[string]func() uint64{"no_key": s.skippedNoKey.Load}),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "inkwall_rate_limit_events_dropped_total",
			Help: "Rate limit security events left out by the per-limit or engine-wide event cap (the requests are still counted).",
		}, func() float64 { return float64(s.EventsDropped()) }),
	}
}

// labelled is a counter with one label, whose values each read a function.
type labelled struct {
	desc   *prometheus.Desc
	values map[string]func() uint64
}

func counterFunc(name, help, label string, values map[string]func() uint64) prometheus.Collector {
	return &labelled{desc: prometheus.NewDesc(name, help, []string{label}, nil), values: values}
}

func (c *labelled) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *labelled) Collect(ch chan<- prometheus.Metric) {
	for v, f := range c.values {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(f()), v)
	}
}
