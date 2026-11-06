// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// maxLogKeys bounds the token buckets a LogLimiter holds; past it, they all
// start again full. Policies and rules are bounded by the bundle, so this
// takes thousands of (policy, rule) pairs.
const maxLogKeys = 4096

// LogLimiter rate-limits security event log lines per policy and rule with
// a token bucket, so a scanner or one false positive on a busy route can't
// flood the logs. It doesn't touch the events sent to the operator. A nil
// LogLimiter, or one with a rate of 0, allows every line. Safe for
// concurrent use.
type LogLimiter struct {
	// Now is the clock, time.Now when nil (for tests).
	Now func() time.Time

	rate       float64 // lines per second, and the burst
	mu         sync.Mutex
	buckets    map[logKey]*logBucket
	suppressed *prometheus.CounterVec
}

type logKey struct {
	policy string
	rule   int
	reason pipeline.Reason
}

type logBucket struct {
	tokens     float64
	last       time.Time
	suppressed uint64 // since the last line
}

// NewLogLimiter allows perSecond lines per policy and rule each second, in
// bursts of as many; 0 allows every line.
func NewLogLimiter(perSecond int) *LogLimiter {
	return &LogLimiter{
		rate:    float64(max(perSecond, 0)),
		buckets: map[logKey]*logBucket{},
		suppressed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "inkwall_security_event_logs_suppressed_total",
			Help: "Security event log lines left out by the per-policy and rule rate limit (the events still go to the operator).",
		}, []string{"policy"}),
	}
}

// Suppressed is the counter of lines left out, by policy.
func (l *LogLimiter) Suppressed() *prometheus.CounterVec { return l.suppressed }

// Collectors returns the limiter's metrics.
func (l *LogLimiter) Collectors() []prometheus.Collector {
	return []prometheus.Collector{l.suppressed}
}

// Allow reports whether v's line is logged and, when it is, how many lines
// of its policy and rule were left out since the last one.
func (l *LogLimiter) Allow(v pipeline.Verdict) (bool, uint64) {
	if l == nil || l.rate == 0 {
		return true, 0
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	t := now()
	k := logKey{policy: v.Policy, rule: v.InterruptingRuleID, reason: v.Reason}
	if k.rule == 0 && len(v.RuleIDs) > 0 {
		k.rule = v.RuleIDs[0]
	}
	l.mu.Lock()
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= maxLogKeys {
			clear(l.buckets)
		}
		b = &logBucket{tokens: l.rate, last: t}
		l.buckets[k] = b
	}
	if d := t.Sub(b.last); d > 0 {
		b.tokens = min(l.rate, b.tokens+d.Seconds()*l.rate)
		b.last = t
	}
	if b.tokens < 1 {
		b.suppressed++
		l.mu.Unlock()
		l.suppressed.WithLabelValues(v.Policy).Inc()
		return false, 0
	}
	b.tokens--
	n := b.suppressed
	b.suppressed = 0
	l.mu.Unlock()
	return true, n
}

// LogMatch is where a rule matched, for logs and the check API: the rule
// and the variable's name, never the matched value.
type LogMatch struct {
	RuleID   int    `json:"rule_id"`
	Variable string `json:"variable"`
}

// LogMatches returns where v's rules matched, bounded as in events: at
// most 32 matches, variable names cut to 128 bytes of valid UTF-8.
func LogMatches(v pipeline.Verdict) []LogMatch {
	if len(v.Matches) == 0 {
		return nil
	}
	out := make([]LogMatch, 0, min(len(v.Matches), maxMatches))
	for _, m := range v.Matches[:min(len(v.Matches), maxMatches)] {
		out = append(out, LogMatch{RuleID: m.RuleID, Variable: truncate(m.Variable, maxVariable)})
	}
	return out
}
