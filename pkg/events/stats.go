// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// latencyBounds are the latency buckets' upper bounds: 50 µs to ~0.8 s,
// doubling, as the engine's inkwall_check_duration_seconds.
var latencyBounds = func() (b [15]time.Duration) {
	for i := range b {
		b[i] = 50 * time.Microsecond << i
	}
	return b
}()

// LatencyBounds returns the latency buckets' upper bounds in seconds, as
// RequestStats.latency_bounds carries them.
func LatencyBounds() []float64 {
	out := make([]float64, len(latencyBounds))
	for i, b := range latencyBounds {
		out[i] = b.Seconds()
	}
	return out
}

// Stats counts the requests each policy decides, for the operator (0002
// §5.2). Safe for concurrent use.
type Stats struct {
	mu       sync.Mutex
	policies map[string]*Counter
	// retired are counters of policies the last bundle doesn't have: taken
	// one last time, then dropped.
	retired map[string]bool
}

// NewStats returns empty counters.
func NewStats() *Stats {
	return &Stats{policies: map[string]*Counter{}, retired: map[string]bool{}}
}

// Counter counts one policy's requests: a few atomic adds per request.
type Counter struct {
	allowed, denied, detected atomic.Uint64
	nanos                     atomic.Uint64
	latency                   [len(latencyBounds) + 1]atomic.Uint64
}

// Observe counts a verdict. A nil Counter counts nothing.
func (c *Counter) Observe(v pipeline.Verdict) {
	if c == nil {
		return
	}
	switch v.Action {
	case pipeline.ActionDeny:
		c.denied.Add(1)
	case pipeline.ActionLog:
		c.detected.Add(1)
	default:
		c.allowed.Add(1)
	}
	d := max(v.Duration, 0)
	c.nanos.Add(uint64(d)) // #nosec G115 -- not negative
	i := 0
	for i < len(latencyBounds) && d > latencyBounds[i] {
		i++
	}
	c.latency[i].Add(1)
}

// Counter returns the policy's counter, the same one for every bundle that
// has the policy.
func (s *Stats) Counter(policy string) *Counter {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.retired, policy)
	c, ok := s.policies[policy]
	if !ok {
		c = &Counter{}
		s.policies[policy] = c
	}
	return c
}

// Retain retires the counters of policies not in keep (the new bundle's):
// Take reports them once more, then drops them.
func (s *Stats) Retain(keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.policies {
		if !keep[id] {
			s.retired[id] = true
		}
	}
}

// Take returns what each policy counted since the previous Take, sorted by
// policy, leaving out policies that counted nothing.
func (s *Stats) Take() []*eventsv1.PolicyStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*eventsv1.PolicyStats
	for id, c := range s.policies {
		if p := c.take(id); p != nil {
			out = append(out, p)
		}
		if s.retired[id] {
			delete(s.policies, id)
			delete(s.retired, id)
		}
	}
	slices.SortFunc(out, func(a, b *eventsv1.PolicyStats) int { return strings.Compare(a.GetPolicy(), b.GetPolicy()) })
	return out
}

// take resets the counter and returns what it had, or nil if nothing. A
// request counted meanwhile may show in its action now and in its latency
// next time.
func (c *Counter) take(policy string) *eventsv1.PolicyStats {
	p := &eventsv1.PolicyStats{
		Policy:   policy,
		Allowed:  c.allowed.Swap(0),
		Denied:   c.denied.Swap(0),
		Detected: c.detected.Swap(0),
	}
	p.LatencySum = time.Duration(c.nanos.Swap(0)).Seconds() // #nosec G115 -- sums of durations
	p.LatencyCounts = make([]uint64, len(c.latency))
	var n uint64
	for i := range c.latency {
		p.LatencyCounts[i] = c.latency[i].Swap(0)
		n += p.LatencyCounts[i]
	}
	if p.Allowed == 0 && p.Denied == 0 && p.Detected == 0 && n == 0 {
		return nil
	}
	return p
}

// AddStats adds d's counts to p's (same policy). Latency counts of
// another length (other buckets) are left out.
func AddStats(p, d *eventsv1.PolicyStats) {
	p.Allowed += d.GetAllowed()
	p.Denied += d.GetDenied()
	p.Detected += d.GetDetected()
	switch {
	case len(p.LatencyCounts) == 0 && len(d.GetLatencyCounts()) > 0:
		p.LatencyCounts = slices.Clone(d.GetLatencyCounts())
	case len(p.LatencyCounts) == len(d.GetLatencyCounts()):
		for i, n := range d.GetLatencyCounts() {
			p.LatencyCounts[i] += n
		}
	default:
		return
	}
	p.LatencySum += d.GetLatencySum()
}

// DiffStats returns what cur counted since prev, two cumulative reports of
// one policy (prev nil: none before). A count lower than before means the
// counts started again from zero: then all of cur is new. Latency in other
// buckets than prev's is left out.
func DiffStats(cur, prev *eventsv1.PolicyStats) *eventsv1.PolicyStats {
	if prev == nil || cur.GetAllowed() < prev.GetAllowed() || cur.GetDenied() < prev.GetDenied() ||
		cur.GetDetected() < prev.GetDetected() {
		return proto.CloneOf(cur)
	}
	d := &eventsv1.PolicyStats{
		Policy:   cur.GetPolicy(),
		Allowed:  cur.GetAllowed() - prev.GetAllowed(),
		Denied:   cur.GetDenied() - prev.GetDenied(),
		Detected: cur.GetDetected() - prev.GetDetected(),
	}
	if len(cur.GetLatencyCounts()) != len(prev.GetLatencyCounts()) {
		return d
	}
	for i, n := range prev.GetLatencyCounts() {
		if cur.GetLatencyCounts()[i] < n {
			return proto.CloneOf(cur)
		}
		d.LatencyCounts = append(d.LatencyCounts, cur.GetLatencyCounts()[i]-n)
	}
	d.LatencySum = max(cur.GetLatencySum()-prev.GetLatencySum(), 0)
	return d
}

// SplitStats splits policies into RequestStats of at most maxBytes each
// (one policy per message at least), so a report of many policies never
// makes a large message.
func SplitStats(policies []*eventsv1.PolicyStats, maxBytes int) []*eventsv1.RequestStats {
	bounds := LatencyBounds()
	var out []*eventsv1.RequestStats
	var cur *eventsv1.RequestStats
	size := 0
	for _, p := range policies {
		// A repeated field's tag and length prefix: at most 4 bytes here.
		n := proto.Size(p) + 4
		if cur == nil || (len(cur.Policies) > 0 && size+n > maxBytes) {
			cur = &eventsv1.RequestStats{LatencyBounds: bounds}
			out = append(out, cur)
			size = proto.Size(cur)
		}
		cur.Policies = append(cur.Policies, p)
		size += n
	}
	return out
}
