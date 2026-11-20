// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// EventsPerLimit caps the security events of one limit, per second.
	EventsPerLimit = 100
	// EventsPerEngine caps the security events of every limit together,
	// per second: at EventsPerLimit, one flooded limit would fill the
	// engine's event buffer (10,000 events) in 100 s while its operator is
	// away, pushing out the attacks that matter.
	EventsPerEngine = 10
	// maxEventLimits bounds the per-limit buckets; past it, they all start
	// again full. Limits are bounded by the bundle.
	maxEventLimits = 65_536
)

// eventCaps holds the event token buckets: one per limit, and the engine's.
type eventCaps struct {
	mu      sync.Mutex
	perID   map[uint32]*eventBucket
	engine  eventBucket
	dropped atomic.Uint64
}

type eventBucket struct {
	tokens float64
	last   time.Time
}

func (c *eventCaps) init() { c.perID = map[uint32]*eventBucket{} }

// take takes a token at t from a bucket of rate tokens a second, as many at
// most.
func (b *eventBucket) take(t time.Time, rate float64) bool {
	if b.last.IsZero() {
		b.tokens = rate
	} else if dt := t.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(rate, b.tokens+dt*rate)
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// AllowEvent reports whether a sampled event of limit l at t is kept, under
// the per-limit and engine-wide caps. A refused one is counted as dropped.
func (s *Store) AllowEvent(l Limit, t time.Time) bool {
	c := &s.events
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.perID[l.id]
	if b == nil {
		if len(c.perID) >= maxEventLimits {
			clear(c.perID)
		}
		b = &eventBucket{}
		c.perID[l.id] = b
	}
	// The limit's own cap first: a limit past it spends no token of the
	// engine's.
	if !b.take(t, EventsPerLimit) || !c.engine.take(t, EventsPerEngine) {
		c.dropped.Add(1)
		return false
	}
	return true
}

// EventsDropped is the sampled events the caps left out.
func (s *Store) EventsDropped() uint64 { return s.events.dropped.Load() }
