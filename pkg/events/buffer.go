// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Defaults of the Buffer.
const (
	// DefaultCapacity bounds the events held while the operator is away:
	// about 10 MiB at the contract's field limits.
	DefaultCapacity = 10_000
	// MaxBatch is the contract's limit on a batch.
	MaxBatch = 1_000
)

// Buffer holds events until the agent sends them, in order of time. Full,
// it drops the oldest and counts them: events are best effort, inspection
// never waits for them. Safe for concurrent use.
type Buffer struct {
	mu       sync.Mutex
	events   []*eventsv1.SecurityEvent // a ring of cap(events)
	head, n  int
	dropped  uint64 // since the last batch
	ready    chan struct{}
	recorded prometheus.Counter
	lost     prometheus.Counter
}

// NewBuffer returns a buffer of capacity events (DefaultCapacity when 0).
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Buffer{
		events: make([]*eventsv1.SecurityEvent, capacity),
		ready:  make(chan struct{}, 1),
		recorded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "inkwall_engine_events_total",
			Help: "Security events recorded for the operator.",
		}),
		lost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "inkwall_engine_events_dropped_total",
			Help: "Security events dropped because the buffer was full (the operator unreachable or slow).",
		}),
	}
}

// Collectors returns the buffer's metrics.
func (b *Buffer) Collectors() []prometheus.Collector {
	return []prometheus.Collector{b.recorded, b.lost}
}

// Add records ev, dropping the oldest event when full. It never blocks.
func (b *Buffer) Add(ev *eventsv1.SecurityEvent) {
	b.mu.Lock()
	if b.n == len(b.events) {
		b.events[b.head] = nil
		b.head = (b.head + 1) % len(b.events)
		b.n--
		b.dropped++
		b.lost.Inc()
	}
	b.events[(b.head+b.n)%len(b.events)] = ev
	b.n++
	b.mu.Unlock()
	b.recorded.Inc()
	select {
	case b.ready <- struct{}{}:
	default:
	}
}

// Len returns how many events are held.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// Next waits for events, then takes up to max of them (MaxBatch when 0 or
// more) as a batch, with the count dropped since the previous batch. It
// returns nil when ctx ends first.
func (b *Buffer) Next(ctx context.Context, max int) *eventsv1.EventBatch {
	if max <= 0 || max > MaxBatch {
		max = MaxBatch
	}
	for {
		if batch := b.take(max); batch != nil {
			return batch
		}
		select {
		case <-b.ready:
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *Buffer) take(max int) *eventsv1.EventBatch {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n == 0 && b.dropped == 0 {
		return nil
	}
	k := min(max, b.n)
	batch := &eventsv1.EventBatch{Events: make([]*eventsv1.SecurityEvent, 0, k), Dropped: b.dropped}
	for range k {
		batch.Events = append(batch.Events, b.events[b.head])
		b.events[b.head] = nil
		b.head = (b.head + 1) % len(b.events)
	}
	b.n -= k
	b.dropped = 0
	if b.n > 0 {
		select {
		case b.ready <- struct{}{}:
		default:
		}
	}
	return batch
}

// Return puts back a batch that couldn't be sent, ahead of newer events,
// so nothing is lost while the buffer has room: the oldest are dropped
// first, as Add does.
func (b *Buffer) Return(batch *eventsv1.EventBatch) {
	if batch == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropped += batch.GetDropped()
	evs := batch.GetEvents()
	for i := len(evs) - 1; i >= 0; i-- {
		if b.n == len(b.events) {
			// Full: the rest of the batch is older than what's held.
			lost := uint64(i + 1) // #nosec G115 -- a small count
			b.dropped += lost
			b.lost.Add(float64(lost))
			break
		}
		b.head = (b.head - 1 + len(b.events)) % len(b.events)
		b.events[b.head] = evs[i]
		b.n++
	}
	select {
	case b.ready <- struct{}{}:
	default:
	}
}

// Recorder turns verdicts into events in a Buffer. A nil Recorder records
// nothing: an engine without an operator only logs its events.
type Recorder struct {
	Source Source
	Buffer *Buffer
}

// Record adds the event for req and v.
func (r *Recorder) Record(req *request.Request, path string, v pipeline.Verdict) {
	if r == nil || r.Buffer == nil {
		return
	}
	r.Buffer.Add(New(r.Source, req, path, v, time.Now()))
}
