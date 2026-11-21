// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// Backoff between a request's attempts: exponential with full jitter,
// from 1 s to 60 s; an authentication failure waits the longest.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// Why events were never delivered: the reason label of the dropped metric.
const (
	DropBufferFull = "buffer_full"
	DropRejected   = "rejected"
	DropTooLarge   = "too_large"
)

// Metrics receives what the exporter counts (operator metrics); nil
// counts nothing.
type Metrics interface {
	Exported(sink string, n int)
	Dropped(sink, reason string, n int)
	Failed(sink, kind string)
	Duration(sink string, d time.Duration)
	Succeeded(sink string, at time.Time)
	Pending(sink string, n uint64)
	BufferBytes(n int64)
	Forget(sink string)
	// Start makes a new sink's series, at 0.
	Start(sink string)
}

type noMetrics struct{}

func (noMetrics) Exported(string, int)           {}
func (noMetrics) Dropped(string, string, int)    {}
func (noMetrics) Failed(string, string)          {}
func (noMetrics) Duration(string, time.Duration) {}
func (noMetrics) Succeeded(string, time.Time)    {}
func (noMetrics) Pending(string, uint64)         {}
func (noMetrics) BufferBytes(int64)              {}
func (noMetrics) Forget(string)                  {}
func (noMetrics) Start(string)                   {}

// sinkRuntime is a sink's configuration and the client it sends with.
type sinkRuntime struct {
	cfg    *sinkConfig
	client *sharedClient
}

// sharedClient closes its connections once retired and idle, so a
// rebuilt transport doesn't cut requests in flight.
type sharedClient struct {
	sinkClient
	mu      sync.Mutex
	users   int
	retired bool
}

func (c *sharedClient) acquire() { c.mu.Lock(); c.users++; c.mu.Unlock() }

// release reports whether the client was retired meanwhile.
func (c *sharedClient) release() bool {
	c.mu.Lock()
	c.users--
	retired := c.retired
	done := retired && c.users == 0
	c.mu.Unlock()
	if done {
		c.close()
	}
	return retired
}

func (c *sharedClient) retire() {
	c.mu.Lock()
	c.retired = true
	done := c.users == 0
	c.mu.Unlock()
	if done {
		c.close()
	}
}

// flight is a request sent or waiting to be.
type flight struct {
	items []item
	// end: the position past its last event, and past the filtered events
	// after it.
	end  position
	size int
	done bool
}

// sender is a sink's goroutine (design 0010 §4.3): it reads from its
// cursor, filters, encodes up to maxEvents events, sends when the request
// is full or maxDelay has passed since its first event, keeps up to
// maxInFlight requests in flight, and moves the cursor only past a run of
// answered requests, in order.
type sender struct {
	name      string
	buf       *buffer
	rt        atomic.Pointer[sinkRuntime]
	hasPolicy func(string) bool
	metrics   Metrics
	state     *sinkState
	now       func() time.Time
	// after makes the maxDelay timers, retryAfter the waits before
	// retries (tests shorten them).
	after      func(time.Duration) <-chan time.Time
	retryAfter func(time.Duration) <-chan time.Time

	reconfigured chan struct{}
	// flush asks the sender to send what it has at once, and to stop when
	// it has nothing left: shutdown.
	flush chan struct{}
	done  chan struct{}
	// drained is closed once the sender, flushing, has nothing left.
	drained chan struct{}
	// loops counts the run loop's passes (tests check it doesn't spin).
	loops atomic.Int64
	// log, if set, logs a key-value message; encodeFailed: it was logged
	// that a request couldn't be encoded.
	log          func(msg string, kv ...any)
	encodeFailed atomic.Bool
	// requests are the goroutines of the requests in flight.
	requests sync.WaitGroup
}

func newSender(name string, buf *buffer, hasPolicy func(string) bool, m Metrics, st *sinkState) *sender {
	return &sender{
		name: name, buf: buf, hasPolicy: hasPolicy, metrics: m, state: st, now: time.Now, after: time.After, retryAfter: time.After,
		reconfigured: make(chan struct{}, 1), flush: make(chan struct{}), done: make(chan struct{}), drained: make(chan struct{}),
	}
}

func (s *sender) configure(rt *sinkRuntime) {
	old := s.rt.Swap(rt)
	if old != nil && old.client != nil && (rt.client != old.client) {
		old.client.retire()
	}
	select {
	case s.reconfigured <- struct{}{}:
	default:
	}
}

// held is the batch the sender reads from.
type held struct {
	seq      uint64
	events   []*eventsv1.SecurityEvent
	next     int
	observed time.Time
}

// run sends until ctx ends.
func (s *sender) run(ctx context.Context) {
	defer close(s.done)
	// done only once every request goroutine has returned: nothing counts
	// for the sink after it is stopped (its metrics forgotten).
	defer s.requests.Wait()
	var (
		cur      *held
		b        builder
		bEnc     string // the encoding b was built under
		reqItems []item
		first    time.Time
		consumed = s.buf.acked(s.name)
		flights  []*flight
		answered = make(chan *flight, 8)
		flushing bool
		drained  bool
	)
	inflight := 0
	for {
		s.loops.Add(1)
		if n := s.buf.takeDropped(s.name); n > 0 {
			s.metrics.Dropped(s.name, DropBufferFull, asInt(n))
			s.state.droppedFull(s.now())
		}
		rt := s.rt.Load()
		var changed <-chan struct{}
		// exhausted: the sender took everything there is, or can't send.
		exhausted := rt == nil || rt.cfg.err != nil
		if !exhausted {
			cfg := rt.cfg
			if b != nil && bEnc != cfg.encoding && inflight < cfg.maxInFlight {
				// The sink changed while a request was being built: send it
				// now; deliver filters and encodes it again under the new
				// configuration first.
				flights = append(flights, s.dispatch(ctx, b, bEnc, reqItems, consumed, answered))
				inflight++
				b = nil
			}
			// Read and encode while a request may still be sent.
			for inflight < cfg.maxInFlight {
				if cur == nil || cur.next >= len(cur.events) {
					cur = nil
					t, ok, ch := s.buf.take(s.name)
					changed = ch
					if !ok {
						exhausted = true
						break
					}
					cur = s.load(t)
					if cur == nil {
						continue
					}
				}
				ev := cur.events[cur.next]
				it := item{ev: ev, observed: cur.observed}
				if p := ev.GetPolicy(); p != "" && s.hasPolicy != nil && s.hasPolicy(p) {
					it.policy = p
				}
				pos := position{seq: cur.seq, idx: cur.next + 1}
				if !cfg.takes(it) {
					// Filtered events advance the cursor like sent ones.
					cur.next++
					consumed = pos
					continue
				}
				if b != nil && bEnc != cfg.encoding {
					// At the in-flight limit with a request of the old
					// configuration: wait for a slot to send it.
					break
				}
				if b == nil {
					b, bEnc = newBuilder(cfg.format, &cfg.view, maxRequest), cfg.encoding
					reqItems = reqItems[:0:0]
					first = s.now()
				}
				if !b.add(it) {
					// Full by size: send, and start the next with this event.
					flights = append(flights, s.dispatch(ctx, b, bEnc, reqItems, consumed, answered))
					inflight++
					b = nil
					continue
				}
				reqItems = append(reqItems, it)
				cur.next++
				consumed = pos
				if b.len() >= cfg.maxEvents {
					flights = append(flights, s.dispatch(ctx, b, bEnc, reqItems, consumed, answered))
					inflight++
					b = nil
				}
			}
			if b != nil && inflight < cfg.maxInFlight && (flushing || s.now().Sub(first) >= cfg.maxDelay) {
				flights = append(flights, s.dispatch(ctx, b, bEnc, reqItems, consumed, answered))
				inflight++
				b = nil
			}
		}
		// Commit the answered requests at the head, in order; with none
		// waiting, what was filtered since is passed too.
		commit := position{}
		for len(flights) > 0 && flights[0].done {
			commit = flights[0].end
			flights = flights[1:]
		}
		if len(flights) == 0 && b == nil {
			commit = consumed
		}
		if commit != (position{}) {
			s.buf.commit(s.name, commit)
		}
		s.metrics.Pending(s.name, s.buf.pending(s.name))
		// Flushing, done when nothing is left, or when the sink can't send.
		if flushing && !drained && (rt == nil || rt.cfg.err != nil || exhausted && len(flights) == 0 && b == nil) {
			drained = true
			close(s.drained)
		}
		// The maxDelay timer, only while a dispatch is possible: not with
		// the configuration invalid, nor at the in-flight limit (an answer
		// wakes the loop then), or it would spin.
		var delay <-chan time.Time
		if b != nil && !flushing && rt != nil && rt.cfg.err == nil && inflight < rt.cfg.maxInFlight {
			delay = s.after(max(rt.cfg.maxDelay-s.now().Sub(first), 0))
		}
		if changed == nil {
			// Not reading (configuration invalid, or in flight to the
			// limit): wake on what lets it read again.
			changed = s.buf.changedCh()
		}
		select {
		case <-ctx.Done():
			return
		case f := <-answered:
			f.done = true
			inflight--
		case <-changed:
		case <-delay:
		case <-s.reconfigured:
		case <-s.flushCh(flushing):
			flushing = true
		}
	}
}

func (s *sender) flushCh(flushing bool) <-chan struct{} {
	if flushing {
		return nil
	}
	return s.flush
}

// load decodes a taken batch, read back from disk when it is there only.
func (s *sender) load(t taken) *held {
	raw := t.raw
	if raw == nil {
		var ok bool
		if raw, ok = s.buf.readBatch(t.seq); !ok {
			// Dropped meanwhile, or torn: lost for this sink.
			s.metrics.Dropped(s.name, DropBufferFull, t.events-t.from)
			s.state.droppedFull(s.now())
			return nil
		}
	}
	var batch eventsv1.EventBatch
	if err := proto.Unmarshal(raw, &batch); err != nil || len(batch.GetEvents()) <= t.from {
		s.metrics.Dropped(s.name, DropBufferFull, t.events-t.from)
		s.state.droppedFull(s.now())
		return nil
	}
	return &held{seq: t.seq, events: batch.GetEvents(), next: t.from, observed: t.observed}
}

// dispatch sends a request on its own goroutine, which tells answered
// when the request is answered for good. encoding is the configuration's
// the request was filtered and built under.
func (s *sender) dispatch(ctx context.Context, b builder, encoding string, items []item, end position, answered chan<- *flight) *flight {
	f := &flight{items: items, end: end}
	p := b.payload()
	f.size = p.size
	s.requests.Add(1)
	go func() {
		defer s.requests.Done()
		s.deliver(ctx, f, part{items: items, p: p, encoding: encoding})
		select {
		case answered <- f:
		case <-ctx.Done():
		}
	}()
	return f
}

// part is a request, or half of one after a 413, and the encoding it was
// built under.
type part struct {
	items    []item
	p        payload
	encoding string
}

// encodeParts filters items for cfg and encodes them in its format, in
// requests of at most maxRequest bytes: a request built under another
// configuration (a sink changed while it waited) is sent as the new one
// says, never with what it now leaves out.
func encodeParts(cfg *sinkConfig, items []item) []part {
	var out []part
	var b builder
	var cur []item
	flush := func() {
		if b != nil && b.len() > 0 {
			out = append(out, part{items: cur, p: b.payload(), encoding: cfg.encoding})
		}
		b, cur = nil, nil
	}
	for _, it := range items {
		if !cfg.takes(it) {
			continue
		}
		if b == nil {
			b = newBuilder(cfg.format, &cfg.view, maxRequest)
		}
		if !b.add(it) {
			flush()
			b = newBuilder(cfg.format, &cfg.view, maxRequest)
			b.add(it)
		}
		cur = append(cur, it)
	}
	flush()
	return out
}

// deliver sends f until it is answered for good: sent, refused, too large,
// or dropped from the buffer while it was retried.
func (s *sender) deliver(ctx context.Context, f *flight, first part) {
	parts := []part{first}
	attempt := 0
	// reencoded: the head part was encoded again after a client refused
	// it; refused again, it is dropped.
	reencoded := false
	for len(parts) > 0 {
		rt := s.rt.Load()
		if rt == nil || rt.client == nil || rt.cfg.err != nil {
			// The sink can't send now: wait for a configuration.
			if !s.retryWait(ctx, maxBackoff) {
				return
			}
			if s.abandoned(f, parts) {
				return
			}
			continue
		}
		if parts[0].encoding != rt.cfg.encoding {
			// Built under the sink's previous configuration: filtered and
			// encoded again. Events the new filters leave out are neither
			// exported nor counted as dropped, as when filtered at read
			// time: that is configuration, not loss.
			parts = append(encodeParts(rt.cfg, parts[0].items), parts[1:]...)
			continue
		}
		pt := parts[0]
		rt.client.acquire()
		start := s.now()
		rctx, cancel := context.WithTimeout(ctx, rt.cfg.timeout)
		r := rt.client.send(rctx, pt.p, rt.cfg.headers)
		cancel()
		retired := rt.client.release()
		if ctx.Err() != nil {
			// Shutting down: unanswered, so not committed; resent after a
			// restart.
			return
		}
		if r.mismatch {
			// A request the client can't send (it didn't encode): encode it
			// again, once. Refused again, its events are dropped as
			// rejected, never retried without a wait. Tests fail on the
			// first (payloadMismatch).
			if !reencoded {
				reencoded = true
				parts[0].encoding = ""
				continue
			}
			s.failed(r)
			s.metrics.Dropped(s.name, DropRejected, len(pt.items))
			s.logEncodeFailure(r.detail)
			parts, reencoded = parts[1:], false
			continue
		}
		reencoded = false
		if r.verdict != sent && retired {
			// The transport was rebuilt meanwhile and this one closed under
			// the request: send it again on the new one, no failure.
			continue
		}
		s.metrics.Duration(s.name, s.now().Sub(start))
		switch r.verdict {
		case sent:
			n := len(pt.items) - r.rejected
			s.metrics.Exported(s.name, max(n, 0))
			if r.rejected > 0 {
				s.metrics.Dropped(s.name, DropRejected, min(r.rejected, len(pt.items)))
			}
			now := s.now()
			s.metrics.Succeeded(s.name, now)
			s.state.succeeded(now)
			parts, attempt = parts[1:], 0
			continue
		case drop:
			s.failed(r)
			s.metrics.Dropped(s.name, DropRejected, len(pt.items))
			parts, attempt = parts[1:], 0
			continue
		case split:
			s.failed(r)
			if len(pt.items) <= 1 {
				s.metrics.Dropped(s.name, DropTooLarge, len(pt.items))
				parts = parts[1:]
				continue
			}
			half := len(pt.items) / 2
			a, b := pt.items[:half], pt.items[half:]
			parts = append([]part{
				{a, encode(rt.cfg.format, &rt.cfg.view, a), pt.encoding},
				{b, encode(rt.cfg.format, &rt.cfg.view, b), pt.encoding},
			}, parts[1:]...)
			continue
		}
		s.failed(r)
		wait := backoff(attempt)
		if r.verdict == retrySlow {
			wait = jitter(maxBackoff)
		}
		if r.after > 0 {
			wait = r.after
		}
		attempt++
		if !s.retryWait(ctx, wait) {
			return
		}
		// Retried for as long as the buffer holds the batch.
		if s.abandoned(f, parts) {
			return
		}
	}
}

// abandoned reports whether the buffer dropped f's events while it was
// retried; what is left of it counts as dropped for a full buffer.
func (s *sender) abandoned(f *flight, parts []part) bool {
	if s.buf.acked(s.name).less(f.end) {
		return false
	}
	n := 0
	for _, p := range parts {
		n += len(p.items)
	}
	s.metrics.Dropped(s.name, DropBufferFull, n)
	s.state.droppedFull(s.now())
	return true
}

// logEncodeFailure logs, once per sender, that a request couldn't be
// encoded and was dropped.
func (s *sender) logEncodeFailure(detail string) {
	if s.encodeFailed.CompareAndSwap(false, true) && s.log != nil {
		s.log("export: a request couldn't be encoded and was dropped", "sink", s.name, "detail", detail)
	}
}

func (s *sender) failed(r result) {
	s.metrics.Failed(s.name, r.kind)
	s.state.failed(s.now(), r)
}

// retryWait waits d before a retry.
func (s *sender) retryWait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-s.retryAfter(d):
		return true
	}
}

// backoff is the wait before attempt+1: full jitter under an exponential
// ceiling, from minBackoff (the first) to maxBackoff.
func backoff(attempt int) time.Duration {
	ceiling := maxBackoff
	if attempt < 6 {
		ceiling = min(minBackoff<<attempt, maxBackoff)
	}
	return jitter(ceiling)
}

// jitter is a wait drawn evenly up to ceiling (full jitter), at least a
// tenth of minBackoff.
func jitter(ceiling time.Duration) time.Duration {
	return max(rand.N(ceiling+1), minBackoff/10) // #nosec G404 -- jitter, not security
}
