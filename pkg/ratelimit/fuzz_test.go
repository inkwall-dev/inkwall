// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

// FuzzTake checks the store against a reference token bucket in floating
// point, for random sequences of (key, time step). With room for every key,
// a request is allowed exactly when the model has a token (within rounding:
// the interval is whole nanoseconds), and a refusal's Retry-After is the
// model's wait rounded up to whole seconds, at least one. With the table
// forced tiny, evictions only forget state: decisions stay well formed;
// and while an attacker floods it with new keys of another limit, a key
// the table refused stays refused until its Retry-After (less the second
// it is rounded up by): a bucket over its limit is evicted only when its
// limit holds more than its share of the slots (counted as over_share).
func FuzzTake(f *testing.F) {
	f.Add(uint16(10), uint16(60), uint16(20), []byte{0, 0, 0, 1, 0, 2, 5, 0})
	f.Add(uint16(1), uint16(3600), uint16(1), []byte{1, 0, 1, 255, 1, 255})
	f.Add(uint16(1000), uint16(1), uint16(1), []byte{3, 1, 3, 1, 3, 1, 3, 1})
	f.Add(uint16(7), uint16(3), uint16(0), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4})
	f.Fuzz(func(t *testing.T, requests, periodSec, burst uint16, ops []byte) {
		if requests == 0 || periodSec == 0 || periodSec > 3600 || len(ops) > 4096 {
			return
		}
		period := time.Duration(periodSec) * time.Second
		big, tiny := New(1024, 0), New(1, 0)
		bl := big.Limit(Identity{Name: "f"}, int64(requests), period, int64(burst))
		tl := tiny.Limit(Identity{Name: "f"}, int64(requests), period, int64(burst))
		flood := tiny.Limit(Identity{Name: "flood"}, 1, time.Hour, 1+int64(requests%3))
		refusedUntil := map[byte]time.Duration{}
		overShareAt := map[byte]uint64{} // EvictionsOverShare at the refusal
		floodKeys := 0
		// The model uses the store's whole-nanosecond interval, so the two
		// agree but for float rounding.
		rate := float64(time.Second) / float64(bl.interval)
		capacity := float64(bl.burst)
		type model struct {
			tokens float64
			at     time.Duration
		}
		models := map[byte]*model{}
		t0 := big.base.Add(time.Hour)
		t1 := tiny.base.Add(time.Hour)
		now := time.Duration(0)
		for i := 0; i+1 < len(ops); i += 2 {
			key, step := ops[i]%8, ops[i+1]
			now += time.Duration(step) * 100 * time.Millisecond
			m := models[key]
			if m == nil {
				m = &model{tokens: capacity, at: now}
				models[key] = m
			}
			m.tokens = min(capacity, m.tokens+(now-m.at).Seconds()*rate)
			m.at = now
			k := Key{tag: tagIPv4}
			k.b[0] = key

			d := big.Take(bl, k, t0.Add(now), nil)
			const eps = 1e-6
			switch {
			case d.Allowed:
				if m.tokens < 1-eps {
					t.Fatalf("op %d: allowed with %.9f tokens in the model", i/2, m.tokens)
				}
				m.tokens = max(m.tokens-1, 0)
			case m.tokens >= 1+eps:
				t.Fatalf("op %d: refused with %.9f tokens in the model", i/2, m.tokens)
			default:
				need := (1 - m.tokens) / rate // seconds
				if d.RetryAfter < time.Second || d.RetryAfter%time.Second != 0 {
					t.Fatalf("op %d: Retry-After %v, not whole seconds ≥ 1", i/2, d.RetryAfter)
				}
				if s := d.RetryAfter.Seconds(); s+eps < need || s > max(need, 1)+1+eps {
					t.Fatalf("op %d: Retry-After %v, but a token comes in %.6fs", i/2, d.RetryAfter, need)
				}
			}

			for range 4 {
				floodKeys++
				tiny.Take(flood, tiny.HeaderKey(strconv.Itoa(floodKeys)), t1.Add(now), nil)
			}
			d = tiny.Take(tl, k, t1.Add(now), nil)
			if !d.Allowed && (d.RetryAfter < time.Second || d.RetryAfter > period*time.Duration(max(burst, 1))+time.Second) {
				t.Fatalf("op %d: tiny table: Retry-After %v", i/2, d.RetryAfter)
			}
			if d.Allowed && now < refusedUntil[key] && tiny.EvictionsOverShare() == overShareAt[key] {
				t.Fatalf("op %d: tiny table: key %d allowed %v before its Retry-After: its bucket was reset", i/2, key, refusedUntil[key]-now)
			}
			if !d.Allowed && held(tiny, tl, k) {
				refusedUntil[key] = max(refusedUntil[key], now+d.RetryAfter-time.Second)
				overShareAt[key] = tiny.EvictionsOverShare()
			}
		}
		if n := tiny.Keys(); n > int64(len(tiny.shards)*len(tiny.shards[0].e)) {
			t.Fatalf("tiny table holds %d keys, more than its slots", n)
		}
	})
}

// held reports whether s holds key k's bucket of l in the table (not in
// the overflow bucket).
func held(s *Store, l Limit, k Key) bool {
	sh, i, _ := s.locate(l.id, k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for j := range uint64(neighbourhood) {
		if e := &sh.e[(i+j)&s.slotMask]; e.id == l.id && e.key == k {
			return true
		}
	}
	return false
}
