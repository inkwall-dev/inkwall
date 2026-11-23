// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"math"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
)

func ip(s string) Key {
	k, ok := IPKey(netip.MustParseAddr(s), 56)
	if !ok {
		panic(s)
	}
	return k
}

func limit(s *Store, name string, requests int64, period time.Duration, burst int64) Limit {
	return s.Limit(Identity{PolicyUID: "uid", Name: name, Key: "ip/56"}, requests, period, burst)
}

// An entry has no pointers and takes 40 bytes: the table's size in the
// design (0009 §5.2) and the capacity's memory cap rest on it.
func TestEntryLayout(t *testing.T) {
	if n := unsafe.Sizeof(entry{}); n != entryBytes {
		t.Fatalf("entry is %d bytes, want %d", n, entryBytes)
	}
}

func TestGCRA(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	// 10 a minute in bursts of 20: one token every 6 s.
	l := limit(s, "login", 10, time.Minute, 20)
	for i := range 20 {
		if d := s.Take(l, k, t0, nil); !d.Allowed {
			t.Fatalf("request %d of the burst refused", i+1)
		}
	}
	d := s.Take(l, k, t0, nil)
	if d.Allowed || d.RetryAfter != 6*time.Second {
		t.Fatalf("past the burst: %+v, want refused, retry after 6s", d)
	}
	// Retry-After rounds up: 1 ns short of a token is still 1 s.
	if d := s.Take(l, k, t0.Add(6*time.Second-time.Nanosecond), nil); d.Allowed || d.RetryAfter != time.Second {
		t.Fatalf("1ns short: %+v, want retry after 1s", d)
	}
	if d := s.Take(l, k, t0.Add(6*time.Second), nil); !d.Allowed {
		t.Fatalf("after 6s: %+v, want a token", d)
	}
	// The same instant twice: no token in between.
	if d := s.Take(l, k, t0.Add(6*time.Second), nil); d.Allowed {
		t.Fatal("the same instant gave a second token")
	}
	// Idle for the whole burst's time: full again.
	t1 := t0.Add(6*time.Second + 20*6*time.Second)
	for i := range 20 {
		if d := s.Take(l, k, t1, nil); !d.Allowed {
			t.Fatalf("refilled burst: request %d refused", i+1)
		}
	}
	// Another key has its own bucket.
	if d := s.Take(l, ip("192.0.2.2"), t1, nil); !d.Allowed {
		t.Fatal("another key was refused")
	}
}

// One request an hour: Retry-After counts in seconds up to the hour.
func TestGCRALongPeriod(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	l := limit(s, "slow", 1, time.Hour, 0)
	k := ip("192.0.2.1")
	if !s.Take(l, k, t0, nil).Allowed {
		t.Fatal("first refused")
	}
	if d := s.Take(l, k, t0.Add(time.Second), nil); d.Allowed || d.RetryAfter != time.Hour-time.Second {
		t.Fatalf("%+v, want retry after 59m59s", d)
	}
}

// A changed rate applies at once to the TAT already there: the limit keeps
// its identity, ID and buckets.
func TestChangedRateKeepsBuckets(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	l := limit(s, "api", 2, time.Second, 2)
	s.Take(l, k, t0, nil)
	s.Take(l, k, t0, nil)
	if s.Take(l, k, t0, nil).Allowed {
		t.Fatal("over the burst allowed")
	}
	// Twice the burst, same identity: the two tokens spent still count.
	l2 := limit(s, "api", 2, time.Second, 4)
	if l2.ID() != l.ID() {
		t.Fatalf("a rate change changed the ID: %d, then %d", l.ID(), l2.ID())
	}
	n := 0
	for s.Take(l2, k, t0, nil).Allowed {
		n++
	}
	if n != 2 {
		t.Fatalf("after raising the burst to 4 with 2 spent, %d more allowed, want 2", n)
	}
	// A new name is a new limit, starting full.
	l3 := limit(s, "api-v2", 2, time.Second, 2)
	if l3.ID() == l.ID() || !s.Take(l3, k, t0, nil).Allowed {
		t.Fatal("a renamed limit didn't start full")
	}
}

func TestRefund(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	l := limit(s, "one", 1, time.Minute, 1)
	d := s.Take(l, k, t0, nil)
	if !d.Allowed {
		t.Fatal("first refused")
	}
	s.Refund(l, k, d)
	if !s.Take(l, k, t0, nil).Allowed {
		t.Fatal("the refunded token wasn't given back")
	}
	if s.Take(l, k, t0, nil).Allowed {
		t.Fatal("a second token appeared")
	}
	// A refund of a key the table doesn't hold does nothing.
	s.Refund(l, ip("192.0.2.9"), Decision{Allowed: true})
}

func TestIPKey(t *testing.T) {
	for _, tc := range []struct {
		a, b   string
		prefix int
		same   bool
	}{
		{"192.0.2.1", "::ffff:192.0.2.1", 56, true},
		{"192.0.2.1", "192.0.2.2", 56, false},
		{"2001:db8:0:1::1", "2001:db8:0:ff::2", 56, true},
		{"2001:db8:0:1::1", "2001:db8:0:100::1", 56, false},
		{"2001:db8:0:1::1", "2001:db8:0:1:ffff::1", 64, true},
		{"2001:db8:0:1::1", "2001:db8:0:2::1", 64, false},
		{"2001:db8::1", "2001:db8::2", 128, false},
		{"2001:db8::1", "2001:db8:ffff::1", 32, true},
	} {
		a, _ := IPKey(netip.MustParseAddr(tc.a), tc.prefix)
		b, _ := IPKey(netip.MustParseAddr(tc.b), tc.prefix)
		if (a == b) != tc.same {
			t.Errorf("%s and %s at /%d: same key %v, want %v", tc.a, tc.b, tc.prefix, a == b, tc.same)
		}
	}
	if _, ok := IPKey(netip.Addr{}, 56); ok {
		t.Error("the zero address has a key")
	}
	// A header hash is never the key of an address, whatever its bytes.
	s := New(1024, 0)
	h := s.HeaderKey("tenant-a")
	if h == ip("192.0.2.1") || h == s.HeaderKey("tenant-b") || h != s.HeaderKey("tenant-a") || !h.Valid() {
		t.Error("header keys aren't distinct and stable")
	}
	if (Key{}).Valid() {
		t.Error("the zero Key is valid")
	}
}

// fill makes every slot of every neighbourhood hold a bucket of l that
// isn't full, by spending one token of many keys.
func fill(s *Store, l Limit, t time.Time, n int) {
	for i := range n {
		var k Key
		k.tag = tagIPv4
		k.b[0], k.b[1], k.b[2], k.b[3] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		s.Take(l, k, t, nil)
	}
}

func TestEviction(t *testing.T) {
	s := New(minShards*neighbourhood, 0) // the smallest table: one neighbourhood a shard
	t0 := s.base.Add(time.Hour)
	l := limit(s, "a", 1, time.Hour, 10)
	slots := len(s.shards) * len(s.shards[0].e)
	fill(s, l, t0, 100*slots)
	if s.Keys() != int64(slots) {
		t.Fatalf("keys %d, want every slot (%d)", s.Keys(), slots)
	}
	if _, active := s.Evictions(); active == 0 {
		t.Fatal("a full table of buckets in use evicted none actively")
	}
}

// find claims, for a new key, an empty slot first, then a free entry (a
// full bucket, or a limit not live), and only then the bucket closest to
// full; only that last one counts as active.
func TestEvictionOrder(t *testing.T) {
	s := New(1, 0)
	l := limit(s, "a", 1, time.Hour, 10)
	dead := limit(s, "dead", 1, time.Hour, 10)
	live := NewLive(l)
	const now = int64(100 * time.Hour)
	sh := &s.shards[0]
	key := func(i int) Key { return Key{tag: tagIPv4, b: [16]byte{byte(i)}} }
	reset := func() {
		for j := range neighbourhood {
			// Every bucket in use, the one at slot 5 closest to full.
			tat := now + int64(2*time.Hour)
			if j == 5 {
				tat = now + int64(time.Hour)
			}
			sh.e[j] = entry{key: key(j + 1), id: l.id, tat: tat}
		}
	}
	claim := func() (int, uint64, uint64) {
		i0, a0 := s.Evictions()
		e := s.find(sh, 0, l.id, key(99), now, live)
		i1, a1 := s.Evictions()
		for j := range sh.e[:neighbourhood] {
			if &sh.e[j] == e {
				return j, i1 - i0, a1 - a0
			}
		}
		t.Fatal("find returned an entry outside the neighbourhood")
		return 0, 0, 0
	}
	for _, tc := range []struct {
		name   string
		setup  func()
		slot   int
		idle   uint64
		active uint64
	}{
		{"an empty slot", func() { sh.e[3] = entry{}; sh.e[6].tat = now - 1 }, 3, 0, 0},
		{"a full bucket", func() { sh.e[6].tat = now }, 6, 1, 0},
		{"a dead limit's entry", func() { sh.e[2].id = dead.id }, 2, 1, 0},
		{"the bucket closest to full", func() {}, 5, 0, 1},
	} {
		reset()
		tc.setup()
		slot, idle, active := claim()
		if slot != tc.slot || idle != tc.idle || active != tc.active {
			t.Errorf("%s: claimed slot %d (%d idle, %d active), want slot %d (%d idle, %d active)",
				tc.name, slot, idle, active, tc.slot, tc.idle, tc.active)
		}
	}
}

// The earliest TAT goes first: a key that stayed within its limit, but was
// limited longest ago, is forgotten before one being limited now.
func TestEvictionKeepsTheBusiest(t *testing.T) {
	s := New(minShards*neighbourhood, 0)
	t0 := s.base.Add(time.Hour)
	l := limit(s, "a", 1, time.Hour, 100)
	hot := ip("198.51.100.7")
	for range 100 {
		s.Take(l, hot, t0, nil) // its TAT: 100 hours ahead
	}
	fill(s, l, t0, 100*len(s.shards)*len(s.shards[0].e)) // each 1 hour ahead
	if s.Take(l, hot, t0, nil).Allowed {
		t.Fatal("the busiest key was forgotten")
	}
}

func TestLive(t *testing.T) {
	s := New(1024, 0)
	a, b, c := limit(s, "a", 1, time.Second, 1), limit(s, "b", 1, time.Second, 1), limit(s, "c", 1, time.Second, 1)
	live := NewLive(a, c)
	if !live.has(a.id) || live.has(b.id) || !live.has(c.id) || live.has(1000) {
		t.Fatal("Live holds the wrong IDs")
	}
	var none *Live
	if !none.has(b.id) {
		t.Fatal("the nil Live doesn't hold every ID")
	}
}

func TestSampling(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	l := limit(s, "a", 1, time.Hour, 1)
	s.Take(l, k, t0, nil)
	d := s.Take(l, k, t0, nil)
	if !d.Event || d.Sampled != 1 {
		t.Fatalf("first limited request: %+v, want an event standing for 1", d)
	}
	for i := range 9 {
		if d := s.Take(l, k, t0.Add(time.Duration(i+1)*time.Second), nil); d.Event {
			t.Fatalf("limited request %d within the minute made an event", i+2)
		}
	}
	d = s.Take(l, k, t0.Add(time.Minute), nil)
	if !d.Event || d.Sampled != 10 {
		t.Fatalf("a minute later: %+v, want an event standing for 10", d)
	}
}

func TestEventCaps(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	a, b := limit(s, "a", 1, time.Second, 1), limit(s, "b", 1, time.Second, 1)
	n := 0
	for range 1000 {
		if s.AllowEvent(a, t0) {
			n++
		}
	}
	// The engine's cap (10) is lower than the limit's (100).
	if n != EventsPerEngine {
		t.Fatalf("%d events kept at once, want the engine's %d", n, EventsPerEngine)
	}
	if s.AllowEvent(b, t0) {
		t.Fatal("another limit's event passed the engine-wide cap")
	}
	if s.EventsDropped() != 1000-EventsPerEngine+1 {
		t.Fatalf("dropped %d, want %d", s.EventsDropped(), 1000-EventsPerEngine+1)
	}
	if !s.AllowEvent(b, t0.Add(time.Second)) {
		t.Fatal("a second later the cap didn't refill")
	}
}

func TestCapacity(t *testing.T) {
	for _, tc := range []struct {
		keys     int
		memLimit int64
		want     int
	}{
		{DefaultKeys, 460 << 20, DefaultKeys},  // 90% of 512 MiB: room
		{10_000_000, 460 << 20, 2_562_457},     // a quarter of it, at 40 B and 85%
		{10_000_000, 0, 1_426_063},             // no limit: 64 MiB
		{10_000_000, math.MaxInt64, 1_426_063}, // GOMEMLIMIT unset
		{0, 0, 1},
	} {
		if got := Capacity(tc.keys, tc.memLimit); got != tc.want {
			t.Errorf("Capacity(%d, %d) = %d, want %d", tc.keys, tc.memLimit, got, tc.want)
		}
	}
	s := New(DefaultKeys, 460<<20)
	s.allocate()
	slots := len(s.shards) * len(s.shards[0].e)
	if slots*loadPercent/100 < s.Capacity() {
		t.Errorf("%d slots hold fewer than %d keys at %d%%", slots, s.Capacity(), loadPercent)
	}
}

// Under concurrent requests of one key no limit admits more than its burst
// at one instant, and charging several limits with refunds leaves none
// charged for a refused request.
func TestConcurrent(t *testing.T) {
	s := New(4096, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	tight := limit(s, "tight", 1, time.Hour, 50)
	loose := limit(s, "loose", 1, time.Hour, 200)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				// Block limits in order, refunding when a later one refuses.
				d := s.Take(loose, k, t0, nil)
				if !d.Allowed {
					continue
				}
				if !s.Take(tight, k, t0, nil).Allowed {
					s.Refund(loose, k, d)
					continue
				}
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 50 {
		t.Fatalf("%d requests allowed, want the tight limit's burst of 50", allowed.Load())
	}
	// loose spent exactly the 50 allowed: 150 tokens left.
	n := 0
	for s.Take(loose, k, t0, nil).Allowed {
		n++
	}
	if n != 150 {
		t.Fatalf("loose has %d tokens left, want 150 (refunds lost or doubled)", n)
	}
}

// The metrics register together, with one series per eviction kind.
func TestCollectors(t *testing.T) {
	s := New(1024, 0)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(s.Collectors()...)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	series := map[string]int{}
	for _, mf := range mfs {
		series[mf.GetName()] = len(mf.GetMetric())
	}
	if series["inkwall_rate_limit_evictions_total"] != 3 || series["inkwall_rate_limit_exceeded_total"] != 2 || series["inkwall_rate_limit_keys"] != 1 || series["inkwall_rate_limit_overflow_total"] != 1 || len(series) != 7 {
		t.Errorf("metrics %v", series)
	}
}

// An event the caps dropped gives its count back: the key's next event
// stands for those requests too.
func TestUnsample(t *testing.T) {
	s := New(1024, 0)
	t0 := s.base.Add(time.Hour)
	k := ip("192.0.2.1")
	l := limit(s, "a", 1, time.Hour, 1)
	s.Take(l, k, t0, nil)
	d := s.Take(l, k, t0, nil) // the first limited: an event of 1
	s.Unsample(l, k, d.Sampled)
	s.Take(l, k, t0.Add(time.Second), nil) // not sampled: within the minute
	if d := s.Take(l, k, t0.Add(time.Minute), nil); !d.Event || d.Sampled != 3 {
		t.Errorf("the next event: %+v, want one standing for 3 (1 given back, 2 since)", d)
	}
	s.Unsample(l, ip("192.0.2.9"), 5) // a key it doesn't hold: nothing
}

// headerKey is the i-th of an attacker's header values.
func headerKey(s *Store, i int) Key { return s.HeaderKey("attacker-" + strconv.Itoa(i)) }

// A bucket over its limit stays limited while an attacker sends one
// request per new header value of another limit, twice the table's
// capacity: with a long interval, the attacker's TATs are later than the
// limited bucket's, which eviction by the earliest TAT would forget. Its
// keys are either over their own limit (burst 1) and so kept, the overflow
// counting the rest, or within it and evicted first.
//
// At most half a neighbourhood of victims share a shard, so their limit
// never holds more than its share of one: there, over-share eviction may
// reset one of them, as it should (TestOverShareBoundary). Picking the
// victims by where the Store's seed puts them keeps the test the same
// whatever the seed.
func TestEvictionKeepsALimitedBucket(t *testing.T) {
	for _, burst := range []int64{1, 2, 100} {
		t.Run("attacker burst "+strconv.FormatInt(burst, 10), func(t *testing.T) {
			s := New(minShards*neighbourhood, 0)
			t0 := s.base.Add(time.Hour)
			login := limit(s, "login", 5, time.Hour, 5)
			flood := s.Limit(Identity{PolicyUID: "uid", Name: "flood", Key: "header/x-key/ip/56"}, 1, time.Hour, burst)
			victims := make([]Key, 64)
			perShard := map[*shard]int{}
			for i, n := 0, 0; i < len(victims); n++ {
				k := ip(netip.AddrFrom4([4]byte{198, 51, byte(n >> 8), byte(n)}).String())
				sh, _, _ := s.locate(login.id, k)
				if perShard[sh] == neighbourhood/2 {
					continue
				}
				perShard[sh]++
				victims[i] = k
				i++
			}
			for i := range victims {
				for range 6 {
					s.Take(login, victims[i], t0, nil)
				}
				if s.Take(login, victims[i], t0, nil).Allowed {
					t.Fatal("the victim isn't over its limit")
				}
			}
			slots := len(s.shards) * len(s.shards[0].e)
			for i := range 2 * slots {
				s.Take(flood, headerKey(s, i), t0.Add(time.Duration(i)*time.Microsecond), nil)
			}
			_, active := s.Evictions()
			for i, v := range victims {
				if s.Take(login, v, t0.Add(time.Second), nil).Allowed {
					t.Fatalf("victim %d was reset: %d active evictions, %d overflows", i, active, s.Overflows())
				}
			}
			if burst == 1 && s.Overflows() == 0 {
				t.Error("a table of buckets over their limits overflowed none")
			}
			if burst > 1 && active == 0 {
				t.Error("the attacker's buckets within their limit weren't evicted")
			}
		})
	}
}

// Over-share eviction applies to every limit, a victim's included: in a
// neighbourhood of protected buckets, a new key of another limit evicts one
// of a limit holding more than its share (5 of 8 with two limits), and is
// counted in an overflow bucket when it holds just its share (4 of 8).
func TestOverShareBoundary(t *testing.T) {
	for _, tc := range []struct {
		login   int
		evicted bool
	}{{5, true}, {4, false}} {
		t.Run(strconv.Itoa(tc.login)+" of "+strconv.Itoa(neighbourhood), func(t *testing.T) {
			s := New(1, 0)
			login := limit(s, "login", 5, time.Hour, 5)
			flood := s.Limit(Identity{PolicyUID: "uid", Name: "flood", Key: "header/x-key/ip/56"}, 1, time.Hour, 1)
			const now = int64(100 * time.Hour)
			sh := &s.shards[0]
			for j := range neighbourhood {
				e := entry{key: Key{tag: tagIPv4, b: [16]byte{byte(j + 1)}}, id: flood.id, tat: now + int64(time.Hour)} // over
				if j < tc.login {
					e.id, e.sampled = login.id, seconds(now) // over and limited now
				}
				sh.e[j] = e
			}
			before := slices.Clone(sh.e)
			e := s.find(sh, 0, flood.id, Key{tag: tagHeader, b: [16]byte{99}}, now, nil)
			switch {
			case tc.evicted && (e == nil || e != &sh.e[0] || s.EvictionsOverShare() != 1):
				t.Fatalf("login over its share: got %p (slot 0 is %p), %d over-share evictions", e, &sh.e[0], s.EvictionsOverShare())
			case !tc.evicted && (e != nil || !slices.Equal(sh.e, before) || s.EvictionsOverShare() != 0):
				t.Fatalf("login at its share lost a bucket: got %p, %d over-share evictions", e, s.EvictionsOverShare())
			}
		})
	}
}

// Fullness is relative to each limit's own capacity: a bucket a tenth
// into a 10-hour burst goes before one at half of a 2-hour burst, though
// its TAT is later.
func TestEvictionRelativeToBurst(t *testing.T) {
	s := New(1, 0)
	long := limit(s, "long", 1, time.Hour, 10)  // capacity 10h
	short := limit(s, "short", 1, time.Hour, 2) // capacity 2h
	const now = int64(100 * time.Hour)
	sh := &s.shards[0]
	for j := range neighbourhood {
		sh.e[j] = entry{key: Key{tag: tagIPv4, b: [16]byte{byte(j + 1)}}, id: short.id, tat: now + int64(time.Hour)} // half
	}
	sh.e[4] = entry{key: Key{tag: tagIPv4, b: [16]byte{5}}, id: long.id, tat: now + int64(time.Hour) + 1} // a tenth
	if e := s.find(sh, 0, long.id, Key{tag: tagIPv4, b: [16]byte{99}}, now, nil); e != &sh.e[4] {
		t.Fatal("evicted a bucket fuller for its limit")
	}
}

// The review's scenario: an attacker fills the table with buckets over a
// cheap header-keyed limit (2 requests a key on 1 an hour: protected for an
// hour), then floods another limit, M, from one address. M's honest new
// clients, on any policy sharing the Store, are still counted on their own
// and allowed: the attacker's limit holds more than its share of every
// neighbourhood, so its buckets give way.
func TestFilledTableDoesNotDenyOthers(t *testing.T) {
	s := New(minShards*neighbourhood, 0)
	t0 := s.base.Add(time.Hour)
	cheap := s.Limit(Identity{PolicyUID: "attacker", Name: "cheap", Key: "header/x-key/ip/56"}, 1, time.Hour, 1)
	m := s.Limit(Identity{PolicyUID: "tenant", Name: "login", Key: "ip/56"}, 5, time.Minute, 5)
	live := NewLive(cheap, m)
	slots := len(s.shards) * len(s.shards[0].e)
	for i := range 2 * slots {
		k := headerKey(s, i)
		s.Take(cheap, k, t0, live)
		s.Take(cheap, k, t0, live) // over: protected
	}
	attacker := ip("203.0.113.7")
	for range 1000 {
		s.Take(m, attacker, t0, live)
	}
	if s.Take(m, attacker, t0, live).Allowed {
		t.Error("the flooding address isn't limited")
	}
	for i := range 500 {
		honest := ip(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}).String())
		if !s.Take(m, honest, t0.Add(time.Second), live).Allowed {
			t.Fatalf("honest client %d of M refused: %d overflows, %d over-share evictions", i, s.Overflows(), s.EvictionsOverShare())
		}
	}
	if s.EvictionsOverShare() == 0 {
		t.Error("no over-share eviction")
	}
}

// A Detect limit's buckets (Observe) are never protected: an observe-only
// policy can't push a Block limit's new keys into overflow buckets.
func TestObservedBucketsAreNotProtected(t *testing.T) {
	s := New(minShards*neighbourhood, 0)
	t0 := s.base.Add(time.Hour)
	detect := limit(s, "detect", 1, time.Hour, 1)
	block := limit(s, "block", 5, time.Minute, 5)
	slots := len(s.shards) * len(s.shards[0].e)
	for i := range 2 * slots {
		k := headerKey(s, i)
		s.Observe(detect, k, t0, nil)
		s.Observe(detect, k, t0, nil) // over, and sampled
	}
	for i := range 500 {
		k := ip(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}).String())
		if !s.Take(block, k, t0, nil).Allowed {
			t.Fatalf("key %d refused", i)
		}
	}
	if s.Overflows() != 0 || s.EvictionsOverShare() != 0 {
		t.Errorf("%d overflows, %d over-share evictions: observed buckets were protected", s.Overflows(), s.EvictionsOverShare())
	}
}

// When every entry is protected and no limit holds more than its share, a
// new key is counted in the overflow bucket its hash picks, shared only
// with the keys of that bucket, and Wait and Refund find it there.
func TestOverflow(t *testing.T) {
	s := New(1, 0)
	l := limit(s, "a", 1, time.Hour, 2)
	const now = int64(100 * time.Hour)
	sh := &s.shards[0]
	sec := seconds(now)
	var before []entry
	for si := range s.shards {
		for j := range s.shards[si].e {
			e := entry{key: Key{tag: tagIPv6, b: [16]byte{byte(si), byte(j)}}, id: l.id, tat: now + int64(2*time.Hour)} // over
			if j%2 == 1 {
				e.tat, e.sampled = now+int64(time.Minute), sec-60 // within, but limited a minute ago
			}
			s.shards[si].e[j] = e
		}
		before = append(before, s.shards[si].e...)
	}
	entries := func() []entry {
		var all []entry
		for si := range s.shards {
			all = append(all, s.shards[si].e...)
		}
		return all
	}
	t0 := s.base.Add(time.Duration(now))
	// a and b have one overflow bucket, c another.
	var a, b, c Key
	bucket := func(k Key) uint8 { _, _, o := s.locate(l.id, k); return o }
	for n := 0; c.tag == 0; n++ {
		k := Key{tag: tagIPv4, b: [16]byte{200, byte(n >> 8), byte(n)}}
		switch {
		case a.tag == 0:
			a = k
		case b.tag == 0 && bucket(k) == bucket(a):
			b = k
		case b.tag != 0 && bucket(k) != bucket(a):
			c = k
		}
	}
	da, db := s.Take(l, a, t0, nil), s.Take(l, b, t0, nil)
	if !da.Allowed || !db.Allowed || !da.overflow {
		t.Fatal("the overflow bucket starts full")
	}
	if d := s.Take(l, a, t0, nil); d.Allowed || d.RetryAfter != time.Hour {
		t.Fatalf("two new keys share their overflow bucket's burst of 2: %+v", d)
	}
	if !s.Take(l, c, t0, nil).Allowed {
		t.Fatal("a key of another overflow bucket was refused")
	}
	if s.Overflows() != 4 || !slices.Equal(entries(), before) {
		t.Fatalf("%d overflows, entries changed: %v", s.Overflows(), !slices.Equal(entries(), before))
	}
	if w := s.Wait(l, b, t0); w != time.Hour {
		t.Errorf("Wait %v, want the overflow bucket's hour", w)
	}
	s.Refund(l, b, db)
	if w := s.Wait(l, b, t0); w != 0 {
		t.Errorf("Wait after a refund %v, want 0", w)
	}
	// A refund for a decision the table made (a key since evicted)
	// doesn't credit the overflow bucket.
	s.Take(l, b, t0, nil)
	s.Refund(l, b, Decision{Allowed: true})
	if w := s.Wait(l, b, t0); w != time.Hour {
		t.Errorf("a table refund credited the overflow bucket: Wait %v", w)
	}
	// A Detect limit's key isn't counted in an overflow bucket.
	if d := s.Observe(l, a, t0, nil); !d.Allowed {
		t.Errorf("Observe counted a key in an overflow bucket: %+v", d)
	}
	// Once one ages out of being protected, it is evicted instead.
	later := now + int64(recentlyLimited) // the sampled ones: no longer recent, still in use
	if e := s.find(sh, 0, l.id, Key{tag: tagIPv4, b: [16]byte{202}}, later, nil); e == nil {
		t.Fatal("no entry once some aged out of being protected")
	}
}
