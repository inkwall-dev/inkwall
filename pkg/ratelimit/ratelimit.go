// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit holds the token buckets of a policy's rate limits
// (design 0009, #705): one engine-wide Store of every limit's buckets, per
// key, in a fixed-size table.
//
// A bucket is stored with the generic cell rate algorithm (GCRA): one
// int64, the time at which it will be full again (the theoretical arrival
// time, TAT). A bucket whose TAT is past is full, exactly as if it were
// absent, which is what makes evicting it safe.
//
// The table is sharded: each shard is a mutex and an open-addressed array
// of 40-byte entries with no pointers, so the garbage collector never scans
// it and nothing is allocated per request. A key lives in the 8 slots from
// its hashed one; when they are all taken, a free entry (a full bucket, or
// one of a limit no longer in the bundle) is reused first, then the one
// closest to full for its own limit. A bucket over its limit, or limited
// recently, is never reused: when every entry is one, the new key is
// counted in its limit's overflow bucket, shared by such keys.
package ratelimit

import (
	"encoding/binary"
	"hash/maphash"
	"math"
	"math/bits"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultKeys is the table's default capacity: buckets held at once per
// engine (--rate-limit-keys).
const DefaultKeys = 262_144

const (
	// entryBytes is an entry's size, padding included.
	entryBytes = 40
	// loadPercent is the most of the table's slots that capacity fills.
	loadPercent = 85
	// neighbourhood is the slots a key may occupy, from its hashed one.
	neighbourhood = 8
	// minShards is the fewest shards, whatever GOMAXPROCS.
	minShards = 64
	// noLimitBytes is the table's memory cap without GOMEMLIMIT.
	noLimitBytes = 64 << 20
	// sampleEvery is the most often one key's limited requests make an
	// event.
	sampleEvery = time.Minute
)

// Key tags: a header hash never equals an address of the same limit.
const (
	tagIPv4 uint8 = iota + 1
	tagIPv6
	tagHeader
)

// Key is what a limit counts by: a client address, masked, or a keyed hash
// of a header's value. The zero Key is no key.
type Key struct {
	tag uint8
	b   [16]byte
}

// Valid reports whether k is a key.
func (k Key) Valid() bool { return k.tag != 0 }

// IPKey is the key of the client address a: IPv4 by its address (an
// IPv4-mapped IPv6 address counts as IPv4), IPv6 by its first v6Prefix
// bits. It reports false for an invalid address, which no IP key counts.
func IPKey(a netip.Addr, v6Prefix int) (Key, bool) {
	if !a.IsValid() {
		return Key{}, false
	}
	a = a.Unmap()
	if a.Is4() {
		k := Key{tag: tagIPv4}
		b := a.As4()
		copy(k.b[:], b[:])
		return k, true
	}
	p, err := a.Prefix(min(max(v6Prefix, 0), 128))
	if err != nil {
		return Key{}, false
	}
	return Key{tag: tagIPv6, b: p.Addr().As16()}, true
}

// HeaderKey is the key of a header's value: a 64-bit hash keyed with the
// Store's seed, so neither memory nor events hold the value.
func (s *Store) HeaderKey(value string) Key {
	k := Key{tag: tagHeader}
	binary.LittleEndian.PutUint64(k.b[:], maphash.String(s.seed, value))
	return k
}

// Limit is a compiled rate limit: requests per period per key, in bursts of
// at most burst.
type Limit struct {
	id       uint32
	interval int64 // nanoseconds per token: period / requests
	burst    int64
}

// ID is the limit's ID in its Store.
func (l Limit) ID() uint32 { return l.id }

// Store holds the buckets of every limit of every policy, shared by every
// bundle's compiled policies, so a bundle swap keeps them. It is safe for
// concurrent use.
type Store struct {
	alloc     sync.Once // the table, at the first Limit
	perShard  int
	seed      maphash.Seed
	base      time.Time // the zero of entries' times, on the monotonic clock
	shards    []shard
	shardMask uint64
	slotMask  uint64
	capacity  int

	mu     sync.Mutex
	ids    map[Identity]uint32
	nextID uint32
	// params are what eviction needs of each limit, by ID (limitParams):
	// copied on write, under mu.
	params atomic.Pointer[[]limitParams]

	// overflow is each limit's shared bucket for the new keys no entry
	// could be found for (find); overflowing counts them, so that a Store
	// that never overflowed doesn't look.
	overMu      sync.Mutex
	overflow    map[uint32]*entry
	overflowing atomic.Int32

	keys         atomic.Int64
	evictIdle    atomic.Uint64
	evictActive  atomic.Uint64
	overflows    atomic.Uint64
	skippedNoKey atomic.Uint64
	overDeny     atomic.Uint64 // requests over a Block limit
	overLog      atomic.Uint64 // over a Detect limit (or on a Detect policy)
	events       eventCaps
}

// Identity names a limit across bundles: the same identity keeps its ID,
// and so its buckets, whatever its rate and burst.
type Identity struct {
	// PolicyUID is the policy's UID.
	PolicyUID string
	// Name is the limit's name, unique in the policy.
	Name string
	// Key is the key spec, for example "ip/56" or "header/x-api-key".
	Key string
}

type shard struct {
	mu sync.Mutex
	e  []entry
	_  [40]byte // apart from the next shard's mutex
}

// limitParams are what eviction needs of a limit: over, the debt (TAT −
// now) past which its next request is refused, (burst − 1) × interval; and
// its capacity, burst × interval. capacity 0: no such limit.
type limitParams struct {
	over     int64
	capacity float64
}

// entry is one bucket. id 0 is an empty slot.
type entry struct {
	key     Key    // 17 bytes
	id      uint32 // at 20
	tat     int64  // at 24: nanoseconds since Store.base
	sampled uint32 // at 32: the second (since base, +1) of the last event; 0: none
	limited uint32 // at 36: requests limited since the last event
}

// New returns a Store of at most keys buckets, fewer when keys entries
// would take more than a quarter of memLimit (the Go runtime's soft memory
// limit, GOMEMLIMIT; math.MaxInt64 or less than 1 means none, and then 64
// MiB at most). Capacity reports what it holds.
func New(keys int, memLimit int64) *Store {
	keys = Capacity(keys, memLimit)
	shards := max(minShards, 1<<bits.Len(uint(4*runtime.GOMAXPROCS(0)-1)))
	// The slots for keys at the load factor, a power of two per shard.
	slots := (keys*100/loadPercent + shards - 1) / shards
	perShard := max(neighbourhood, 1<<bits.Len(uint(max(slots, 1)-1)))
	s := &Store{
		perShard:  perShard,
		seed:      maphash.MakeSeed(),
		base:      time.Now(),
		shards:    make([]shard, shards),
		shardMask: uint64(shards - 1),
		slotMask:  uint64(perShard - 1),
		capacity:  keys,
		ids:       map[Identity]uint32{},
	}
	s.events.init()
	return s
}

// allocate makes the table, once: an engine whose bundles have no limits
// never holds it.
func (s *Store) allocate() {
	s.alloc.Do(func() {
		for i := range s.shards {
			s.shards[i].e = make([]entry, s.perShard)
		}
	})
}

// Capacity is the buckets a Store of keys holds under memLimit: keys, or
// fewer when they would take more than a quarter of memLimit, or of 64 MiB
// without one.
func Capacity(keys int, memLimit int64) int {
	budget := int64(noLimitBytes)
	if memLimit > 0 && memLimit < math.MaxInt64 {
		budget = memLimit / 4
	}
	most := budget * loadPercent / 100 / entryBytes
	return int(max(min(int64(max(keys, 1)), most), 1))
}

// Capacity is the buckets the Store holds at most.
func (s *Store) Capacity() int { return s.capacity }

// Keys is the buckets the Store holds now, full ones included until they
// are reused.
func (s *Store) Keys() int64 { return s.keys.Load() }

// Evictions reports the entries reused for a new key: idle ones (a full
// bucket, or a limit no longer live: nothing lost) and active ones (the
// bucket closest to full, whose state is forgotten).
func (s *Store) Evictions() (idle, active uint64) {
	return s.evictIdle.Load(), s.evictActive.Load()
}

// Overflows reports the requests of new keys counted in their limit's
// overflow bucket: every entry of their neighbourhood was over its limit,
// or limited recently, which are never evicted.
func (s *Store) Overflows() uint64 { return s.overflows.Load() }

// Intern returns the ID of a limit's identity, the same for the life of the
// Store. IDs are never reused.
func (s *Store) Intern(id Identity) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.ids[id]; ok {
		return n
	}
	s.nextID++
	s.ids[id] = s.nextID
	return s.nextID
}

// Limit compiles a limit of the identity id: requests per period, in bursts
// of burst (requests when not positive). requests and period are at least
// 1 and 1ns.
func (s *Store) Limit(id Identity, requests int64, period time.Duration, burst int64) Limit {
	s.allocate()
	requests = max(requests, 1)
	if burst <= 0 {
		burst = requests
	}
	l := Limit{
		id:       s.Intern(id),
		interval: max(int64(period)/requests, 1),
		burst:    burst,
	}
	s.setParams(l)
	return l
}

// setParams records what eviction needs of l (limitParams): the latest
// compiled, when a bundle changes the rate.
func (s *Store) setParams(l Limit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ps []limitParams
	if old := s.params.Load(); old != nil {
		ps = *old
	}
	p := limitParams{over: (l.burst - 1) * l.interval, capacity: float64(l.burst) * float64(l.interval)}
	if int(l.id) < len(ps) && ps[l.id] == p {
		return
	}
	next := make([]limitParams, max(len(ps), int(l.id)+1))
	copy(next, ps)
	next[l.id] = p
	s.params.Store(&next)
}

// Live is the set of limit IDs of one compiled bundle: an entry of a limit
// not in it is free. The nil Live holds every ID.
type Live struct{ bits []uint64 }

// NewLive returns the set of limits.
func NewLive(limits ...Limit) *Live {
	l := &Live{}
	for _, lim := range limits {
		l.Add(lim)
	}
	return l
}

// Add adds l to the set.
func (s *Live) Add(l Limit) {
	if s == nil {
		return
	}
	w := int(l.id / 64)
	for len(s.bits) <= w {
		s.bits = append(s.bits, 0)
	}
	s.bits[w] |= 1 << (l.id % 64)
}

func (l *Live) has(id uint32) bool {
	if l == nil {
		return true
	}
	w := int(id / 64)
	return w < len(l.bits) && l.bits[w]&(1<<(id%64)) != 0
}

// Decision is a limit's answer for one request.
type Decision struct {
	// Allowed is whether the request is within the limit (it was charged).
	Allowed bool
	// RetryAfter is, when not Allowed, how long until it would be: whole
	// seconds, at least one.
	RetryAfter time.Duration
	// Event is whether this limited request becomes a security event: the
	// key's first limited request, then one a minute.
	Event bool
	// Sampled is, with Event, the limited requests the event stands for,
	// this one included.
	Sampled uint32
}

// Take checks the request of key k at t against l and, when it is within
// the limit, charges it, in one step. live is the compiled bundle's set of
// limits, for reusing the entries of others.
func (s *Store) Take(l Limit, k Key, t time.Time, live *Live) Decision {
	now := int64(t.Sub(s.base))
	sh, i := s.locate(l.id, k)
	sh.mu.Lock()
	e := s.find(sh, i, l.id, k, now, live)
	if e == nil {
		sh.mu.Unlock()
		return s.takeOverflow(l, now)
	}
	d := charge(e, l, now)
	sh.mu.Unlock()
	return d
}

// charge checks a request at now against e, of limit l, and charges it
// when it is within the limit. Called with e's lock held.
func charge(e *entry, l Limit, now int64) Decision {
	tat := max(e.tat, now)
	over := tat + l.interval - now - l.burst*l.interval
	if over <= 0 {
		e.tat = tat + l.interval
		return Decision{Allowed: true}
	}
	return refuse(e, over, now)
}

// refuse is charge's refusal of a request over the limit by over.
func refuse(e *entry, over, now int64) Decision {
	d := Decision{RetryAfter: ceilSeconds(over)}
	e.limited++
	sec := seconds(now)
	if e.sampled == 0 || int64(sec-e.sampled) >= int64(sampleEvery/time.Second) {
		d.Event, d.Sampled = true, e.limited
		e.sampled, e.limited = sec, 0
	}
	return d
}

// seconds is now as entries' sampled holds it: the second since base, +1.
func seconds(now int64) uint32 {
	return uint32(min(now/int64(time.Second)+1, math.MaxUint32)) //nolint:gosec // bounded by min
}

// takeOverflow charges a request of a new key to its limit's overflow
// bucket: one bucket for every such key of the limit, so they share the
// limit's rate (conservative), rather than one of them resetting a bucket
// that is limiting a client.
func (s *Store) takeOverflow(l Limit, now int64) Decision {
	s.overflows.Add(1)
	s.overMu.Lock()
	defer s.overMu.Unlock()
	e := s.overflow[l.id]
	if e == nil {
		if s.overflow == nil {
			s.overflow = map[uint32]*entry{}
		}
		e = &entry{id: l.id, tat: now}
		s.overflow[l.id] = e
		s.overflowing.Add(1)
	}
	return charge(e, l, now)
}

// overflowEntry calls f with l's overflow bucket, locked, if it has one.
func (s *Store) overflowEntry(l Limit, f func(*entry)) {
	if s.overflowing.Load() == 0 {
		return
	}
	s.overMu.Lock()
	defer s.overMu.Unlock()
	if e := s.overflow[l.id]; e != nil {
		f(e)
	}
}

// Wait is how long until key k's request at t would be within l, without
// charging it: 0 when it is now, whole seconds otherwise.
func (s *Store) Wait(l Limit, k Key, t time.Time) time.Duration {
	now := int64(t.Sub(s.base))
	wait := func(e *entry) time.Duration {
		if over := max(e.tat, now) + l.interval - now - l.burst*l.interval; over > 0 {
			return ceilSeconds(over)
		}
		return 0
	}
	sh, i := s.locate(l.id, k)
	sh.mu.Lock()
	for j := range uint64(neighbourhood) {
		e := &sh.e[(i+j)&s.slotMask]
		if e.id == l.id && e.key == k {
			d := wait(e)
			sh.mu.Unlock()
			return d
		}
	}
	sh.mu.Unlock()
	// Not held: counted in the overflow bucket, if anywhere.
	var d time.Duration
	s.overflowEntry(l, func(e *entry) { d = wait(e) })
	return d
}

// Refund gives back the token a request took from l for key k, when a
// later limit refused it.
func (s *Store) Refund(l Limit, k Key) {
	sh, i := s.locate(l.id, k)
	sh.mu.Lock()
	for j := range uint64(neighbourhood) {
		e := &sh.e[(i+j)&s.slotMask]
		if e.id == l.id && e.key == k {
			e.tat -= l.interval
			sh.mu.Unlock()
			return
		}
	}
	sh.mu.Unlock()
	s.overflowEntry(l, func(e *entry) { e.tat -= l.interval })
}

// SkippedNoKey counts a request an IP limit couldn't count: no valid client
// address.
func (s *Store) SkippedNoKey() { s.skippedNoKey.Add(1) }

// Exceeded counts a request over a limit: denied, or logged (detect).
func (s *Store) Exceeded(detect bool) {
	if detect {
		s.overLog.Add(1)
	} else {
		s.overDeny.Add(1)
	}
}

// Unsample gives back the n limited requests a sampled event stood for,
// when the event caps dropped it: the key's next event counts them.
func (s *Store) Unsample(l Limit, k Key, n uint32) {
	sh, i := s.locate(l.id, k)
	sh.mu.Lock()
	for j := range uint64(neighbourhood) {
		e := &sh.e[(i+j)&s.slotMask]
		if e.id == l.id && e.key == k {
			e.limited += n
			sh.mu.Unlock()
			return
		}
	}
	sh.mu.Unlock()
	s.overflowEntry(l, func(e *entry) { e.limited += n })
}

func (s *Store) locate(id uint32, k Key) (*shard, uint64) {
	var b [21]byte
	binary.LittleEndian.PutUint32(b[:4], id)
	b[4] = k.tag
	copy(b[5:], k.b[:])
	h := maphash.Bytes(s.seed, b[:])
	return &s.shards[h&s.shardMask], (h >> 32) & s.slotMask
}

// find returns the entry of (id, k) in its neighbourhood from slot i,
// claiming one when there is none: an empty slot, else a free entry, else
// the bucket closest to full for its own limit (the least debt for its
// burst) of those that aren't protected (protected). nil: every entry is
// protected, and the key isn't held. Called with the shard locked.
func (s *Store) find(sh *shard, i uint64, id uint32, k Key, now int64, live *Live) *entry {
	var empty, free, victim *entry
	var (
		params         []limitParams
		victimDebt     int64
		victimCapacity float64
		pid            uint32 // the limit p is of; 0: params not loaded yet
		p              limitParams
		// An entry limited (sampled) after recent is limited recently:
		// sampled is the second after the event's.
		recent = now - int64(recentlyLimited)
	)
	for j := range uint64(neighbourhood) {
		e := &sh.e[(i+j)&s.slotMask]
		switch {
		case e.id == id && e.key == k:
			return e
		case e.id == 0:
			if empty == nil {
				empty = e
			}
		case e.tat <= now || !live.has(e.id):
			if free == nil {
				free = e
			}
		case empty == nil && free == nil:
			// In use: is it the victim so far? The closest to full for its
			// own limit (the least debt, TAT − now, for its capacity) that
			// isn't protected: over its limit (its next request would be
			// refused), or limited (sampled) within recentlyLimited.
			// Evicting one of those would give its client a full burst.
			debt := e.tat - now
			if victim != nil && e.id == victim.id && debt >= victimDebt {
				continue // not closer to full than the victim, of one capacity
			}
			if pid == 0 {
				if ps := s.params.Load(); ps != nil {
					params = *ps
				}
			}
			if e.id != pid {
				pid, p = e.id, limitParams{over: math.MaxInt64} // unknown: never over, capacity 0
				if int(pid) < len(params) && params[pid].capacity != 0 {
					p = params[pid]
				}
			}
			capacity := p.capacity
			if capacity == 0 { // unknown limit: as full as can be
				capacity = float64(debt)
			}
			switch {
			case debt > p.over, e.sampled != 0 && int64(e.sampled)*int64(time.Second) > recent:
				continue // protected
			case victim != nil && e.id != victim.id && float64(debt)*victimCapacity >= float64(victimDebt)*capacity:
				continue // not closer to full for its capacity (without dividing)
			}
			victim, victimDebt, victimCapacity = e, debt, capacity
		}
	}
	e := empty
	switch {
	case e != nil:
		s.keys.Add(1)
	case free != nil:
		e = free
		s.evictIdle.Add(1)
	case victim != nil:
		e = victim
		s.evictActive.Add(1)
	default:
		return nil
	}
	*e = entry{key: k, id: id, tat: now}
	return e
}

// recentlyLimited is how long after its last sampled limited request an
// entry stays protected: a client limited now and again, between events
// (one a sampleEvery), is still being limited.
const recentlyLimited = 2 * sampleEvery

// ceilSeconds rounds d up to whole seconds, at least one.
func ceilSeconds(d int64) time.Duration {
	sec := (d + int64(time.Second) - 1) / int64(time.Second)
	return time.Duration(max(sec, 1)) * time.Second
}
