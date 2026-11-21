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
// closest to full.
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

	keys         atomic.Int64
	evictIdle    atomic.Uint64
	evictActive  atomic.Uint64
	skippedNoKey atomic.Uint64
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
	return Limit{
		id:       s.Intern(id),
		interval: max(int64(period)/requests, 1),
		burst:    burst,
	}
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
	tat := max(e.tat, now)
	over := tat + l.interval - now - l.burst*l.interval
	if over <= 0 {
		e.tat = tat + l.interval
		sh.mu.Unlock()
		return Decision{Allowed: true}
	}
	d := Decision{RetryAfter: ceilSeconds(over)}
	e.limited++
	sec := uint32(min(now/int64(time.Second)+1, math.MaxUint32)) //nolint:gosec // bounded by min
	if e.sampled == 0 || int64(sec-e.sampled) >= int64(sampleEvery/time.Second) {
		d.Event, d.Sampled = true, e.limited
		e.sampled, e.limited = sec, 0
	}
	sh.mu.Unlock()
	return d
}

// Wait is how long until key k's request at t would be within l, without
// charging it: 0 when it is now, whole seconds otherwise.
func (s *Store) Wait(l Limit, k Key, t time.Time) time.Duration {
	now := int64(t.Sub(s.base))
	sh, i := s.locate(l.id, k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for j := range uint64(neighbourhood) {
		e := &sh.e[(i+j)&s.slotMask]
		if e.id == l.id && e.key == k {
			if over := max(e.tat, now) + l.interval - now - l.burst*l.interval; over > 0 {
				return ceilSeconds(over)
			}
			return 0
		}
	}
	return 0
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
			break
		}
	}
	sh.mu.Unlock()
}

// SkippedNoKey counts a request an IP limit couldn't count: no valid client
// address.
func (s *Store) SkippedNoKey() { s.skippedNoKey.Add(1) }

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
// the one closest to full. Called with the shard locked.
func (s *Store) find(sh *shard, i uint64, id uint32, k Key, now int64, live *Live) *entry {
	var empty, free, earliest *entry
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
		case earliest == nil || e.tat < earliest.tat:
			earliest = e
		}
	}
	e := empty
	switch {
	case e != nil:
		s.keys.Add(1)
	case free != nil:
		e = free
		s.evictIdle.Add(1)
	default:
		e = earliest
		s.evictActive.Add(1)
	}
	*e = entry{key: k, id: id, tat: now}
	return e
}

// ceilSeconds rounds d up to whole seconds, at least one.
func ceilSeconds(d int64) time.Duration {
	sec := (d + int64(time.Second) - 1) / int64(time.Second)
	return time.Duration(max(sec, 1)) * time.Second
}
