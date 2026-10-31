// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/pkg/events"
)

// DefaultStatsInterval is how often a replica sends the request counts
// that changed.
const DefaultStatsInterval = 10 * time.Second

// minStatsLimit is how many policies' totals a replica keeps before it
// forgets those no longer in the bundle.
const minStatsLimit = 4096

// requestStats sums the request counts of a replica's engines per policy,
// since the replica started counting. Policies are those of the bundles it
// served (the distribution server takes no others). Past a limit, the
// totals of policies no longer in the bundle are forgotten, so they stay
// bounded as policies come and go. Safe for concurrent use; the zero value
// is ready.
type requestStats struct {
	mu     sync.Mutex
	since  time.Time
	totals map[string]*eventsv1.PolicyStats
	// changed are the policies counted since the last upload.
	changed map[string]bool
	// limit is how many totals are kept before evicting: at least
	// minStatsLimit, and twice those kept after the last eviction, so a
	// large bundle doesn't evict on every add.
	limit int
}

// add counts what engines counted since their previous reports. has
// reports whether the current bundle has a policy (nil: none).
func (r *requestStats) add(deltas []*eventsv1.PolicyStats, has func(id string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.totals == nil {
		r.since = time.Now()
		r.totals, r.changed = map[string]*eventsv1.PolicyStats{}, map[string]bool{}
	}
	for _, d := range deltas {
		t, ok := r.totals[d.GetPolicy()]
		if !ok {
			t = &eventsv1.PolicyStats{Policy: d.GetPolicy()}
			r.totals[d.GetPolicy()] = t
		}
		events.AddStats(t, d)
		r.changed[d.GetPolicy()] = true
	}
	if len(r.totals) > max(r.limit, minStatsLimit) {
		r.evict(has)
	}
}

// evict forgets the totals of the policies no longer in the bundle. A
// policy that comes back counts from zero again.
func (r *requestStats) evict(has func(id string) bool) {
	n := 0
	for id := range r.totals {
		if has == nil || !has(id) {
			delete(r.totals, id)
			delete(r.changed, id)
			n++
		}
	}
	distribution.RequestStatsDropped.WithLabelValues(distribution.DroppedEvicted).Add(float64(n))
	r.limit = 2 * len(r.totals)
}

// upload returns the totals of the policies counted since the last upload,
// or of every policy (all, on a new stream), sorted by policy; nil when
// there are none.
func (r *requestStats) upload(all bool) *controlplanev1.RequestStatsUpload {
	r.mu.Lock()
	defer r.mu.Unlock()
	var policies []*eventsv1.PolicyStats
	for id, t := range r.totals {
		if all || r.changed[id] {
			policies = append(policies, proto.CloneOf(t))
		}
	}
	clear(r.changed)
	if len(policies) == 0 {
		return nil
	}
	slices.SortFunc(policies, func(a, b *eventsv1.PolicyStats) int { return strings.Compare(a.GetPolicy(), b.GetPolicy()) })
	return &controlplanev1.RequestStatsUpload{
		Since: timestamppb.New(r.since), Time: timestamppb.Now(),
		Stats: &eventsv1.RequestStats{LatencyBounds: events.LatencyBounds(), Policies: policies},
	}
}
