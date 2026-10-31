// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package fakecontrolplane

import (
	"testing"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// A replica's totals are cumulative: the newest replaces, and a total
// that goes down (the replica forgot the policy) counts from zero again.
func TestRequestStatsReset(t *testing.T) {
	s := &Server{requestStats: map[string]map[string]*eventsv1.PolicyStats{}, statsTotals: map[string]map[string]*eventsv1.PolicyStats{}}
	site := func(allowed, denied uint64) []*eventsv1.PolicyStats {
		return []*eventsv1.PolicyStats{{Policy: "shop/site", Allowed: allowed, Denied: denied, LatencyCounts: []uint64{allowed + denied}}}
	}
	s.addRequestStats("r1/1", site(3, 1))
	s.addRequestStats("r1/1", site(5, 2))
	s.addRequestStats("r1/1", site(1, 0)) // forgotten, back
	s.addRequestStats("r1/1", site(2, 0))
	s.addRequestStats("r2/1", site(10, 0))
	p := s.RequestStats()["shop/site"]
	if p.GetAllowed() != 17 || p.GetDenied() != 2 || len(p.GetLatencyCounts()) != 1 || p.GetLatencyCounts()[0] != 19 {
		t.Errorf("got %v, want 17 allowed, 2 denied, 19 timed", p)
	}
}
