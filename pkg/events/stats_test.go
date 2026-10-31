// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func TestCounter(t *testing.T) {
	s := NewStats()
	c := s.Counter("shop/site")
	c.Observe(pipeline.Verdict{Action: pipeline.ActionAllow, Duration: 10 * time.Microsecond})
	c.Observe(pipeline.Verdict{Action: pipeline.ActionDeny, Duration: 50 * time.Microsecond})
	c.Observe(pipeline.Verdict{Action: pipeline.ActionLog, Duration: 120 * time.Microsecond})
	c.Observe(pipeline.Verdict{Action: pipeline.ActionAllow, Duration: time.Second})
	var none *Counter
	none.Observe(pipeline.Verdict{}) // counts nothing, doesn't panic

	got := s.Take()
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	p := got[0]
	if p.GetPolicy() != "shop/site" || p.GetAllowed() != 2 || p.GetDenied() != 1 || p.GetDetected() != 1 {
		t.Errorf("counts %v", p)
	}
	// Up to 50 µs, then (100, 200] µs, then over the last bound.
	want := make([]uint64, len(latencyBounds)+1)
	want[0], want[2], want[len(want)-1] = 2, 1, 1
	if !slices.Equal(p.GetLatencyCounts(), want) {
		t.Errorf("latency counts %v, want %v", p.GetLatencyCounts(), want)
	}
	if d := p.GetLatencySum() - 1.00018; d < -1e-9 || d > 1e-9 {
		t.Errorf("latency sum %v", p.GetLatencySum())
	}
	if b := LatencyBounds(); len(b) != len(latencyBounds) || b[0] != 50e-6 || b[len(b)-1] != 0.8192 {
		t.Errorf("bounds %v", b)
	}
	// Taken: nothing left until counted again.
	if got := s.Take(); got != nil {
		t.Errorf("second take: %v", got)
	}
}

func TestDiffStats(t *testing.T) {
	ps := func(allowed, denied uint64, counts ...uint64) *eventsv1.PolicyStats {
		return &eventsv1.PolicyStats{Policy: "p", Allowed: allowed, Denied: denied, LatencyCounts: counts, LatencySum: float64(allowed + denied)}
	}
	for _, tc := range []struct {
		name      string
		cur, prev *eventsv1.PolicyStats
		want      *eventsv1.PolicyStats
	}{
		{"first report", ps(3, 1, 4, 0), nil, ps(3, 1, 4, 0)},
		{"difference", ps(5, 2, 6, 1), ps(3, 1, 4, 0), ps(2, 1, 2, 1)},
		{"unchanged", ps(3, 1, 4, 0), ps(3, 1, 4, 0), ps(0, 0, 0, 0)},
		// The counts started again from zero: all of them are new.
		{"reset", ps(2, 0, 2, 0), ps(3, 1, 4, 0), ps(2, 0, 2, 0)},
		{"reset in a bucket", ps(9, 9, 1, 17), ps(3, 1, 4, 0), ps(9, 9, 1, 17)},
		{"other buckets", ps(5, 1, 6), ps(3, 1, 4, 0), &eventsv1.PolicyStats{Policy: "p", Allowed: 2}},
	} {
		if got := DiffStats(tc.cur, tc.prev); !proto.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAddStats(t *testing.T) {
	p := &eventsv1.PolicyStats{Policy: "p"}
	AddStats(p, &eventsv1.PolicyStats{Allowed: 1, Denied: 2, Detected: 3, LatencyCounts: []uint64{1, 5}, LatencySum: 0.5})
	AddStats(p, &eventsv1.PolicyStats{Allowed: 1, LatencyCounts: []uint64{0, 1}, LatencySum: 0.25})
	// Other buckets: the counts are added, not the latency.
	AddStats(p, &eventsv1.PolicyStats{Denied: 1, LatencyCounts: []uint64{1}, LatencySum: 9})
	want := &eventsv1.PolicyStats{Policy: "p", Allowed: 2, Denied: 3, Detected: 3, LatencyCounts: []uint64{1, 6}, LatencySum: 0.75}
	if !proto.Equal(p, want) {
		t.Errorf("got %v, want %v", p, want)
	}
}

// A report of many policies is split into small messages, each policy in
// exactly one.
func TestSplitStats(t *testing.T) {
	if got := SplitStats(nil, 1000); got != nil {
		t.Errorf("no policies: %v", got)
	}
	var policies []*eventsv1.PolicyStats
	for i := range 2000 {
		policies = append(policies, &eventsv1.PolicyStats{
			Policy: fmt.Sprintf("namespace-%d/%s", i, strings.Repeat("p", 40)), Allowed: 1 << 40, Denied: 1 << 30, Detected: 1 << 20,
			LatencyCounts: slices.Repeat([]uint64{1 << 40}, len(latencyBounds)+1), LatencySum: 1e6,
		})
	}
	const limit = 32 << 10
	msgs := SplitStats(policies, limit)
	if len(msgs) < 2 {
		t.Fatalf("%d messages", len(msgs))
	}
	var names []string
	for _, m := range msgs {
		if n := proto.Size(m); n > limit {
			t.Errorf("a message of %d bytes, over %d", n, limit)
		}
		if !slices.Equal(m.GetLatencyBounds(), LatencyBounds()) {
			t.Errorf("bounds %v", m.GetLatencyBounds())
		}
		for _, p := range m.GetPolicies() {
			names = append(names, p.GetPolicy())
		}
	}
	if len(names) != len(policies) || names[0] != policies[0].GetPolicy() || names[len(names)-1] != policies[len(policies)-1].GetPolicy() {
		t.Errorf("%d policies sent of %d", len(names), len(policies))
	}
	// A policy larger than the limit still goes, alone.
	if got := SplitStats(policies[:2], 10); len(got) != 2 {
		t.Errorf("%d messages for two policies over the limit", len(got))
	}
}

// BenchmarkCounterObserve measures counting one request, on every core at
// once: it runs on every request a policy decides.
func BenchmarkCounterObserve(b *testing.B) {
	c := NewStats().Counter("shop/site")
	v := pipeline.Verdict{Action: pipeline.ActionAllow, Duration: 300 * time.Microsecond}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Observe(v)
		}
	})
}
