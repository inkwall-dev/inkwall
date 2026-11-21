// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// The heap the control plane's queue takes when full: it bounds its
// batches' wire size (controlPlane.eventsBufferMiB, 64 MiB) but holds them
// decoded. The chart's memory formula (values.yaml) uses this number; run
// with QUEUE_HEAP=1 to print it:
//
//	QUEUE_HEAP=1 go test ./operator/internal/controlplane -run TestQueueHeap -v
func TestQueueHeap(t *testing.T) {
	if os.Getenv("QUEUE_HEAP") == "" {
		t.Skip("set QUEUE_HEAP=1 to measure")
	}
	const wire = 64 << 20
	q, err := openQueue("", wire)
	if err != nil {
		t.Fatal(err)
	}
	// A typical denial: a CRS rule with a few matches, about 600 bytes on
	// the wire.
	// Every string its own, as decoding makes them.
	c := strings.Clone
	event := func(i int) *eventsv1.SecurityEvent {
		return &eventsv1.SecurityEvent{
			EventId: c("01JD3Q4Z8M2N5X7Y9A1B3C" + strings.Repeat("0", 4)), Time: timestamppb.New(time.Unix(int64(1_800_000_000+i), 0)),
			EngineId: c("traefik-7d9c4b7f5d-x2k9p"), PodNamespace: c("traefik"), PodName: c("traefik-7d9c4b7f5d-x2k9p"),
			Policy: c("shop/web"), BundleVersion: 42, Action: enginev1.Action_ACTION_DENY, Reason: enginev1.Reason_REASON_RULE,
			InterruptingRuleId: 949110, AnomalyScore: 15,
			Matches: []*eventsv1.Match{
				{RuleId: 942100, Variable: c("ARGS:id"), Snippet: c("1' OR '1'='1")},
				{RuleId: 942190, Variable: c("ARGS:id"), Snippet: c("1' OR '1'='1")},
				{RuleId: 942260, Variable: c("ARGS:q"), Snippet: c("' UNION SELECT")},
			},
			Method: c("GET"), Host: c("shop.example.com"), Path: c("/search/products/42"), ClientIp: c("203.0.113.7"),
			UserAgent: c("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"),
			RequestId: c("a1b2c3d4e5f6a7b8c9d0"), Status: 403, Latency: durationpb.New(420 * time.Microsecond),
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; q.bytes < wire*99/100; i++ {
		b := &eventsv1.EventBatch{}
		for j := range 100 {
			b.Events = append(b.Events, event(i*100+j))
		}
		if err := q.add(b); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("queue: %d events, %d MiB on the wire, %d MiB of heap (%.1fx)", q.count, q.bytes>>20, heap>>20, float64(heap)/float64(q.bytes))
	runtime.KeepAlive(q)
}
