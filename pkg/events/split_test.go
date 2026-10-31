// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// maximal is an event with every field at its limit.
func maximal() *eventsv1.SecurityEvent {
	long := strings.Repeat("x", 4096)
	req := &request.Request{
		ID: long, Method: long, Host: long, ClientIP: netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
		Headers: http.Header{"User-Agent": {long}},
	}
	v := pipeline.Verdict{
		Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, InterruptingRuleID: 949110,
		AnomalyScore: 1000, Duration: time.Second, Policy: long,
	}
	for i := range 2 * maxMatches {
		v.Matches = append(v.Matches, rules.Match{RuleID: 900000 + i, Variable: "ARGS:" + long, Value: long})
	}
	src := Source{EngineID: strings.Repeat("e", 253), PodNamespace: strings.Repeat("n", 63), PodName: strings.Repeat("p", 253)}
	return New(src, req, "/"+long, v, time.Now())
}

func TestMaximalEvent(t *testing.T) {
	// Split keeps an event whole: the agent's and the forwarder's message
	// budgets hold several of these.
	if n := proto.Size(maximal()); n > 10<<10 {
		t.Errorf("an event at the field limits is %d bytes, over 10 KiB", n)
	}
}

func TestSplit(t *testing.T) {
	const maxBytes = 60 << 10
	in := &eventsv1.EventBatch{Dropped: 7}
	for i := range 256 {
		ev := maximal()
		ev.EventId = strconv.Itoa(i)
		in.Events = append(in.Events, ev)
	}
	// One event too large for any message: left out, and counted.
	in.Events[100] = &eventsv1.SecurityEvent{EventId: "huge", Path: strings.Repeat("x", maxBytes)}

	parts := Split(in, maxBytes)
	if len(parts) < 2 {
		t.Fatalf("%d parts, want several", len(parts))
	}
	var ids []string
	var dropped uint64
	for i, p := range parts {
		if n := proto.Size(p); n > maxBytes {
			t.Errorf("part %d is %d bytes, over %d", i, n, maxBytes)
		}
		for _, ev := range p.GetEvents() {
			ids = append(ids, ev.GetEventId())
		}
		dropped += p.GetDropped()
	}
	if parts[0].GetDropped() != 7 {
		t.Errorf("the first part carries %d dropped, want 7", parts[0].GetDropped())
	}
	if dropped != 8 {
		t.Errorf("dropped %d, want 8 (7 and the huge event)", dropped)
	}
	var want []string
	for i := range 256 {
		if i != 100 {
			want = append(want, strconv.Itoa(i))
		}
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("events %v, want %v in order", ids, want)
	}

	// A batch that fits is sent as it is.
	small := &eventsv1.EventBatch{Events: in.Events[:2]}
	if got := Split(small, maxBytes); len(got) != 1 || got[0] != small {
		t.Errorf("Split of a small batch = %v, want it unchanged", got)
	}
	// Only dropped counts: one batch.
	if got := Split(&eventsv1.EventBatch{Dropped: 3, Events: in.Events[100:101]}, maxBytes); len(got) != 1 || got[0].GetDropped() != 4 || len(got[0].GetEvents()) != 0 {
		t.Errorf("Split of a huge event = %v, want one batch with 4 dropped", got)
	}
}
