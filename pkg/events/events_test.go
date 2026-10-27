// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func TestNewRedacts(t *testing.T) {
	req := &request.Request{
		ID: "req-1", Method: "POST", Host: "shop.example", ClientIP: netip.MustParseAddr("203.0.113.7"),
		Headers: http.Header{"User-Agent": {"curl/8"}, "Authorization": {"Bearer secret"}},
	}
	v := pipeline.Verdict{
		Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, InterruptingRuleID: 949110,
		RuleIDs: []int{942100, 949110}, AnomalyScore: 10, Duration: 2 * time.Millisecond, Policy: "shop/checkout",
		Matches: []rules.Match{
			{RuleID: 942100, Variable: "ARGS:id", Value: "1' OR '1'='1" + strings.Repeat("x", 100)},
			{RuleID: 920000, Variable: "REQUEST_HEADERS:Authorization", Value: "Bearer secret"},
			{RuleID: 920001, Variable: "REQUEST_COOKIES:session", Value: "s3cr3t"},
			{RuleID: 920002, Variable: "REQUEST_HEADERS:user-agent", Value: "curl/8"},
		},
	}
	src := Source{EngineID: "e-1", PodNamespace: "traefik", PodName: "traefik-a", BundleVersion: func() uint64 { return 7 }}
	now := time.Now()
	ev := New(src, req, "/checkout?card=4111111111111111", v, now)

	if ev.GetPath() != "/checkout" {
		t.Errorf("path = %q, want the query string dropped", ev.GetPath())
	}
	if got := ev.GetMatches()[0].GetSnippet(); len(got) != maxSnippet || !strings.HasPrefix(got, "1' OR") {
		t.Errorf("snippet = %q (%d bytes), want the first %d bytes", got, len(got), maxSnippet)
	}
	for _, m := range ev.GetMatches()[1:3] {
		if m.GetSnippet() != "" {
			t.Errorf("%s: snippet %q, want none (redacted)", m.GetVariable(), m.GetSnippet())
		}
	}
	if ev.GetMatches()[3].GetSnippet() != "curl/8" {
		t.Errorf("User-Agent snippet = %q", ev.GetMatches()[3].GetSnippet())
	}
	want := &eventsv1.SecurityEvent{
		EngineId: "e-1", PodNamespace: "traefik", PodName: "traefik-a", Policy: "shop/checkout", BundleVersion: 7,
		Action: enginev1.Action_ACTION_DENY, Reason: enginev1.Reason_REASON_RULE, InterruptingRuleId: 949110,
		AnomalyScore: 10, Method: "POST", Host: "shop.example", ClientIp: "203.0.113.7", UserAgent: "curl/8",
		RequestId: "req-1", Status: 403,
	}
	got := fmt.Sprint(ev.GetEngineId(), ev.GetPodNamespace(), ev.GetPodName(), ev.GetPolicy(), ev.GetBundleVersion(),
		ev.GetAction(), ev.GetReason(), ev.GetInterruptingRuleId(), ev.GetAnomalyScore(), ev.GetMethod(), ev.GetHost(),
		ev.GetClientIp(), ev.GetUserAgent(), ev.GetRequestId(), ev.GetStatus())
	wantS := fmt.Sprint(want.GetEngineId(), want.GetPodNamespace(), want.GetPodName(), want.GetPolicy(), want.GetBundleVersion(),
		want.GetAction(), want.GetReason(), want.GetInterruptingRuleId(), want.GetAnomalyScore(), want.GetMethod(), want.GetHost(),
		want.GetClientIp(), want.GetUserAgent(), want.GetRequestId(), want.GetStatus())
	if got != wantS {
		t.Errorf("event:\n got %s\nwant %s", got, wantS)
	}
	if ev.GetLatency().AsDuration() != 2*time.Millisecond || !ev.GetTime().AsTime().Equal(now.UTC().Truncate(time.Nanosecond)) {
		t.Errorf("latency %v, time %v", ev.GetLatency().AsDuration(), ev.GetTime().AsTime())
	}

	// Detect mode: forwarded, so the client's status isn't known.
	v.Action = pipeline.ActionLog
	if ev := New(src, req, "/", v, now); ev.GetStatus() != 0 || ev.GetAction() != enginev1.Action_ACTION_LOG {
		t.Errorf("detect: status %d, action %v", ev.GetStatus(), ev.GetAction())
	}
}

func TestNewLimits(t *testing.T) {
	long := strings.Repeat("é", 2000) // 2 bytes each
	req := &request.Request{Host: long, ID: long, Headers: http.Header{"User-Agent": {long}}}
	v := pipeline.Verdict{Policy: long}
	for i := range 100 {
		v.Matches = append(v.Matches, rules.Match{RuleID: i, Variable: "ARGS:" + long, Value: long})
	}
	ev := New(Source{}, req, "/"+long, v, time.Now())
	for name, c := range map[string]struct {
		s   string
		max int
	}{
		"host": {ev.GetHost(), maxHost}, "path": {ev.GetPath(), maxPath}, "user agent": {ev.GetUserAgent(), maxUserAgent},
		"request ID": {ev.GetRequestId(), maxRequestID}, "policy": {ev.GetPolicy(), maxPolicy},
		"variable": {ev.GetMatches()[0].GetVariable(), maxVariable}, "snippet": {ev.GetMatches()[0].GetSnippet(), maxSnippet},
	} {
		if len(c.s) > c.max || !utf8.ValidString(c.s) || len(c.s) < c.max-1 {
			t.Errorf("%s: %d bytes (valid UTF-8: %v), want at most %d, cut on a character", name, len(c.s), utf8.ValidString(c.s), c.max)
		}
	}
	if n := len(ev.GetMatches()); n != maxMatches {
		t.Errorf("%d matches, want %d", n, maxMatches)
	}
	if ev := New(Source{}, &request.Request{Host: "a\xffb"}, "/", pipeline.Verdict{}, time.Now()); !utf8.ValidString(ev.GetHost()) {
		t.Errorf("host %q: invalid UTF-8", ev.GetHost())
	}
}

func TestNewID(t *testing.T) {
	now := time.Now()
	a, b := NewID(now), NewID(now.Add(time.Millisecond))
	if len(a) != 26 || strings.Trim(a, crockford) != "" || a[0] > '7' {
		t.Fatalf("ID %q: want 26 Crockford base-32 characters", a)
	}
	if a >= b {
		t.Errorf("IDs not sorted by time: %s, %s", a, b)
	}
	if NewID(now) == a {
		t.Error("two IDs at the same time are equal")
	}
}

func ev(id string) *eventsv1.SecurityEvent { return &eventsv1.SecurityEvent{EventId: id} }

func ids(b *eventsv1.EventBatch) string {
	var s []string
	for _, e := range b.GetEvents() {
		s = append(s, e.GetEventId())
	}
	return strings.Join(s, ",")
}

func TestBufferDropsOldest(t *testing.T) {
	b := NewBuffer(3)
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		b.Add(ev(id))
	}
	batch := b.Next(context.Background(), 2)
	if ids(batch) != "3,4" || batch.GetDropped() != 2 {
		t.Fatalf("batch %s dropped %d, want 3,4 dropped 2", ids(batch), batch.GetDropped())
	}
	batch = b.Next(context.Background(), 0)
	if ids(batch) != "5" || batch.GetDropped() != 0 {
		t.Fatalf("batch %s dropped %d, want 5 dropped 0", ids(batch), batch.GetDropped())
	}
}

func TestBufferReturn(t *testing.T) {
	b := NewBuffer(4)
	for _, id := range []string{"1", "2", "3"} {
		b.Add(ev(id))
	}
	batch := b.Next(context.Background(), 2) // 1,2
	b.Add(ev("4"))
	b.Return(batch) // the send failed
	if got := ids(b.Next(context.Background(), 0)); got != "1,2,3,4" {
		t.Fatalf("after Return: %s, want 1,2,3,4 (in order)", got)
	}

	// No room for all of it: the oldest go, counted.
	for _, id := range []string{"1", "2", "3"} {
		b.Add(ev(id))
	}
	batch = b.Next(context.Background(), 2) // 1,2
	b.Add(ev("4"))
	b.Add(ev("5"))
	b.Return(batch)
	got := b.Next(context.Background(), 0)
	if ids(got) != "2,3,4,5" || got.GetDropped() != 1 {
		t.Fatalf("after Return to a full buffer: %s dropped %d, want 2,3,4,5 dropped 1", ids(got), got.GetDropped())
	}
}

func TestBufferNextWaits(t *testing.T) {
	b := NewBuffer(0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got := b.Next(ctx, 0); got != nil {
		t.Fatalf("empty buffer: %v, want nil when ctx ends", got)
	}
	got := make(chan *eventsv1.EventBatch)
	go func() { got <- b.Next(context.Background(), 0) }()
	time.Sleep(20 * time.Millisecond)
	b.Add(ev("1"))
	select {
	case batch := <-got:
		if ids(batch) != "1" {
			t.Errorf("batch %s", ids(batch))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Next didn't wake up on Add")
	}
}

func TestNilRecorder(t *testing.T) {
	var r *Recorder
	r.Record(&request.Request{}, "/", pipeline.Verdict{}) // no panic
	r = &Recorder{Buffer: NewBuffer(1)}
	r.Record(&request.Request{}, "/", pipeline.Verdict{Action: pipeline.ActionDeny})
	if r.Buffer.Len() != 1 {
		t.Errorf("recorded %d, want 1", r.Buffer.Len())
	}
}
