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

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
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

// A response's event says so, and a match in the response body, the
// leaked data itself, has no snippet.
func TestNewResponse(t *testing.T) {
	req := &request.Request{ID: "req-1", Method: "GET", Host: "shop.example", Headers: http.Header{}}
	v := pipeline.Verdict{
		Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, InterruptingRuleID: 959100, Response: true,
		Matches: []rules.Match{
			{RuleID: 951230, Variable: "RESPONSE_BODY", Value: "SQL syntax ... password=hunter2"},
			{RuleID: 100101, Variable: "RESPONSE_HEADERS:Set-Cookie", Value: "session=s3cr3t"},
			{RuleID: 100102, Variable: "RESPONSE_HEADERS:X-Powered-By", Value: "PHP/5.6"},
		},
	}
	ev := New(Source{}, req, "/", v, time.Now())
	if ev.GetPhase() != eventsv1.Phase_PHASE_RESPONSE || ev.GetStatus() != 403 {
		t.Errorf("phase %v, status %d", ev.GetPhase(), ev.GetStatus())
	}
	for _, m := range ev.GetMatches()[:2] {
		if m.GetSnippet() != "" {
			t.Errorf("%s: snippet %q, want none", m.GetVariable(), m.GetSnippet())
		}
	}
	if ev.GetMatches()[2].GetSnippet() != "PHP/5.6" {
		t.Errorf("X-Powered-By snippet %q", ev.GetMatches()[2].GetSnippet())
	}
	v.Response = false
	if ev := New(Source{}, req, "/", v, time.Now()); ev.GetPhase() != eventsv1.Phase_PHASE_REQUEST {
		t.Errorf("request event phase %v", ev.GetPhase())
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

// TestNewRedactsSensitiveArguments: by default, a match on an argument or
// header whose name looks like a credential leaves no snippet (#355).
func TestNewRedactsSensitiveArguments(t *testing.T) {
	req := &request.Request{Method: "POST", Host: "shop.example"}
	v := pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonRule}
	for _, variable := range []string{
		"ARGS:password", "ARGS_POST:token", "ARGS_GET:api_key", "ARGS:apiKey", "ARGS:new_passwd",
		"ARGS:client_secret", "ARGS:auth", "ARGS:sessionid", "ARGS:jwt", "ARGS:credit_card",
		"ARGS:card_number", "ARGS:SSN", "ARGS:user_ssn", "ARGS_POST:json.user.Password",
		"REQUEST_HEADERS:X-Api-Key", "REQUEST_HEADERS:x-auth-token",
	} {
		v.Matches = []rules.Match{{RuleID: 942100, Variable: variable, Value: "1' OR '1'='1"}}
		if got := New(Source{}, req, "/", v, time.Now()).GetMatches()[0].GetSnippet(); got != "" {
			t.Errorf("%s: snippet %q, want none", variable, got)
		}
	}
	for _, variable := range []string{"ARGS:q", "ARGS_POST:comment", "ARGS:classname", "REQUEST_HEADERS:User-Agent", "ARGS_NAMES:password"} {
		v.Matches = []rules.Match{{RuleID: 942100, Variable: variable, Value: "1' OR '1'='1"}}
		if got := New(Source{}, req, "/", v, time.Now()).GetMatches()[0].GetSnippet(); got != "1' OR '1'='1" {
			t.Errorf("%s: snippet %q, want it kept", variable, got)
		}
	}
	// A whole query string or body names the argument in the value.
	v.Matches = []rules.Match{{RuleID: 942100, Variable: "QUERY_STRING", Value: "user=a&password=1' OR '1'='1"}}
	if got := New(Source{}, req, "/", v, time.Now()).GetMatches()[0].GetSnippet(); got != "" {
		t.Errorf("QUERY_STRING with a password: snippet %q, want none", got)
	}
}

// TestNewRedactsConfigured: events.redact adds headers and argument
// patterns, and snippets: false sends none.
func TestNewRedactsConfigured(t *testing.T) {
	req := &request.Request{Method: "GET", Host: "shop.example"}
	v := pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonRule}
	check := func(r *Redaction, variable string, want bool) {
		t.Helper()
		v.Matches = []rules.Match{{RuleID: 942100, Variable: variable, Value: "<script>"}}
		got := New(Source{Redaction: func() *Redaction { return r }}, req, "/", v, time.Now()).GetMatches()[0].GetSnippet()
		if want && got != "<script>" || !want && got != "" {
			t.Errorf("%s: snippet %q, kept: want %t", variable, got, want)
		}
	}
	r := NewRedaction(&bundlev1.EventsConfig{RedactHeaders: []string{"X-Tenant"}, RedactArguments: []string{"Email"}})
	check(r, "REQUEST_HEADERS:x-tenant", false)
	check(r, "RESPONSE_HEADERS:X-Tenant", false)
	check(r, "ARGS:user_email", false)
	check(r, "ARGS_POST:EMAIL", false)
	check(r, "ARGS:password", false) // the defaults still apply
	check(r, "ARGS:q", true)
	check(r, "REQUEST_HEADERS:X-Tenant-Name", true)

	r = NewRedaction(&bundlev1.EventsConfig{NoSnippets: true})
	check(r, "ARGS:q", false)
	check(r, "REQUEST_HEADERS:User-Agent", false)

	check(NewRedaction(nil), "ARGS:q", true)
	check(nil, "ARGS:q", true)
	check(nil, "ARGS:password", false)
}

// An event says which protocol it is about, and a WebSocket message's has
// its own phase (#356).
func TestNewProtocol(t *testing.T) {
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule}
	for _, c := range []struct {
		name    string
		headers http.Header
		message bool
		proto   eventsv1.Protocol
		phase   eventsv1.Phase
	}{
		{"http", http.Header{}, false, eventsv1.Protocol_PROTOCOL_HTTP, eventsv1.Phase_PHASE_REQUEST},
		{"grpc", http.Header{"Content-Type": {"application/grpc+proto"}}, false, eventsv1.Protocol_PROTOCOL_GRPC, eventsv1.Phase_PHASE_REQUEST},
		{"handshake", http.Header{"Upgrade": {"websocket"}}, false, eventsv1.Protocol_PROTOCOL_WEBSOCKET, eventsv1.Phase_PHASE_REQUEST},
		{"message", http.Header{"Upgrade": {"websocket"}}, true, eventsv1.Protocol_PROTOCOL_WEBSOCKET, eventsv1.Phase_PHASE_WEBSOCKET_MESSAGE},
	} {
		v.WebSocketMessage = c.message
		ev := New(Source{}, &request.Request{Method: "GET", Headers: c.headers}, "/", v, time.Now())
		if ev.GetProtocol() != c.proto || ev.GetPhase() != c.phase {
			t.Errorf("%s: protocol %v, phase %v; want %v, %v", c.name, ev.GetProtocol(), ev.GetPhase(), c.proto, c.phase)
		}
	}
}
