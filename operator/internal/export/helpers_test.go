// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// allowLoopback lets the tests' sinks on 127.0.0.1 through the dialer's
// guard, and nothing else that it refuses.
func allowLoopback(t *testing.T) {
	t.Helper()
	testLoopback.Add(1)
	t.Cleanup(func() { testLoopback.Add(-1) })
}

// useResolver resolves every name with r for the test.
func useResolver(t *testing.T, r *net.Resolver) {
	t.Helper()
	testResolver.Store(r)
	t.Cleanup(func() { testResolver.Store(nil) })
}

var (
	eventTime    = time.Date(2026, 11, 20, 10, 15, 2, 123456789, time.UTC)
	observedTime = time.Date(2026, 11, 20, 10, 15, 2, 401337000, time.UTC)
)

// fullEvent sets every field: the example of design 0010 §5.1.
func fullEvent() *eventsv1.SecurityEvent {
	return &eventsv1.SecurityEvent{
		EventId:            "01JD3Q4Z8M2N5X7Y9A1B3C5D7E",
		Time:               timestamppb.New(eventTime),
		EngineId:           "01JDENGINE",
		PodNamespace:       "traefik",
		PodName:            "traefik-7d9c",
		Policy:             "shop/web",
		BundleVersion:      42,
		Action:             enginev1.Action_ACTION_DENY,
		Reason:             enginev1.Reason_REASON_RULE,
		InterruptingRuleId: 949110,
		Matches:            []*eventsv1.Match{{RuleId: 942100, Variable: "ARGS:id", Snippet: "1' OR '1'='1"}, {RuleId: 920350, Variable: "REQUEST_HEADERS:Host"}},
		AnomalyScore:       25,
		Method:             "GET",
		Host:               "shop.example.com",
		Path:               "/search",
		ClientIp:           "203.0.113.7",
		UserAgent:          "curl/8.10.1",
		RequestId:          "a1b2c3",
		Status:             403,
		Latency:            durationpb.New(420 * time.Microsecond),
		Phase:              eventsv1.Phase_PHASE_REQUEST,
		Protocol:           eventsv1.Protocol_PROTOCOL_HTTP,
	}
}

// oldEvent is from an engine before 0.4.0: no phase, no protocol, and no
// time or latency.
func oldEvent() *eventsv1.SecurityEvent {
	return &eventsv1.SecurityEvent{
		EventId: "01JD3Q4Z8M2N5X7Y9A1B3C5D7F", EngineId: "01JDOLD", PodNamespace: "traefik", PodName: "traefik-old",
		BundleVersion: 7, Action: enginev1.Action_ACTION_LOG, Reason: enginev1.Reason_REASON_RULE,
		Method: "POST", Host: "shop.example.com", Path: "/login",
	}
}

// rateLimited is a rate limit's sampled event, on a WebSocket's message,
// with a policy the bundle doesn't have.
func rateLimited() *eventsv1.SecurityEvent {
	return &eventsv1.SecurityEvent{
		EventId: "01JD3Q4Z8M2N5X7Y9A1B3C5D7G", Time: timestamppb.New(eventTime), EngineId: "01JDENGINE",
		Policy: "payments/web", BundleVersion: 42, Action: enginev1.Action_ACTION_DENY, Reason: enginev1.Reason_REASON_RATE_LIMIT,
		Status: 429, Method: "GET", Host: "pay.example.com", Path: "/ws\n{\"event_id\":\"fake\"}", ClientIp: "2001:db8::7",
		Phase: eventsv1.Phase_PHASE_WEBSOCKET_MESSAGE, Protocol: eventsv1.Protocol_PROTOCOL_WEBSOCKET,
		RateLimit: "per-client", SampledCount: 17, Latency: durationpb.New(0),
	}
}

// inBundle has shop/web only.
func inBundle(p string) bool { return p == "shop/web" }

func items(evs ...*eventsv1.SecurityEvent) []item {
	out := make([]item, len(evs))
	for i, ev := range evs {
		out[i] = item{ev: ev, observed: observedTime}
		if inBundle(ev.GetPolicy()) {
			out[i].policy = ev.GetPolicy()
		}
	}
	return out
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test -update writes it)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the golden file (a v1 field renamed? that is v2, design 0010 §5.3):\n got: %s\nwant: %s", name, got, want)
	}
}

func batchOf(n int, mk func(i int) *eventsv1.SecurityEvent) *eventsv1.EventBatch {
	b := &eventsv1.EventBatch{}
	for i := range n {
		b.Events = append(b.Events, mk(i))
	}
	return b
}

func numbered(prefix string) func(i int) *eventsv1.SecurityEvent {
	return func(i int) *eventsv1.SecurityEvent {
		ev := fullEvent()
		ev.EventId = prefix + strings.Repeat("0", 3) + string(rune('a'+i%26)) + itoa(i)
		return ev
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
