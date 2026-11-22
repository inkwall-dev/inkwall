// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	_, body := get(t, m.AdminHandler(nil), "/metrics")
	return body
}

// Every rule that matched counts, by the verdict's action (#356).
func TestRuleMatches(t *testing.T) {
	m := NewMetrics("proxy")
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule, RuleIDs: []int{942100, 949110}})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonRule, RuleIDs: []int{942100}})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow})
	body := scrape(t, m)
	for _, want := range []string{
		`inkwall_rule_matches_total{action="deny",adapter="proxy",rule_id="942100"} 1`,
		`inkwall_rule_matches_total{action="deny",adapter="proxy",rule_id="949110"} 1`,
		`inkwall_rule_matches_total{action="log",adapter="proxy",rule_id="942100"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

// Rule IDs come from the loaded rules, but a cap still bounds the series:
// past it, matches count under rule_id="other".
func TestRuleMatchesBounded(t *testing.T) {
	m := NewMetrics("proxy")
	for id := range maxRuleSeries + 100 {
		m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionLog, RuleIDs: []int{100000 + id}})
	}
	if n := testutil.CollectAndCount(m.ruleMatches); n != maxRuleSeries+1 {
		t.Errorf("%d series, want %d", n, maxRuleSeries+1)
	}
	if got := testutil.ToFloat64(m.ruleMatches.WithLabelValues("other", "log")); got != 100 {
		t.Errorf("other: %v, want 100", got)
	}
}

// The policy label is off by default; on, distinct policies past the cap
// count as "other", so 5,000 policies make at most cap+1 policies' series.
func TestPolicyRequests(t *testing.T) {
	m := NewMetrics("proxy")
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule, Policy: "shop/web"})
	if strings.Contains(scrape(t, m), "inkwall_policy_requests_total") {
		t.Fatal("policy metrics without opting in")
	}

	m = NewMetrics("proxy")
	m.EnablePolicyMetrics(100)
	for i := range 5_000 {
		for _, a := range []pipeline.Action{pipeline.ActionAllow, pipeline.ActionDeny} {
			m.ObserveVerdict(pipeline.Verdict{Action: a, Reason: pipeline.ReasonRule, Policy: fmt.Sprintf("ns/p%d", i)})
		}
	}
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy})
	if n := testutil.CollectAndCount(m.policyRequests); n != 2*(100+1)+1 {
		t.Errorf("%d series for 5,000 policies, want %d", n, 2*(100+1)+1)
	}
	body := scrape(t, m)
	for _, want := range []string{
		`inkwall_policy_requests_total{action="deny",adapter="proxy",policy="ns/p0",reason="rule"} 1`,
		`inkwall_policy_requests_total{action="deny",adapter="proxy",policy="other",reason="rule"} 4900`,
		`inkwall_policy_requests_total{action="allow",adapter="proxy",policy="none",reason="no-policy"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

// gRPC messages read with and without a schema, and the fields it doesn't
// describe (design 0013 §10), by policy with policy metrics.
func TestGRPCRead(t *testing.T) {
	read := pipeline.Verdict{Action: pipeline.ActionAllow, Policy: "shop/api", GRPCRead: pipeline.GRPCRead{Described: 2, Undescribed: 1, Unknown: 3}}
	m := NewMetrics("proxy")
	m.ObserveVerdict(read)
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow, StreamEvent: 1, GRPCRead: pipeline.GRPCRead{Described: 1}})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow})
	body := scrape(t, m)
	for _, want := range []string{
		`inkwall_grpc_messages_read_total{adapter="proxy",schema="described"} 3`,
		`inkwall_grpc_messages_read_total{adapter="proxy",schema="undescribed"} 1`,
		`inkwall_grpc_unknown_fields_total{adapter="proxy"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	m = NewMetrics("proxy")
	m.EnablePolicyMetrics(10)
	m.ObserveVerdict(read)
	body = scrape(t, m)
	for _, want := range []string{
		`inkwall_grpc_messages_read_total{adapter="proxy",policy="shop/api",schema="described"} 2`,
		`inkwall_grpc_unknown_fields_total{adapter="proxy",policy="shop/api"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

// In standalone mode, the one pipeline enforces no policy: its requests
// count under policy="none".
func TestPolicyRequestsStandalone(t *testing.T) {
	m := NewMetrics("proxy")
	m.EnablePolicyMetrics(0)
	p := pipeline.New(evaluator{res: rules.Result{Interrupted: true, Status: 403}}, pipeline.Config{Mode: pipeline.ModeBlock, Observer: m})
	p.Check(context.Background(), &request.Request{})
	want := `inkwall_policy_requests_total{action="deny",adapter="proxy",policy="none",reason="rule"} 1`
	if body := scrape(t, m); !strings.Contains(body, want) {
		t.Errorf("metrics missing %q", want)
	}
}

// WebSocket messages count apart from requests (#356, #363), and the
// proxy's connections and violations have their own metrics.
func TestWebSocketMetrics(t *testing.T) {
	m := NewMetrics("proxy")
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule, WebSocketMessage: true, RuleIDs: []int{941100}})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow, WebSocketMessage: true})
	done := m.WebSocketOpened()
	m.WebSocketOpened()()
	m.WebSocketViolation(1007)
	body := scrape(t, m)
	for _, want := range []string{
		`inkwall_websocket_messages_total{action="deny",adapter="proxy"} 1`,
		`inkwall_websocket_messages_total{action="allow",adapter="proxy"} 1`,
		`inkwall_websocket_connections{adapter="proxy"} 1`,
		`inkwall_websocket_violations_total{adapter="proxy",code="1007"} 1`,
		`inkwall_rule_matches_total{action="deny",adapter="proxy",rule_id="941100"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(body, "inkwall_requests_total{") || !strings.Contains(body, `inkwall_check_duration_seconds_count{adapter="proxy"} 0`) {
		t.Errorf("WebSocket messages counted as requests:\n%s", body)
	}
	done()
	done() // once only
	if got := testutil.ToFloat64(m.wsConnections); got != 0 {
		t.Errorf("connections %v after both closed", got)
	}
}

// Requests an adapter can't read count by kind; a nil Metrics is fine.
func TestAdapterErrors(t *testing.T) {
	m := NewMetrics("forwardauth")
	m.AdapterError(ErrInvalidRequest)
	m.AdapterError(ErrInvalidRequest)
	m.AdapterError(ErrProtocol)
	body := scrape(t, m)
	for _, want := range []string{
		`inkwall_adapter_errors_total{adapter="forwardauth",kind="invalid_request"} 2`,
		`inkwall_adapter_errors_total{adapter="forwardauth",kind="protocol"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	var none *Metrics
	none.AdapterError(ErrProtocol)
	none.WebSocketOpened()()
	none.WebSocketViolation(1002)
}

// A recovered panic is logged with its value and stack, and counted by
// component; a nil Metrics only logs.
func TestPanicked(t *testing.T) {
	m := NewMetrics("spoe")
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	m.Panicked(context.Background(), logger, PanicSPOENotify, "boom")
	if want := `inkwall_panics_total{adapter="spoe",component="spoe_notify"} 1`; !strings.Contains(scrape(t, m), want) {
		t.Errorf("metrics missing %q", want)
	}
	var none *Metrics
	none.Panicked(context.Background(), logger, PanicSPOENotify, "boom")
	for _, want := range []string{`"level":"ERROR"`, `"component":"spoe_notify"`, `"panic":"boom"`, `"stack":"goroutine `, "TestPanicked"} {
		if strings.Count(logs.String(), want) != 2 {
			t.Errorf("logs %s: want %q twice", logs.String(), want)
		}
	}
}

// inkwall_rule_sets reports the compiled rule sets in memory.
func TestRuleSets(t *testing.T) {
	m := NewMetrics("proxy")
	n := 3
	m.WatchRuleSets(func() int { return n })
	if !strings.Contains(scrape(t, m), "inkwall_rule_sets 3") {
		t.Error("inkwall_rule_sets missing")
	}
}
