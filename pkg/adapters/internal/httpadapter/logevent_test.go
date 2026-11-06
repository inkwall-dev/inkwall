// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// The security event line says where each rule matched, by variable name
// only: never what it matched (#354).
func TestLogEventMatches(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	v := pipeline.Verdict{
		Action: pipeline.ActionLog, Reason: pipeline.ReasonRule, Policy: "shop/web", AnomalyScore: 5, RuleIDs: []int{942100},
		Matches: []rules.Match{{RuleID: 942100, Variable: "ARGS:q", Value: "1' OR '1'='1 hunter2"}},
	}
	LogEvent(context.Background(), logger, nil, &request.Request{Method: "GET", Host: "shop.example"}, "/search", v)

	if strings.Contains(out.String(), "hunter2") {
		t.Fatalf("the line carries the matched value: %s", out.String())
	}
	var line struct {
		Matches []struct {
			RuleID   int    `json:"rule_id"`
			Variable string `json:"variable"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if len(line.Matches) != 1 || line.Matches[0].RuleID != 942100 || line.Matches[0].Variable != "ARGS:q" {
		t.Errorf("matches %+v, want 942100 on ARGS:q", line.Matches)
	}
	if !strings.Contains(out.String(), `"matches":[{"rule_id":942100,"variable":"ARGS:q"}]`) {
		t.Errorf("line %s", out.String())
	}

	// Bounded as in events: at most 32 matches, variables of at most 128
	// bytes.
	out.Reset()
	v.Matches = nil
	for range 100 {
		v.Matches = append(v.Matches, rules.Match{RuleID: 920000, Variable: "ARGS:" + strings.Repeat("a", 500)})
	}
	LogEvent(context.Background(), logger, nil, &request.Request{}, "/", v)
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if len(line.Matches) != 32 || len(line.Matches[0].Variable) != 128 {
		t.Errorf("%d matches, a variable of %d bytes: want 32 and 128", len(line.Matches), len(line.Matches[0].Variable))
	}
}

// 10,000 identical events in a second log at most the configured lines per
// policy and rule; the rest are counted, and every event still goes to the
// operator.
func TestLogEventRateLimit(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	now := time.Unix(1000, 0)
	limiter := events.NewLogLimiter(10)
	limiter.Now = func() time.Time { return now }
	buf := events.NewBuffer(20_000)
	rec := &events.Recorder{Buffer: buf, Log: limiter}
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, Policy: "shop/web", InterruptingRuleID: 949110,
		RuleIDs: []int{942100, 949110}, Matches: []rules.Match{{RuleID: 942100, Variable: "ARGS:q"}}}
	for range 10_000 {
		LogEvent(context.Background(), logger, rec, &request.Request{}, "/", v)
	}
	if n := strings.Count(out.String(), "\n"); n != 10 {
		t.Errorf("%d lines, want 10", n)
	}
	if got := testutil.ToFloat64(limiter.Suppressed().WithLabelValues("shop/web")); got != 9_990 {
		t.Errorf("suppressed %v, want 9990", got)
	}
	if buf.Len() != 10_000 {
		t.Errorf("%d events for the operator, want all 10000", buf.Len())
	}

	// Another rule, or another policy, has its own budget.
	out.Reset()
	other := v
	other.InterruptingRuleID = 949111
	LogEvent(context.Background(), logger, rec, &request.Request{}, "/", other)
	other = v
	other.Policy = "shop/api"
	LogEvent(context.Background(), logger, rec, &request.Request{}, "/", other)
	if n := strings.Count(out.String(), "\n"); n != 2 {
		t.Errorf("%d lines for other rules and policies, want 2", n)
	}

	// A second later the bucket has refilled, and the line says how many
	// were left out.
	out.Reset()
	now = now.Add(time.Second)
	LogEvent(context.Background(), logger, rec, &request.Request{}, "/", v)
	if !strings.Contains(out.String(), `"suppressed":9990`) {
		t.Errorf("line after suppression: %s", out.String())
	}

	// 0: no limit.
	out.Reset()
	unlimited := &events.Recorder{Log: events.NewLogLimiter(0)}
	for range 100 {
		LogEvent(context.Background(), logger, unlimited, &request.Request{}, "/", v)
	}
	if n := strings.Count(out.String(), "\n"); n != 100 {
		t.Errorf("unlimited: %d lines, want 100", n)
	}
}
