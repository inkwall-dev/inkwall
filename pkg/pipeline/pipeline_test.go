// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

type fakeEvaluator struct {
	res   rules.Result
	err   error
	delay time.Duration
}

func (f fakeEvaluator) Evaluate(_ context.Context, _ *request.Request) (rules.Result, error) {
	time.Sleep(f.delay)
	return f.res, f.err
}

var blocked = rules.Result{Interrupted: true, Status: 403, RuleID: 949110, MatchedRuleIDs: []int{942100, 949110}}

func TestCheck(t *testing.T) {
	tests := []struct {
		name       string
		eval       fakeEvaluator
		cfg        Config
		wantAction Action
		wantStatus int
		wantReason Reason
	}{
		{name: "clean request is allowed", eval: fakeEvaluator{}, cfg: Config{Mode: ModeBlock},
			wantAction: ActionAllow, wantReason: ReasonNone},
		{name: "block mode denies interrupted request", eval: fakeEvaluator{res: blocked}, cfg: Config{Mode: ModeBlock},
			wantAction: ActionDeny, wantStatus: 403, wantReason: ReasonRule},
		{name: "detect mode only logs", eval: fakeEvaluator{res: blocked}, cfg: Config{Mode: ModeDetect},
			wantAction: ActionLog, wantReason: ReasonRule},
		{name: "missing status defaults to 403", eval: fakeEvaluator{res: rules.Result{Interrupted: true}}, cfg: Config{Mode: ModeBlock},
			wantAction: ActionDeny, wantStatus: http.StatusForbidden, wantReason: ReasonRule},
		{name: "custom status is kept", eval: fakeEvaluator{res: rules.Result{Interrupted: true, Status: 429}}, cfg: Config{Mode: ModeBlock},
			wantAction: ActionDeny, wantStatus: 429, wantReason: ReasonRule},
		{name: "timeout fails open", eval: fakeEvaluator{res: blocked, delay: 50 * time.Millisecond},
			cfg:        Config{Mode: ModeBlock, Timeout: 5 * time.Millisecond},
			wantAction: ActionAllow, wantReason: ReasonTimeout},
		{name: "timeout fails closed", eval: fakeEvaluator{delay: 50 * time.Millisecond},
			cfg:        Config{Mode: ModeBlock, FailureMode: FailClosed, Timeout: 5 * time.Millisecond},
			wantAction: ActionDeny, wantStatus: http.StatusServiceUnavailable, wantReason: ReasonTimeout},
		{name: "evaluator error fails open", eval: fakeEvaluator{err: errors.New("boom")}, cfg: Config{Mode: ModeBlock},
			wantAction: ActionAllow, wantReason: ReasonError},
		{name: "evaluator error fails closed", eval: fakeEvaluator{err: errors.New("boom")},
			cfg:        Config{Mode: ModeBlock, FailureMode: FailClosed},
			wantAction: ActionDeny, wantStatus: http.StatusServiceUnavailable, wantReason: ReasonError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(tt.eval, tt.cfg).Check(context.Background(), &request.Request{})
			if v.Action != tt.wantAction || v.Status != tt.wantStatus || v.Reason != tt.wantReason {
				t.Fatalf("got action=%s status=%d reason=%s, want action=%s status=%d reason=%s",
					v.Action, v.Status, v.Reason, tt.wantAction, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

func TestCheckReturnsWithinTimeout(t *testing.T) {
	p := New(fakeEvaluator{delay: time.Second}, Config{Timeout: 10 * time.Millisecond})
	start := time.Now()
	p.Check(context.Background(), &request.Request{})
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Check took %s, want about the 10ms timeout", elapsed)
	}
}

func TestCheckReportsMatchedRules(t *testing.T) {
	v := New(fakeEvaluator{res: blocked}, Config{Mode: ModeBlock}).Check(context.Background(), &request.Request{})
	if v.InterruptingRuleID != 949110 || len(v.RuleIDs) != 2 {
		t.Fatalf("got interrupting=%d rules=%v", v.InterruptingRuleID, v.RuleIDs)
	}
	if v.Duration <= 0 {
		t.Fatal("Duration not recorded")
	}
}

func TestCheckCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := New(fakeEvaluator{delay: 50 * time.Millisecond}, Config{}).Check(ctx, &request.Request{})
	if v.Reason != ReasonCanceled || v.Action != ActionAllow {
		t.Fatalf("got action=%s reason=%s, want allow/canceled", v.Action, v.Reason)
	}
}
