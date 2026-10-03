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

func TestCheckShedsLoadWhenSlotsAreBusy(t *testing.T) {
	// One slot, held by an evaluation that outlives its 5ms deadline.
	p := New(fakeEvaluator{delay: 200 * time.Millisecond}, Config{
		Mode: ModeBlock, Timeout: 5 * time.Millisecond, MaxConcurrent: 1,
	})
	if v := p.Check(context.Background(), &request.Request{}); v.Reason != ReasonTimeout {
		t.Fatalf("first request: reason = %s, want timeout", v.Reason)
	}

	// The abandoned evaluation still holds the slot: the next request is shed
	// immediately rather than starting more work.
	start := time.Now()
	v := p.Check(context.Background(), &request.Request{})
	if v.Reason != ReasonOverload || v.Action != ActionAllow {
		t.Fatalf("second request: got action=%s reason=%s, want allow/overload", v.Action, v.Reason)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("shed request took %s, want immediate", elapsed)
	}

	// Fail-closed policies reject shed requests.
	closed := New(fakeEvaluator{delay: 200 * time.Millisecond}, Config{
		Mode: ModeBlock, FailureMode: FailClosed, Timeout: 5 * time.Millisecond, MaxConcurrent: 1,
	})
	closed.Check(context.Background(), &request.Request{})
	if v := closed.Check(context.Background(), &request.Request{}); v.Reason != ReasonOverload || v.Status != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed shed: got status=%d reason=%s, want 503/overload", v.Status, v.Reason)
	}
}

func TestCheckReleasesSlots(t *testing.T) {
	p := New(fakeEvaluator{}, Config{Mode: ModeBlock, MaxConcurrent: 1})
	for range 100 {
		if v := p.Check(context.Background(), &request.Request{}); v.Reason == ReasonOverload {
			t.Fatal("slot not released after a completed evaluation")
		}
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

func TestOversizedBodyPolicy(t *testing.T) {
	truncated := &request.Request{BodyTruncated: true}
	tests := []struct {
		name       string
		cfg        Config
		req        *request.Request
		wantAction Action
		wantStatus int
		wantReason Reason
	}{
		{name: "inspect prefix by default", cfg: Config{Mode: ModeBlock}, req: truncated,
			wantAction: ActionAllow, wantReason: ReasonNone},
		{name: "deny in block mode", cfg: Config{Mode: ModeBlock, Oversize: OversizeDeny}, req: truncated,
			wantAction: ActionDeny, wantStatus: http.StatusRequestEntityTooLarge, wantReason: ReasonOversize},
		{name: "log in detect mode", cfg: Config{Mode: ModeDetect, Oversize: OversizeDeny}, req: truncated,
			wantAction: ActionLog, wantReason: ReasonOversize},
		{name: "complete body unaffected", cfg: Config{Mode: ModeBlock, Oversize: OversizeDeny}, req: &request.Request{},
			wantAction: ActionAllow, wantReason: ReasonNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(fakeEvaluator{}, tt.cfg).Check(context.Background(), tt.req)
			if v.Action != tt.wantAction || v.Status != tt.wantStatus || v.Reason != tt.wantReason {
				t.Fatalf("got action=%s status=%d reason=%s, want action=%s status=%d reason=%s",
					v.Action, v.Status, v.Reason, tt.wantAction, tt.wantStatus, tt.wantReason)
			}
		})
	}
}
