// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package pipeline turns a request into a verdict: it runs the rule
// evaluator under a per-request deadline and applies the enforcement mode
// (detect or block) and the failure mode (fail open or closed).
package pipeline

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// DefaultTimeout is the per-request inspection deadline used when Config
// does not set one.
const DefaultTimeout = 20 * time.Millisecond

// Mode is the enforcement mode.
type Mode uint8

const (
	// ModeDetect reports matches but never blocks. It is the default.
	ModeDetect Mode = iota
	// ModeBlock blocks requests that the rules interrupt.
	ModeBlock
)

// FailureMode decides what happens when inspection fails or times out.
type FailureMode uint8

const (
	// FailOpen allows the request. It is the default: Inkwall must not take
	// down the traffic it protects.
	FailOpen FailureMode = iota
	// FailClosed rejects the request with 503 Service Unavailable.
	FailClosed
)

// Config configures a Pipeline.
type Config struct {
	Mode        Mode
	FailureMode FailureMode
	// Timeout bounds inspection time per request. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxConcurrent bounds how many evaluations run at once, including ones
	// that already timed out and are still finishing. When all slots are
	// busy, new requests get the failure mode immediately (ReasonOverload)
	// instead of adding work. Zero means 2 * GOMAXPROCS.
	MaxConcurrent int
}

// Pipeline evaluates requests. It is safe for concurrent use.
type Pipeline struct {
	eval    rules.Evaluator
	mode    Mode
	failure FailureMode
	timeout time.Duration
	slots   chan struct{}
}

// New returns a pipeline that evaluates requests with eval.
func New(eval rules.Evaluator, cfg Config) *Pipeline {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 2 * runtime.GOMAXPROCS(0)
	}
	return &Pipeline{
		eval:    eval,
		mode:    cfg.Mode,
		failure: cfg.FailureMode,
		timeout: timeout,
		slots:   make(chan struct{}, maxConcurrent),
	}
}

type outcome struct {
	res rules.Result
	err error
}

// Check inspects r and returns the verdict. It returns within the configured
// timeout even if the evaluator does not.
func (p *Pipeline) Check(ctx context.Context, r *request.Request) Verdict {
	start := time.Now()

	// Admission control. Evaluations cannot be interrupted, so a timed-out
	// evaluation keeps using CPU until it finishes. Without a bound, a flood
	// of expensive requests saturates every core and makes all requests time
	// out, which with fail-open switches inspection off.
	select {
	case p.slots <- struct{}{}:
	default:
		v := p.failed(ReasonOverload)
		v.Duration = time.Since(start)
		return v
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// The evaluator runs on its own goroutine so the deadline can be enforced
	// here. A late result is discarded; the buffered channel lets that
	// goroutine finish without leaking, and it releases its slot only then.
	done := make(chan outcome, 1)
	go func() {
		defer func() { <-p.slots }()
		res, err := p.eval.Evaluate(ctx, r)
		done <- outcome{res: res, err: err}
	}()

	var v Verdict
	select {
	case o := <-done:
		if o.err != nil {
			v = p.failed(ReasonError)
		} else {
			v = p.decide(o.res)
		}
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			v = p.failed(ReasonTimeout)
		} else {
			v = p.failed(ReasonCanceled)
		}
	}
	v.Duration = time.Since(start)
	return v
}

func (p *Pipeline) decide(res rules.Result) Verdict {
	v := Verdict{Action: ActionAllow, RuleIDs: res.MatchedRuleIDs, InterruptingRuleID: res.RuleID}
	if !res.Interrupted {
		return v
	}
	v.Reason = ReasonRule
	if p.mode == ModeDetect {
		v.Action = ActionLog
		return v
	}
	v.Action = ActionDeny
	v.Status = res.Status
	if v.Status < 400 || v.Status > 599 {
		v.Status = http.StatusForbidden
	}
	return v
}

func (p *Pipeline) failed(reason Reason) Verdict {
	if p.failure == FailClosed {
		return Verdict{Action: ActionDeny, Status: http.StatusServiceUnavailable, Reason: reason}
	}
	return Verdict{Action: ActionAllow, Reason: reason}
}
