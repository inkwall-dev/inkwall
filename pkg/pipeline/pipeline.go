// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package pipeline turns a request into a verdict: it runs the rule
// evaluator under a per-request deadline and applies the enforcement mode
// (detect or block) and the failure mode (fail open or closed).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// DefaultTimeout is the per-request inspection deadline used when Config
// does not set one. It is a safety cap, not the expected latency: it is set
// so that requests within the default argument and body limits finish in
// time, because in block mode a timeout rejects the request.
const DefaultTimeout = 250 * time.Millisecond

// Mode is the enforcement mode.
type Mode uint8

const (
	// ModeDetect reports matches but never blocks. It is the default.
	ModeDetect Mode = iota
	// ModeBlock blocks requests that the rules interrupt.
	ModeBlock
)

// FailureMode decides what happens when a request cannot be inspected:
// inspection timed out, failed, or was shed under overload.
type FailureMode uint8

const (
	// FailAuto is the default: fail closed in block mode and open in detect
	// mode. A fail-open block mode is bypassable: padding a request until
	// inspection times out gets it forwarded uninspected.
	FailAuto FailureMode = iota
	// FailOpen allows the request, choosing availability over enforcement.
	FailOpen
	// FailClosed rejects the request with 503 Service Unavailable.
	FailClosed
)

// Resolve returns the effective failure mode for an enforcement mode.
func (f FailureMode) Resolve(m Mode) FailureMode {
	if f != FailAuto {
		return f
	}
	if m == ModeBlock {
		return FailClosed
	}
	return FailOpen
}

// OversizeAction decides what happens to a request whose body is longer than
// the inspection limit.
type OversizeAction uint8

const (
	// OversizeAuto is the default: deny in block mode, allow in detect mode.
	OversizeAuto OversizeAction = iota
	// OversizeAllow inspects headers and URI only and forwards the body
	// uninspected; the verdict carries ReasonOversize so it is logged and
	// counted. A truncated body is never inspected: a prefix of JSON, XML
	// or multipart cannot be parsed, and inspecting a prefix of any body
	// leaves the rest as a hiding place.
	OversizeAllow
	// OversizeDeny rejects oversized bodies with 413 Content Too Large in
	// block mode (detect mode logs them), so no body escapes inspection.
	OversizeDeny
)

// Resolve returns the effective oversize action for an enforcement mode.
func (o OversizeAction) Resolve(m Mode) OversizeAction {
	if o != OversizeAuto {
		return o
	}
	if m == ModeBlock {
		return OversizeDeny
	}
	return OversizeAllow
}

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
	// Oversize decides what happens to bodies longer than the inspection
	// limit (request.Request.BodyTruncated).
	Oversize OversizeAction
	// Observer, if set, is told about every verdict (metrics).
	Observer Observer
	// Routes decides which paths skip inspection entirely or skip only body
	// inspection (tier T0). Nil inspects everything.
	Routes *router.Table
}

// Observer receives every verdict. Implementations must be fast and safe for
// concurrent use: they run on the request path.
type Observer interface {
	ObserveVerdict(v Verdict)
}

// Pipeline evaluates requests. It is safe for concurrent use.
type Pipeline struct {
	eval     rules.Evaluator
	mode     Mode
	failure  FailureMode
	timeout  time.Duration
	slots    chan struct{}
	oversize OversizeAction
	observer Observer
	routes   *router.Table
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
		eval:     eval,
		mode:     cfg.Mode,
		failure:  cfg.FailureMode.Resolve(cfg.Mode),
		timeout:  timeout,
		slots:    make(chan struct{}, maxConcurrent),
		oversize: cfg.Oversize.Resolve(cfg.Mode),
		observer: cfg.Observer,
		routes:   cfg.Routes,
	}
}

// InFlight returns the number of evaluations running now, including ones
// that timed out and are still finishing.
func (p *Pipeline) InFlight() int { return len(p.slots) }

// Capacity returns the maximum number of concurrent evaluations.
func (p *Pipeline) Capacity() int { return cap(p.slots) }

type outcome struct {
	res rules.Result
	err error
}

// Check inspects r and returns the verdict. It returns within the configured
// timeout even if the evaluator does not.
func (p *Pipeline) Check(ctx context.Context, r *request.Request) Verdict {
	start := time.Now()
	v := p.check(ctx, r)
	v.Duration = time.Since(start)
	if p.observer != nil {
		p.observer.ObserveVerdict(v)
	}
	return v
}

func (p *Pipeline) check(ctx context.Context, r *request.Request) Verdict {
	switch p.routes.Decide(r.RawURI) {
	case router.SkipAll:
		return Verdict{Action: ActionAllow, Reason: ReasonSkipped}
	case router.SkipBody:
		withoutBody := *r
		withoutBody.Body = nil
		withoutBody.BodyTruncated = false
		r = &withoutBody
	case router.InspectAll:
	}

	if !r.BodyTruncated {
		return p.evaluate(ctx, r)
	}
	if p.oversize == OversizeDeny && p.mode == ModeBlock {
		return p.enforce(Verdict{Reason: ReasonOversize}, http.StatusRequestEntityTooLarge)
	}
	withoutBody := *r
	withoutBody.Body = nil
	withoutBody.BodyTruncated = false
	v := p.evaluate(ctx, &withoutBody)
	if v.Reason != ReasonNone {
		return v
	}
	// Headers and URI were clean, but the body went uninspected.
	v.Reason = ReasonOversize
	if p.oversize == OversizeDeny { // detect mode: report what block mode would do
		return p.enforce(v, http.StatusRequestEntityTooLarge)
	}
	return v
}

// evaluate runs the rule evaluator under admission control and the deadline.
func (p *Pipeline) evaluate(ctx context.Context, r *request.Request) Verdict {
	// Admission control. Evaluations cannot be interrupted, so a timed-out
	// evaluation keeps using CPU until it finishes. Without a bound, a flood
	// of expensive requests saturates every core and makes all requests time
	// out, which with fail-open switches inspection off.
	select {
	case p.slots <- struct{}{}:
	default:
		return p.failed(ReasonOverload)
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// The evaluator runs on its own goroutine so the deadline can be enforced
	// here. A late result is discarded; the buffered channel lets that
	// goroutine finish without leaking, and it releases its slot only then.
	done := make(chan outcome, 1)
	go func() {
		defer func() { <-p.slots }()
		// net/http recovers panics only on the handler goroutine; a panic
		// here (in the rule engine or a callback it runs) would kill the
		// process. Turn it into an evaluation error instead.
		defer func() {
			if v := recover(); v != nil {
				done <- outcome{err: fmt.Errorf("evaluator panic: %v", v)}
			}
		}()
		res, err := p.eval.Evaluate(ctx, r)
		done <- outcome{res: res, err: err}
	}()

	select {
	case o := <-done:
		if o.err != nil {
			return p.failed(ReasonError)
		}
		return p.decide(o.res)
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return p.failed(ReasonTimeout)
		}
		return p.failed(ReasonCanceled)
	}
}

func (p *Pipeline) decide(res rules.Result) Verdict {
	v := Verdict{Action: ActionAllow, RuleIDs: res.MatchedRuleIDs, InterruptingRuleID: res.RuleID}
	if !res.Interrupted {
		return v
	}
	v.Reason = ReasonRule
	status := res.Status
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	return p.enforce(v, status)
}

// enforce turns a would-block verdict into a deny with status in block mode,
// or a log in detect mode.
func (p *Pipeline) enforce(v Verdict, status int) Verdict {
	if p.mode == ModeDetect {
		v.Action = ActionLog
		return v
	}
	v.Action = ActionDeny
	v.Status = status
	return v
}

func (p *Pipeline) failed(reason Reason) Verdict {
	if p.failure == FailClosed {
		return Verdict{Action: ActionDeny, Status: http.StatusServiceUnavailable, Reason: reason}
	}
	return Verdict{Action: ActionAllow, Reason: reason}
}
