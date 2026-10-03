// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import "time"

// Action is what the proxy should do with the request.
type Action uint8

const (
	// ActionAllow forwards the request.
	ActionAllow Action = iota
	// ActionDeny rejects the request with Verdict.Status.
	ActionDeny
	// ActionLog forwards the request but records that it would have been
	// blocked (detect mode).
	ActionLog
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// Reason explains a verdict.
type Reason uint8

const (
	// ReasonNone means no rule interrupted the request.
	ReasonNone Reason = iota
	// ReasonRule means a rule interrupted the request.
	ReasonRule
	// ReasonTimeout means inspection exceeded the deadline.
	ReasonTimeout
	// ReasonError means the evaluator failed.
	ReasonError
	// ReasonCanceled means the caller canceled the request.
	ReasonCanceled
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonRule:
		return "rule"
	case ReasonTimeout:
		return "timeout"
	case ReasonError:
		return "error"
	case ReasonCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// Verdict is the pipeline's decision for one request.
type Verdict struct {
	Action Action
	// Status is the HTTP status to return when Action is ActionDeny.
	Status int
	Reason Reason
	// InterruptingRuleID is the rule that interrupted the request, if any.
	InterruptingRuleID int
	// RuleIDs lists every rule that matched, including score-only matches.
	RuleIDs []int
	// Duration is the time spent inspecting.
	Duration time.Duration
}
