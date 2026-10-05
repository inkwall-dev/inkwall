// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules defines the interface between the inspection pipeline and a
// rule engine. Coraza is the first implementation (package rules/coraza); the
// interface keeps a different engine possible without touching adapters.
//
// Evaluation currently takes a whole request with its buffered body prefix.
// Streaming evaluation (headers, then body chunks, then response) arrives with
// the Envoy ext_proc adapter.
package rules

import (
	"context"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Result is the outcome of evaluating one request.
type Result struct {
	// Interrupted reports that a rule asked to block the request.
	Interrupted bool
	// Status is the HTTP status the blocking rule asked for (0 if unset).
	Status int
	// RuleID is the rule that interrupted the request, if any.
	RuleID int
	// MatchedRuleIDs lists every rule that matched request data, including
	// rules that only contributed to an anomaly score.
	MatchedRuleIDs []int
}

// Evaluator evaluates requests against a compiled rule set. Implementations
// must be safe for concurrent use.
type Evaluator interface {
	Evaluate(ctx context.Context, r *request.Request) (Result, error)
}
