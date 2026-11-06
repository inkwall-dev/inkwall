// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules defines the interface between the inspection pipeline and a
// rule engine. Coraza is the first implementation (package rules/coraza); the
// interface keeps a different engine possible without touching adapters.
//
// Evaluation takes a whole request with its buffered body prefix. Every
// adapter gathers the body before deciding, the ext_proc adapter too (Envoy's
// BUFFERED_PARTIAL body, or the chunks it streams in observability mode).
// Streaming evaluation (headers, then body chunks) is not built.
//
// An ExchangeEvaluator also keeps a request's evaluation open for its
// response (phases 3 and 4), for the policies that inspect responses: the
// response rules see what the request rules set (the paranoia level, the
// anomaly scores, the user's variables).
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
	// Matches says where each of those rules matched, unredacted: the
	// caller redacts before anything leaves the engine.
	Matches []Match
	// AnomalyScore is the CRS inbound anomaly score (0 without CRS), or
	// the outbound one for a response.
	AnomalyScore int
	// Detected reports that rules above the CRS's blocking paranoia level,
	// up to its detection level, reached the anomaly threshold: the request
	// (or response) is logged, never blocked, for them.
	Detected bool
}

// Match is where a rule matched.
type Match struct {
	RuleID int
	// Variable is the collection and key, e.g. ARGS:id.
	Variable string
	// Value is the matched data.
	Value string
}

// Evaluator evaluates requests against a compiled rule set. Implementations
// must be safe for concurrent use.
type Evaluator interface {
	Evaluate(ctx context.Context, r *request.Request) (Result, error)
}

// ExchangeEvaluator is an Evaluator that can keep a request's evaluation
// open for its response.
type ExchangeEvaluator interface {
	Evaluator
	// EvaluateExchange evaluates r as Evaluate does and, unless the
	// request was interrupted, returns the evaluation to continue with the
	// response. The caller must Close it.
	EvaluateExchange(ctx context.Context, r *request.Request) (Result, Exchange, error)
}

// Exchange is a request's evaluation, kept for its response. It is not
// safe for concurrent use.
type Exchange interface {
	// EvaluateResponse evaluates the response (phases 3 and 4), once. The
	// result lists only what matched the response.
	EvaluateResponse(ctx context.Context, resp *request.Response) (Result, error)
	// Close releases the evaluation.
	Close()
}

// ResponseBodyTypes are the media types of the response bodies the rules
// read; adapters buffer no others. A user's SecResponseBodyMimeType
// changes what Coraza reads, not what adapters buffer.
var ResponseBodyTypes = []string{
	"text/plain", "text/html", "text/xml",
	"application/json", "application/xml", "application/problem+json",
}
