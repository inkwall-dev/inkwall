// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"sync/atomic"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Swap is an Evaluator whose rules can be replaced while it serves
// (standalone mode's rule reload, #359): an evaluation runs entirely on the
// evaluator it started with, and those that start after Store use the new
// one. It is safe for concurrent use.
type Swap struct {
	cur atomic.Pointer[box]
}

type box struct{ e Evaluator }

var _ ExchangeEvaluator = (*Swap)(nil)

// NewSwap returns a Swap evaluating with e.
func NewSwap(e Evaluator) *Swap {
	s := &Swap{}
	s.Store(e)
	return s
}

// Store makes e the evaluator of the evaluations that start from now on.
func (s *Swap) Store(e Evaluator) { s.cur.Store(&box{e}) }

// Load returns the current evaluator.
func (s *Swap) Load() Evaluator { return s.cur.Load().e }

// Evaluate implements Evaluator.
func (s *Swap) Evaluate(ctx context.Context, r *request.Request) (Result, error) {
	return s.Load().Evaluate(ctx, r)
}

// EvaluateExchange implements ExchangeEvaluator: with the current
// evaluator's exchange, or none if it keeps none.
func (s *Swap) EvaluateExchange(ctx context.Context, r *request.Request) (Result, Exchange, error) {
	e := s.Load()
	if ee, ok := e.(ExchangeEvaluator); ok {
		return ee.EvaluateExchange(ctx, r)
	}
	res, err := e.Evaluate(ctx, r)
	return res, nil, err
}
