// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"sync"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

type fixed struct{ id int }

func (f fixed) Evaluate(context.Context, *request.Request) (Result, error) {
	return Result{RuleID: f.id}, nil
}

type exchanging struct{ fixed }

func (e exchanging) EvaluateExchange(ctx context.Context, r *request.Request) (Result, Exchange, error) {
	res, _ := e.Evaluate(ctx, r)
	return res, nil, nil
}

// TestSwap: Store replaces the evaluator for the evaluations that start
// after it; concurrent evaluations see one or the other, never an error.
func TestSwap(t *testing.T) {
	s := NewSwap(fixed{1})
	ctx := context.Background()
	if res, _ := s.Evaluate(ctx, &request.Request{}); res.RuleID != 1 {
		t.Fatalf("rule %d", res.RuleID)
	}
	// An evaluator without exchanges: evaluated, no exchange.
	if res, x, err := s.EvaluateExchange(ctx, &request.Request{}); err != nil || x != nil || res.RuleID != 1 {
		t.Fatalf("EvaluateExchange: %+v %v %v", res, x, err)
	}
	s.Store(exchanging{fixed{2}})
	if res, _, _ := s.EvaluateExchange(ctx, &request.Request{}); res.RuleID != 2 {
		t.Fatalf("after Store: rule %d", res.RuleID)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 1000 {
				if i == 0 {
					s.Store(fixed{3})
					continue
				}
				if res, err := s.Evaluate(ctx, &request.Request{}); err != nil || res.RuleID == 0 {
					t.Error(res, err)
					return
				}
			}
		})
	}
	wg.Wait()
}
