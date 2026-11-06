// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// disabledOperators reach outside the engine: inspectFile runs a program
// for every value it inspects and rbl makes DNS queries to a domain the rule
// names. Rule sets are written by namespace users and run in a shared
// engine, so CheckUserRules rejects them, and no binary that links this
// package runs them. The release builds also leave them out with Coraza's
// coraza.disabled_operators build tags; registering here covers every other
// build (go install, go test).
//
// They still compile, as operators that never match: rule sets accepted
// before they were rejected are in bundles already, and a bundle with a
// rule that doesn't compile is refused whole, which would keep every
// policy's rules from changing, or leave a new engine without any.
var disabledOperators = []string{"inspectFile", "rbl"}

type neverMatch struct{}

func (neverMatch) Evaluate(plugintypes.TransactionState, string) bool { return false }

func init() {
	for _, name := range disabledOperators {
		plugins.RegisterOperator(name, func(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
			return neverMatch{}, nil
		})
	}
}
