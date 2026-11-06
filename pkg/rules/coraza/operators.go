// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// disabledOperators reach outside the engine: inspectFile runs a program
// for every value it inspects and rbl makes DNS queries to a domain the rule
// names. Rule sets are written by namespace users and run in a shared
// engine, so no binary that links this package registers them. The release
// builds also leave them out with Coraza's coraza.disabled_operators build
// tags; registering here covers every other build (go install, go test).
var disabledOperators = []string{"inspectFile", "rbl"}

func init() {
	for _, name := range disabledOperators {
		plugins.RegisterOperator(name, func(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
			return nil, fmt.Errorf("operator %s is disabled in Inkwall", name)
		})
	}
}
