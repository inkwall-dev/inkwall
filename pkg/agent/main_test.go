// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package's tests when one leaves goroutines running
// (#395): a connection, stream or timer the code under test didn't stop.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
