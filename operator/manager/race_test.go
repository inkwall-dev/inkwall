// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package manager

import "time"

// waitFor is how long eventually waits. The race detector makes the
// operator's bundle builds about ten times slower, and CI's runners are
// slower again, so a build that takes seconds can take minutes there.
const waitFor = 4 * time.Minute
