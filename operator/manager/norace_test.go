// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package manager

import "time"

// waitFor is how long eventually waits (race_test.go has the race
// detector's).
const waitFor = time.Minute
