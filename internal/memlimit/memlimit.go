// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package memlimit sets the Go runtime's soft memory limit from the
// container's memory limit, for the operator and the engine.
package memlimit

import (
	"runtime/debug"
	"strconv"
)

// Env has the container's memory limit in bytes: the chart (operator) and
// the injected engine set it from the downward API (resourceFieldRef
// limits.memory). Without a limit, Kubernetes gives the node's allocatable
// memory.
const Env = "MEMORY_LIMIT"

// Limit returns the Go runtime's soft memory limit: 90% of the container's
// memory limit, the rest left for what the runtime doesn't manage. 0 when
// GOMEMLIMIT is set (the runtime applied it) or no limit is known.
//
// The heap goal is otherwise twice the live heap at the last GC, so the RSS
// of a busy process reaches the container limit long before its live heap
// does (0004 §8). With a limit, the GC runs more often near it.
func Limit(getenv func(string) string) int64 {
	if getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit, err := strconv.ParseInt(getenv(Env), 10, 64)
	if err != nil || limit <= 0 {
		return 0
	}
	return limit / 10 * 9
}

// Set applies Limit, if any, and returns it.
func Set(getenv func(string) string) int64 {
	limit := Limit(getenv)
	if limit > 0 {
		debug.SetMemoryLimit(limit)
	}
	return limit
}
