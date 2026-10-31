// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"
)

// MemoryLimitEnv has the container's memory limit in bytes: the chart sets
// it from the downward API (resourceFieldRef limits.memory). Without a
// limit, Kubernetes gives the node's allocatable memory.
const MemoryLimitEnv = "MEMORY_LIMIT"

// memoryLimit returns the Go runtime's soft memory limit: 90% of the
// container's memory limit, the rest left for what the runtime doesn't
// manage. 0 when GOMEMLIMIT is set (the runtime applied it) or no limit is
// known.
//
// The heap goal is otherwise twice the live heap at the last GC, so the
// RSS of a busy operator reaches the container limit long before its live
// heap does (0004 §8). With a limit, the GC runs more often near it.
func memoryLimit(getenv func(string) string) int64 {
	if getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit, err := strconv.ParseInt(getenv(MemoryLimitEnv), 10, 64)
	if err != nil || limit <= 0 {
		return 0
	}
	return limit / 10 * 9
}
