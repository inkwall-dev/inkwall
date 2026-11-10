// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package memlimit sets the Go runtime's soft memory limit from the
// container's memory limit, for the operator and the engine.
package memlimit

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
)

// Env has the container's memory limit in bytes: the chart (operator) and
// the injected engine set it from the downward API (resourceFieldRef
// limits.memory). Without a limit, Kubernetes gives the node's allocatable
// memory.
const Env = "MEMORY_LIMIT"

// unlimited is where a cgroup v1 limit means none: v1 reports "no limit"
// as the largest page-aligned int64.
const unlimited = 1 << 62

// Limit returns the Go runtime's soft memory limit: 90% of the container's
// memory limit, the rest left for what the runtime doesn't manage. 0 when
// GOMEMLIMIT is set (the runtime applied it) or no limit is known.
//
// The heap goal is otherwise twice the live heap at the last GC, so the RSS
// of a busy process reaches the container limit long before its live heap
// does (0004 §8). With a limit, the GC runs more often near it.
func Limit(getenv func(string) string) int64 {
	limit, _ := Detect(getenv, nil)
	return limit
}

// Detect returns Limit and where the container's limit came from: Env, or
// without it (a plain container: docker run --memory), the file of the
// process's cgroup that has it, cgroup v2's memory.max or v1's
// memory.limit_in_bytes, read from root (nil: no cgroup is read). "" when
// there is no limit.
func Detect(getenv func(string) string, root fs.FS) (int64, string) {
	if getenv("GOMEMLIMIT") != "" {
		return 0, ""
	}
	if limit, err := strconv.ParseInt(getenv(Env), 10, 64); err == nil && limit > 0 {
		return limit / 10 * 9, Env
	}
	if root == nil {
		return 0, ""
	}
	limit, file := cgroupLimit(root)
	if limit <= 0 {
		return 0, ""
	}
	return limit / 10 * 9, "/" + file
}

// cgroupLimit returns the memory limit of the process's cgroup, and the
// file it read, from /proc/self/cgroup: cgroup v2's unified hierarchy
// (0::/path) or v1's memory controller (N:memory:/path), the lowest of the
// cgroup's and its ancestors' under the mount. With a private cgroup
// namespace (Docker's default on v2), the mount's root is the container's
// cgroup, and the path "/".
func cgroupLimit(root fs.FS) (int64, string) {
	b, err := fs.ReadFile(root, "proc/self/cgroup")
	if err != nil {
		return 0, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		var dir, name string
		switch {
		case parts[0] == "0" && parts[1] == "":
			dir, name = "sys/fs/cgroup", "memory.max"
		case slices.Contains(strings.Split(parts[1], ","), "memory"):
			dir, name = "sys/fs/cgroup/memory", "memory.limit_in_bytes"
		default:
			continue
		}
		// The lowest limit of the cgroup and its ancestors, which bound
		// it too.
		var (
			limit int64
			from  string
		)
		for p := path.Clean("/" + parts[2]); ; p = path.Dir(p) {
			file := path.Join(dir, p, name)
			if l, ok := readLimit(root, file); ok && l > 0 && (limit == 0 || l < limit) {
				limit, from = l, file
			}
			if p == "/" {
				break
			}
		}
		return limit, from
	}
	return 0, ""
}

// readLimit reads a cgroup memory limit file: ok and 0 for no limit ("max",
// or v1's largest value), not ok when there is no such file or it doesn't
// hold a limit.
func readLimit(root fs.FS, file string) (int64, bool) {
	b, err := fs.ReadFile(root, file)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, true
	}
	limit, err := strconv.ParseInt(s, 10, 64)
	if err != nil || limit <= 0 {
		return 0, false
	}
	if limit >= unlimited {
		return 0, true
	}
	return limit, true
}

// Set applies Detect, with the root filesystem's cgroup, if there is a
// limit, and returns it and where it came from.
func Set(getenv func(string) string) (int64, string) {
	limit, from := Detect(getenv, os.DirFS("/"))
	if limit > 0 {
		debug.SetMemoryLimit(limit)
	}
	return limit, from
}
