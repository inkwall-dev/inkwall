// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package memlimit

import (
	"testing"
	"testing/fstest"
)

// Without MEMORY_LIMIT (a plain container: docker run --memory 256m), the
// limit comes from the container's cgroup, v2 or v1 (#537).
func TestLimitFromCgroup(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	v2 := fstest.MapFS{
		"proc/self/cgroup":         file("0::/\n"),
		"sys/fs/cgroup/memory.max": file("268435456\n"),
	}
	// The host's cgroup namespace: the process's own cgroup, under the
	// mount.
	v2Nested := fstest.MapFS{
		"proc/self/cgroup": file("0::/system.slice/docker-0123.scope\n"),
		"sys/fs/cgroup/system.slice/docker-0123.scope/memory.max": file("536870912\n"),
		"sys/fs/cgroup/memory.max":                                file("max\n"),
	}
	// A parent's lower limit bounds the cgroup too.
	v2Parent := fstest.MapFS{
		"proc/self/cgroup": file("0::/app.slice/run-1.scope\n"),
		"sys/fs/cgroup/app.slice/run-1.scope/memory.max": file("max\n"),
		"sys/fs/cgroup/app.slice/memory.max":             file("268435456\n"),
	}
	// The cgroup's path isn't under the mount (the host's namespace, the
	// container's cgroup mounted): the mount's root.
	v2Hidden := fstest.MapFS{
		"proc/self/cgroup":         file("0::/system.slice/docker-0123.scope\n"),
		"sys/fs/cgroup/memory.max": file("268435456\n"),
	}
	v2Unlimited := fstest.MapFS{
		"proc/self/cgroup":         file("0::/\n"),
		"sys/fs/cgroup/memory.max": file("max\n"),
	}
	v1 := fstest.MapFS{
		"proc/self/cgroup": file("12:pids:/docker/0123\n11:memory:/docker/0123\n1:name=systemd:/docker/0123\n"),
		"sys/fs/cgroup/memory/docker/0123/memory.limit_in_bytes": file("268435456\n"),
	}
	// A private cgroup namespace on v1: the container's cgroup is the
	// mount's root.
	v1Root := fstest.MapFS{
		"proc/self/cgroup":                           file("11:memory:/\n"),
		"sys/fs/cgroup/memory/memory.limit_in_bytes": file("268435456\n"),
	}
	v1Unlimited := fstest.MapFS{
		"proc/self/cgroup":                           file("11:memory:/\n"),
		"sys/fs/cgroup/memory/memory.limit_in_bytes": file("9223372036854771712\n"),
	}
	for _, tc := range []struct {
		name     string
		env      map[string]string
		fsys     fstest.MapFS
		want     int64
		wantFrom string
	}{
		{"v2", nil, v2, 241591905, "/sys/fs/cgroup/memory.max"},
		{"v2 nested", nil, v2Nested, 483183819, "/sys/fs/cgroup/system.slice/docker-0123.scope/memory.max"},
		{"v2 parent", nil, v2Parent, 241591905, "/sys/fs/cgroup/app.slice/memory.max"},
		{"v2 hidden", nil, v2Hidden, 241591905, "/sys/fs/cgroup/memory.max"},
		{"v2 unlimited", nil, v2Unlimited, 0, ""},
		{"v1", nil, v1, 241591905, "/sys/fs/cgroup/memory/docker/0123/memory.limit_in_bytes"},
		{"v1 root", nil, v1Root, 241591905, "/sys/fs/cgroup/memory/memory.limit_in_bytes"},
		{"v1 unlimited", nil, v1Unlimited, 0, ""},
		{"no cgroup", nil, fstest.MapFS{}, 0, ""},
		{"garbage", nil, fstest.MapFS{"proc/self/cgroup": file("0::/\n"), "sys/fs/cgroup/memory.max": file("lots\n")}, 0, ""},
		// MEMORY_LIMIT wins; GOMEMLIMIT, which the runtime applied, wins over both.
		{"MEMORY_LIMIT wins", map[string]string{Env: "536870912"}, v2, 483183819, Env},
		{"GOMEMLIMIT wins", map[string]string{"GOMEMLIMIT": "300MiB"}, v2, 0, ""},
		// An unparseable MEMORY_LIMIT: the cgroup's.
		{"bad MEMORY_LIMIT", map[string]string{Env: "512Mi"}, v2, 241591905, "/sys/fs/cgroup/memory.max"},
	} {
		got, from := Detect(func(k string) string { return tc.env[k] }, tc.fsys)
		if got != tc.want || from != tc.wantFrom {
			t.Errorf("%s: %d from %q, want %d from %q", tc.name, got, from, tc.want, tc.wantFrom)
		}
	}
}
