// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command releases prints the releases an upgrade test starts from, worked
// out from the repository's tags (#390): the latest patch of each of the
// -minors newest minor versions, newest first, without the leading v.
// Pre-releases (v0.4.0-rc.1) and other modules' tags are left out. On a
// release branch (release-X.Y) only X.Y and older count, so its test never
// starts from a newer release than its own.
//
//	go run ./hack/releases                         # 0.4.1
//	go run ./hack/releases -minors 2               # 0.4.1 and 0.3.3
//	go run ./hack/releases -branch release-0.3     # 0.3.3
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	tagRE    = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
	branchRE = regexp.MustCompile(`^release-(\d+)\.(\d+)$`)
)

type version struct{ major, minor, patch int }

func (v version) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s) // \d+ only; a value too large is 0, and harmless
	return n
}

// latest returns the latest patch of each of the minors newest minor
// versions among tags, newest first, at or below branch's minor version if
// branch is a release branch.
func latest(tags []string, branch string, minors int) []string {
	var limit *version
	if m := branchRE.FindStringSubmatch(branch); m != nil {
		limit = &version{atoi(m[1]), atoi(m[2]), int(^uint(0) >> 1)}
	}
	var vs []version
	for _, t := range tags {
		m := tagRE.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		v := version{atoi(m[1]), atoi(m[2]), atoi(m[3])}
		if limit != nil && limit.less(v) {
			continue
		}
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[j].less(vs[i]) })
	var out []string
	for i, v := range vs {
		if len(out) == minors {
			break
		}
		if i > 0 && vs[i-1].major == v.major && vs[i-1].minor == v.minor {
			continue // an older patch of a minor already printed
		}
		out = append(out, v.String())
	}
	return out
}

func main() {
	branch := flag.String("branch", "", "the branch under test: on release-X.Y, only releases up to X.Y count")
	minors := flag.Int("minors", 1, "how many minor versions to print the latest patch of")
	flag.Parse()

	var stderr bytes.Buffer
	cmd := exec.Command("git", "tag", "-l", "v*")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "releases: git tag: %v: %s\n", err, strings.TrimSpace(stderr.String()))
		os.Exit(2)
	}
	vs := latest(strings.Fields(string(out)), *branch, *minors)
	if len(vs) == 0 {
		fmt.Fprintln(os.Stderr, "releases: no release tag found: fetch the tags (git fetch --tags), or set the version yourself")
		os.Exit(1)
	}
	fmt.Println(strings.Join(vs, "\n"))
}
