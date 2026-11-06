// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// metricNameRE finds the metrics the code registers: a Prometheus *Opts
// literal's Name.
var metricNameRE = regexp.MustCompile(`Name:\s*"(inkwall_[a-z0-9_]+)"`)

// skippedSourceDirs hold code that isn't shipped: tools, tests and fakes.
var skippedSourceDirs = map[string]bool{"hack": true, "test": true, "testdata": true, "vendor": true, ".git": true, "node_modules": true}

// checkMetrics reports the metrics the shipped Go code registers that the
// metrics doc doesn't name.
func (r *repo) checkMetrics(doc string) []problem {
	src, err := fs.ReadFile(r.fsys, doc)
	if err != nil {
		return []problem{{doc, 0, "cannot read it"}}
	}
	text := string(src)
	defined := map[string]string{} // metric -> the first file registering it
	err = fs.WalkDir(r.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skippedSourceDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if path.Ext(p) != ".go" || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := fs.ReadFile(r.fsys, p)
		if err != nil {
			return err
		}
		for _, m := range metricNameRE.FindAllStringSubmatch(string(b), -1) {
			if _, ok := defined[m[1]]; !ok {
				defined[m[1]] = p
			}
		}
		return nil
	})
	if err != nil {
		return []problem{{doc, 0, fmt.Sprintf("listing the metrics: %v", err)}}
	}
	names := make([]string, 0, len(defined))
	for n := range defined {
		names = append(names, n)
	}
	sort.Strings(names)
	var probs []problem
	for _, n := range names {
		if !strings.Contains(text, "`"+n+"`") {
			probs = append(probs, problem{doc, 0, fmt.Sprintf("metric %s (%s) is not listed", n, defined[n])})
		}
	}
	return probs
}
