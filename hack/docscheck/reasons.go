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

// reasonRE finds the condition reasons the operator sets: its Reason*
// constants.
var reasonRE = regexp.MustCompile(`\bReason[A-Za-z0-9]*\s*=\s*"([A-Za-z]+)"`)

// checkReasons reports the condition reasons the operator's code (operator/,
// tests aside) defines that the doc doesn't name in backticks.
func (r *repo) checkReasons(doc string) []problem {
	src, err := fs.ReadFile(r.fsys, doc)
	if err != nil {
		return []problem{{doc, 0, "cannot read it"}}
	}
	text := string(src)
	defined := map[string]string{} // reason -> the first file defining it
	err = fs.WalkDir(r.fsys, "operator", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
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
		for _, m := range reasonRE.FindAllStringSubmatch(string(b), -1) {
			if _, ok := defined[m[1]]; !ok {
				defined[m[1]] = p
			}
		}
		return nil
	})
	if err != nil {
		return []problem{{doc, 0, fmt.Sprintf("listing the condition reasons: %v", err)}}
	}
	reasons := make([]string, 0, len(defined))
	for n := range defined {
		reasons = append(reasons, n)
	}
	sort.Strings(reasons)
	var probs []problem
	for _, n := range reasons {
		if !strings.Contains(text, "`"+n+"`") {
			probs = append(probs, problem{doc, 0, fmt.Sprintf("condition reason %s (%s) is not documented", n, defined[n])})
		}
	}
	return probs
}
