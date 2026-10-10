// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command benchgate fails when benchmarks regressed. It reads the CSV output
// of `benchstat -format csv base.txt head.txt` on stdin, prints every
// regression, and exits 1 if there is one.
//
// A benchmark regressed when benchstat calls the difference significant (the
// "vs base" column is a percentage, not "~") and the head is slower, or uses
// more memory or allocations, by more than -threshold percent. Requiring
// significance keeps noise on shared CI runners from failing pull requests;
// the threshold keeps tiny but real changes from doing so (0001 §8: 5%).
package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	threshold := flag.Float64("threshold", 5, "maximum allowed regression in percent")
	flag.Parse()
	regressions, err := check(os.Stdin, *threshold)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchgate:", err)
		os.Exit(2)
	}
	if len(regressions) == 0 {
		fmt.Printf("no significant regression over %.0f%%\n", *threshold)
		return
	}
	for _, r := range regressions {
		fmt.Println("REGRESSION", r)
	}
	os.Exit(1)
}

// check returns one line per regression found in benchstat's CSV.
func check(r io.Reader, threshold float64) ([]string, error) {
	cr := csv.NewReader(r)
	// Header lines (goos:, pkg:, ...) have one field, data rows seven.
	cr.FieldsPerRecord = -1
	var (
		unit        string
		regressions []string
		rows        int
	)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 7 {
			continue
		}
		name := rec[0]
		switch {
		case name == "" && rec[5] == "vs base":
			// ",sec/op,CI,sec/op,CI,vs base,P" starts a unit section.
			unit = rec[1]
			continue
		case name == "" || name == "geomean" || unit == "":
			continue
		}
		rows++
		delta := rec[5]
		if delta == "~" || delta == "" {
			continue
		}
		base, err1 := strconv.ParseFloat(rec[1], 64)
		head, err2 := strconv.ParseFloat(rec[3], 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%s %s: unparsable values %q, %q", name, unit, rec[1], rec[3])
		}
		var pct float64
		switch {
		case base == 0 && head == 0:
			continue
		case base == 0:
			// From zero (e.g. a zero-allocation path that now allocates):
			// any increase is a regression.
			pct = 100
		default:
			pct = (head - base) / base * 100
		}
		if pct > threshold {
			regressions = append(regressions,
				fmt.Sprintf("%s %s: %s -> %s (%+.1f%%, %s)", name, unit, rec[1], rec[3], pct, strings.TrimSpace(rec[6])))
		}
	}
	if rows == 0 {
		return nil, errors.New("no benchmark rows in the input; is it benchstat -format csv output?")
	}
	return regressions, nil
}
