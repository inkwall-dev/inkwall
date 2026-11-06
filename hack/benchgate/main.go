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
//
// Below -fast-below per op (1 µs), time is gated at -fast-threshold (25%)
// instead: where the compiler and linker place a benchmark's code moves such
// a benchmark by up to ~15% with no change in what it runs (#413, #428,
// #422), because alignment and branch-predictor aliasing weigh on a few
// hundred nanoseconds. Their bytes and allocations per op keep -threshold:
// layout doesn't change those. docs/design/0001 §8 says how to tell a layout
// shift from a real regression.
//
// Regressions are keyed by package, benchmark and unit. -flagged writes the
// keys found, one "pkg<TAB>benchmark<TAB>unit" line each. -confirm reads such
// a file from an earlier run and fails only on regressions that are in it as
// well, so a regression must show on two independent runs: real ones repeat,
// noise mostly does not.
package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	lim := defaultLimits
	flag.Float64Var(&lim.threshold, "threshold", lim.threshold, "maximum allowed regression in percent")
	flag.Float64Var(&lim.fastThreshold, "fast-threshold", lim.fastThreshold, "maximum allowed time regression in percent of a benchmark faster than -fast-below")
	flag.DurationVar(&lim.fastBelow, "fast-below", lim.fastBelow, "benchmarks faster than this per op (on the base) are gated on time at -fast-threshold")
	flagged := flag.String("flagged", "", "write the regressions found to this file, one key per line")
	confirm := flag.String("confirm", "", "fail only on regressions also listed in this file (from -flagged)")
	flag.Parse()
	if err := run(os.Stdin, os.Stdout, lim, *flagged, *confirm); err != nil {
		if errors.Is(err, errRegressed) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "benchgate:", err)
		os.Exit(2)
	}
}

var errRegressed = errors.New("regressed")

// limits are the allowed regressions.
type limits struct {
	threshold float64 // percent
	// fastThreshold is the percent allowed on the time of a benchmark
	// faster than fastBelow per op; 0: threshold.
	fastThreshold float64
	fastBelow     time.Duration
}

var defaultLimits = limits{threshold: 5, fastThreshold: 25, fastBelow: time.Microsecond}

func run(in io.Reader, out io.Writer, lim limits, flaggedFile, confirmFile string) error {
	var earlier map[string]bool
	if confirmFile != "" {
		var err error
		if earlier, err = readKeys(confirmFile); err != nil {
			return err
		}
	}
	regressions, err := check(in, lim)
	if err != nil {
		return err
	}
	if flaggedFile != "" {
		var b strings.Builder
		for _, r := range regressions {
			b.WriteString(r.key() + "\n")
		}
		if err := os.WriteFile(flaggedFile, []byte(b.String()), 0o600); err != nil {
			return err
		}
	}
	failed := 0
	for _, r := range regressions {
		if earlier != nil && !earlier[r.key()] {
			fmt.Fprintln(out, "NOT CONFIRMED", r)
			continue
		}
		fmt.Fprintln(out, "REGRESSION", r)
		failed++
	}
	if earlier != nil {
		// Flagged on the first run but not this one: noise.
		seen := map[string]bool{}
		for _, r := range regressions {
			seen[r.key()] = true
		}
		var gone []string
		for k := range earlier {
			if !seen[k] {
				gone = append(gone, k)
			}
		}
		sort.Strings(gone)
		for _, k := range gone {
			fmt.Fprintln(out, "NOT REPEATED", strings.ReplaceAll(k, "\t", " "))
		}
	}
	if failed > 0 {
		return errRegressed
	}
	fmt.Fprintf(out, "no significant regression over %.0f%%", lim.threshold)
	if lim.fastThreshold > 0 {
		fmt.Fprintf(out, " (time under %v/op: %.0f%%)", lim.fastBelow, lim.fastThreshold)
	}
	fmt.Fprintln(out)
	return nil
}

// regression is one benchmark and unit that got worse.
type regression struct {
	pkg, name, unit string
	detail          string
}

func (r regression) key() string { return r.pkg + "\t" + r.name + "\t" + r.unit }

func (r regression) String() string {
	return fmt.Sprintf("%s %s %s: %s", r.pkg, r.name, r.unit, r.detail)
}

func readKeys(path string) (map[string]bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	keys := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := s.Text(); line != "" {
			keys[line] = true
		}
	}
	return keys, s.Err()
}

// check returns the regressions found in benchstat's CSV.
func check(r io.Reader, lim limits) ([]regression, error) {
	cr := csv.NewReader(r)
	// Header lines (goos:, pkg:, ...) have one field, data rows seven.
	cr.FieldsPerRecord = -1
	var (
		pkg, unit   string
		regressions []regression
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
		if len(rec) == 1 {
			if p, ok := strings.CutPrefix(rec[0], "pkg: "); ok {
				pkg, unit = strings.TrimSpace(p), ""
			}
			continue
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
		threshold := lim.threshold
		if unit == "sec/op" && lim.fastThreshold > 0 && base < lim.fastBelow.Seconds() {
			threshold = lim.fastThreshold
		}
		if pct > threshold {
			regressions = append(regressions, regression{
				pkg: pkg, name: name, unit: unit,
				detail: fmt.Sprintf("%s -> %s (%+.1f%%, %s)", rec[1], rec[3], pct, strings.TrimSpace(rec[6])),
			})
		}
	}
	if rows == 0 {
		return nil, errors.New("no benchmark rows in the input; is it benchstat -format csv output?")
	}
	return regressions, nil
}
