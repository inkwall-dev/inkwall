// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Shaped like the output of benchstat -format csv.
const csvOut = `goos: linux
goarch: amd64
pkg: github.com/inkwall-dev/inkwall/pkg/rules/coraza
cpu: 12th Gen Intel(R) Core(TM) i7-1255U
,base.txt,,head.txt,,,
,sec/op,CI,sec/op,CI,vs base,P
Evaluate/benign_get-12,0.000449,2%,0.000520,1%,+15.81%,p=0.000 n=8
Evaluate/benign_form-12,0.000634,2%,0.000700,9%,~,p=0.240 n=8
Evaluate/attack_sqli-12,0.000472,1%,0.000480,1%,+1.69%,p=0.010 n=8
Evaluate/attack_xss-12,0.000517,1%,0.000400,1%,-22.63%,p=0.000 n=8
geomean,0.0005,,0.0006,,+9.00%,

pkg: github.com/inkwall-dev/inkwall/pkg/router
,base.txt,,head.txt,,,
,allocs/op,CI,allocs/op,CI,vs base,P
Evaluate/benign_get-12,2812,0%,2812,0%,~,p=1.000 n=8
Decide-12,0,0%,1,0%,+Inf%,p=0.000 n=8
geomean,,,,,+0.00%,
`

const (
	coraza = "github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	router = "github.com/inkwall-dev/inkwall/pkg/router"
)

func TestCheck(t *testing.T) {
	got, err := check(strings.NewReader(csvOut), limits{threshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	// Flagged: +15.8% significant, and 0 -> 1 allocation. Not flagged: not
	// significant (~), under the threshold, improvements, geomean.
	want := []string{
		coraza + "\tEvaluate/benign_get-12\tsec/op",
		router + "\tDecide-12\tallocs/op",
	}
	if len(got) != len(want) {
		t.Fatalf("regressions: %v", got)
	}
	for i, r := range got {
		if r.key() != want[i] {
			t.Errorf("regression %d: key %q, want %q", i, r.key(), want[i])
		}
	}

	if got, _ := check(strings.NewReader(csvOut), limits{threshold: 20}); len(got) != 1 {
		t.Fatalf("threshold 20: %v", got)
	}
}

func TestCheckRejectsOtherInput(t *testing.T) {
	for _, in := range []string{"", "goos: linux\n", "name old time/op new time/op delta\n"} {
		if _, err := check(strings.NewReader(in), limits{threshold: 5}); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestRunConfirm(t *testing.T) {
	dir := t.TempDir()
	flagged := filepath.Join(dir, "flagged")

	// First run: both regressions fail the gate and are written down.
	var out strings.Builder
	if err := run(strings.NewReader(csvOut), &out, limits{threshold: 5}, flagged, ""); !errors.Is(err, errRegressed) {
		t.Fatalf("first run: %v\n%s", err, &out)
	}
	keys, err := os.ReadFile(flagged)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(keys), "\n"); n != 2 {
		t.Fatalf("flagged file has %d lines:\n%s", n, keys)
	}

	// A re-check that shows only the allocation regression: that one is
	// confirmed, the other is reported as not repeated.
	recheck := strings.Replace(csvOut, "+15.81%", "~", 1)
	out.Reset()
	err = run(strings.NewReader(recheck), &out, limits{threshold: 5}, "", flagged)
	if !errors.Is(err, errRegressed) {
		t.Fatalf("re-check: %v\n%s", err, &out)
	}
	if !strings.Contains(out.String(), "REGRESSION "+router+" Decide-12 allocs/op") ||
		!strings.Contains(out.String(), "NOT REPEATED "+coraza+" Evaluate/benign_get-12 sec/op") {
		t.Fatalf("re-check output:\n%s", &out)
	}

	// Nothing repeats: the gate passes.
	clean := strings.Replace(recheck, "+Inf%", "~", 1)
	out.Reset()
	if err := run(strings.NewReader(clean), &out, limits{threshold: 5}, "", flagged); err != nil {
		t.Fatalf("clean re-check: %v\n%s", err, &out)
	}

	// A regression the first run did not flag does not fail the re-check.
	if err := os.WriteFile(flagged, []byte(router+"\tDecide-12\tallocs/op\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(strings.NewReader(csvOut), &out, limits{threshold: 5}, "", flagged); !errors.Is(err, errRegressed) {
		t.Fatalf("partial re-check: %v\n%s", err, &out)
	}
	if !strings.Contains(out.String(), "NOT CONFIRMED "+coraza+" Evaluate/benign_get-12 sec/op") {
		t.Fatalf("partial re-check output:\n%s", &out)
	}
}

// The #413 and #428 bench failures, as benchstat printed them on CI: the
// same machine code for pkg/policy Lookup, moved in the binary; 8-14% on a
// ~440 ns benchmark, allocations unchanged. Plus a 1.5 µs benchmark that
// really got 8% slower, and sub-microsecond ones that really regressed.
const layoutCSV = `goos: linux
goarch: amd64
pkg: github.com/inkwall-dev/inkwall/pkg/policy
cpu: AMD EPYC 7763 64-Core Processor
,base.txt,,head.txt,,,
,sec/op,CI,sec/op,CI,vs base,P
Lookup-4,4.334e-07,1%,4.956e-07,0%,+14.36%,p=0.000 n=8
Slow-4,1.5e-06,1%,1.62e-06,1%,+8.00%,p=0.000 n=8
Doubled-4,2e-07,1%,4.2e-07,1%,+110.00%,p=0.000 n=8
Allocates-4,3e-07,1%,3.3e-07,1%,+10.00%,p=0.000 n=8
geomean,4e-07,,4.5e-07,,+12.00%,
,base.txt,,head.txt,,,
,B/op,CI,B/op,CI,vs base,P
Lookup-4,56,0%,56,0%,~,p=1.000 n=8
Allocates-4,56,0%,80,0%,+42.86%,p=0.000 n=8
geomean,,,,,+0.00%,
,base.txt,,head.txt,,,
,allocs/op,CI,allocs/op,CI,vs base,P
Lookup-4,2,0%,2,0%,~,p=1.000 n=8
Allocates-4,2,0%,3,0%,+50.00%,p=0.000 n=8
geomean,,,,,+0.00%,
`

// Below 1 µs/op, time is gated at a higher threshold: a code-layout shift
// moves such a benchmark by up to ~15% without any change in what it runs
// (#422). Memory and allocations keep the threshold, and so does time
// above 1 µs.
func TestCheckFastBenchmarks(t *testing.T) {
	const policy = "github.com/inkwall-dev/inkwall/pkg/policy"
	got, err := check(strings.NewReader(layoutCSV), defaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range got {
		keys = append(keys, r.key())
	}
	want := []string{
		policy + "\tSlow-4\tsec/op",         // 8% on 1.5 µs: a real regression
		policy + "\tDoubled-4\tsec/op",      // +110% under 1 µs: past the fast threshold
		policy + "\tAllocates-4\tB/op",      // more memory
		policy + "\tAllocates-4\tallocs/op", // and an allocation more
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("regressions:\n%s\nwant:\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
	// Lookup, the layout shift, is not among them; its own CSV passes.
	lookupOnly := strings.Join(slices.DeleteFunc(strings.Split(layoutCSV, "\n"), func(l string) bool {
		return strings.HasPrefix(l, "Slow-") || strings.HasPrefix(l, "Doubled-") || strings.HasPrefix(l, "Allocates-")
	}), "\n")
	var out strings.Builder
	if err := run(strings.NewReader(lookupOnly), &out, defaultLimits, "", ""); err != nil {
		t.Errorf("the layout shift fails the gate: %v\n%s", err, &out)
	}
	// With one threshold for all, as before #422, it would fail.
	if got, _ := check(strings.NewReader(lookupOnly), limits{threshold: 5}); len(got) != 1 {
		t.Errorf("one threshold: %v", got)
	}
}
