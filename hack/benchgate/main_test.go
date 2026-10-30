// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
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
	got, err := check(strings.NewReader(csvOut), 5)
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

	if got, _ := check(strings.NewReader(csvOut), 20); len(got) != 1 {
		t.Fatalf("threshold 20: %v", got)
	}
}

func TestCheckRejectsOtherInput(t *testing.T) {
	for _, in := range []string{"", "goos: linux\n", "name old time/op new time/op delta\n"} {
		if _, err := check(strings.NewReader(in), 5); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestRunConfirm(t *testing.T) {
	dir := t.TempDir()
	flagged := filepath.Join(dir, "flagged")

	// First run: both regressions fail the gate and are written down.
	var out strings.Builder
	if err := run(strings.NewReader(csvOut), &out, 5, flagged, ""); !errors.Is(err, errRegressed) {
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
	err = run(strings.NewReader(recheck), &out, 5, "", flagged)
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
	if err := run(strings.NewReader(clean), &out, 5, "", flagged); err != nil {
		t.Fatalf("clean re-check: %v\n%s", err, &out)
	}

	// A regression the first run did not flag does not fail the re-check.
	if err := os.WriteFile(flagged, []byte(router+"\tDecide-12\tallocs/op\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(strings.NewReader(csvOut), &out, 5, "", flagged); !errors.Is(err, errRegressed) {
		t.Fatalf("partial re-check: %v\n%s", err, &out)
	}
	if !strings.Contains(out.String(), "NOT CONFIRMED "+coraza+" Evaluate/benign_get-12 sec/op") {
		t.Fatalf("partial re-check output:\n%s", &out)
	}
}
