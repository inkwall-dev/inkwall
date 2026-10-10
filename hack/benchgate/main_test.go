// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
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

,base.txt,,head.txt,,,
,allocs/op,CI,allocs/op,CI,vs base,P
Evaluate/benign_get-12,2812,0%,2812,0%,~,p=1.000 n=8
Decide-12,0,0%,1,0%,+Inf%,p=0.000 n=8
geomean,,,,,+0.00%,
`

func TestCheck(t *testing.T) {
	got, err := check(strings.NewReader(csvOut), 5)
	if err != nil {
		t.Fatal(err)
	}
	// Flagged: +15.8% significant, and 0 -> 1 allocation. Not flagged: not
	// significant (~), under the threshold, improvements, geomean.
	if len(got) != 2 ||
		!strings.HasPrefix(got[0], "Evaluate/benign_get-12 sec/op") ||
		!strings.HasPrefix(got[1], "Decide-12 allocs/op") {
		t.Fatalf("regressions:\n%s", strings.Join(got, "\n"))
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
