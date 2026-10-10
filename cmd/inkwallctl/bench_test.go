// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

func TestPercentile(t *testing.T) {
	var lat []time.Duration
	for i := 1; i <= 1000; i++ {
		lat = append(lat, time.Duration(i)*time.Microsecond)
	}
	for p, want := range map[float64]time.Duration{0.5: 500, 0.99: 990, 0.999: 999, 1: 1000} {
		if got := percentile(lat, p); got != want*time.Microsecond {
			t.Errorf("p%v = %v, want %v", p*100, got, want*time.Microsecond)
		}
	}
	if got := percentile([]time.Duration{7}, 0.999); got != 7 {
		t.Errorf("single sample: %v", got)
	}
}

func TestWeightedSchedule(t *testing.T) {
	corpus := []corpusEntry{{weight: 3}, {weight: 1}}
	s := weighted(corpus)
	counts := map[int]int{}
	for _, i := range s {
		counts[i]++
	}
	if len(s) != 4 || counts[0] != 3 || counts[1] != 1 {
		t.Fatalf("schedule %v", s)
	}
	// Fixed seed: the same order every run.
	if again := weighted(corpus); !slices.Equal(s, again) {
		t.Fatalf("schedule not deterministic: %v, %v", s, again)
	}
}

func TestWrongVerdict(t *testing.T) {
	resp := func(a enginev1.Action, r enginev1.Reason) *enginev1.CheckResponse {
		return &enginev1.CheckResponse{Action: a, Reason: r}
	}
	allow := resp(enginev1.Action_ACTION_ALLOW, enginev1.Reason_REASON_NONE)
	deny := resp(enginev1.Action_ACTION_DENY, enginev1.Reason_REASON_RULE)
	logged := resp(enginev1.Action_ACTION_LOG, enginev1.Reason_REASON_RULE)
	overload := resp(enginev1.Action_ACTION_DENY, enginev1.Reason_REASON_OVERLOAD)
	failedOpen := resp(enginev1.Action_ACTION_ALLOW, enginev1.Reason_REASON_TIMEOUT)
	for _, tc := range []struct {
		expect string
		out    *enginev1.CheckResponse
		wrong  bool
	}{
		{"allow", allow, false},
		{"allow", deny, true},
		{"deny", deny, false},
		{"deny", logged, false},
		{"deny", allow, true},
		{"deny", overload, true},
		{"allow", failedOpen, true},
		{"", deny, false},
	} {
		if got := wrongVerdict(tc.expect, tc.out); got != tc.wrong {
			t.Errorf("expect %q, got %v/%v: wrong=%v, want %v", tc.expect, tc.out.GetAction(), tc.out.GetReason(), got, tc.wrong)
		}
	}
}

func TestDefaultCorpusVerdicts(t *testing.T) {
	// The corpus's expectations must hold, or every bench run fails.
	check, err := newChecker(config{timeout: 10 * time.Second, maxBodyBytes: 64 << 10, paranoiaLevel: 1, threshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range defaultCorpus() {
		out, err := check(e.req)
		if err != nil {
			t.Fatal(err)
		}
		if wrongVerdict(e.expect, out) {
			t.Errorf("%s: got %v/%v, want %s", e.class, out.GetAction(), out.GetReason(), e.expect)
		}
	}
}

func TestRunBench(t *testing.T) {
	code, out, errOut := runCLI(t, "bench", "--duration", "300ms", "--warmup", "0", "--concurrency", "2", "--json", "--timeout", "10s")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var rep benchReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, out)
	}
	if rep.Total.Requests == 0 || rep.RPS <= 0 || rep.Cores != 2 || rep.Total.P50 <= 0 || rep.Total.P50 > rep.Total.P99 {
		t.Fatalf("implausible report: %+v", rep)
	}
	if len(rep.Classes) == 0 || rep.Classes[0].Class != "benign-get" {
		t.Fatalf("classes: %+v", rep.Classes)
	}

	// Open loop: about rate * duration requests, no more.
	code, out, errOut = runCLI(t, "bench", "--duration", "500ms", "--warmup", "0", "--rate", "40", "--json", "--timeout", "10s")
	if code != 0 {
		t.Fatalf("--rate: exit %d: %s", code, errOut)
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Total.Requests < 15 || rep.Total.Requests > 21 || rep.Rate != 40 {
		t.Fatalf("--rate 40 for 0.5s sent %d requests", rep.Total.Requests)
	}
}

func TestRunBenchUserCorpusAndEngine(t *testing.T) {
	srv := httptest.NewServer(engineHandler(t))
	t.Cleanup(srv.Close)
	code, out, errOut := runCLI(t, "bench", "--engine", srv.URL, "--duration", "300ms", "--warmup", "0",
		"--concurrency", "2", "http://shop.example.com/products?id=7")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "target "+srv.URL) || !strings.Contains(out, "1 GET /products?id=7") || strings.Contains(out, "per core") {
		t.Fatalf("report:\n%s", out)
	}
}

func TestRunBenchFailures(t *testing.T) {
	for _, args := range [][]string{
		{"bench", "--duration", "0"},
		{"bench", "--concurrency", "0"},
		{"bench", "--rate", "-1"},
		{"bench", "--warmup", "-1s"},
		{"bench", "--engine", "http://127.0.0.1:1", "--duration", "100ms"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	// Overload makes the numbers invalid: exit 1, not a report that passes.
	code, _, errOut := runCLI(t, "bench", "--duration", "300ms", "--warmup", "0", "--concurrency", "200")
	if code != 1 || !strings.Contains(errOut, "not valid") {
		t.Fatalf("overloaded run: exit %d, %q", code, errOut)
	}
}
