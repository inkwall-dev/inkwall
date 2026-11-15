// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package kind tests the kind scripts' logic that runs without a cluster.
package kind

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// container is one container's status at a sample, the times in seconds.
type container struct {
	name               string
	restarts           int
	runningSince       int64 // 0: waiting (in back-off)
	lastStart, lastEnd int64 // the run the last restart ended; 0: none
}

func status(c container) map[string]any {
	ts := func(s int64) string { return time.Unix(s, 0).UTC().Format(time.RFC3339) }
	st := map[string]any{"name": c.name, "restartCount": c.restarts, "state": map[string]any{}}
	if c.runningSince > 0 {
		st["state"] = map[string]any{"running": map[string]any{"startedAt": ts(c.runningSince)}}
	} else {
		st["state"] = map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}}
	}
	if c.lastEnd > 0 {
		st["lastState"] = map[string]any{"terminated": map[string]any{
			"startedAt": ts(c.lastStart), "finishedAt": ts(c.lastEnd), "exitCode": 1}}
	}
	return st
}

// The soak's restart classification (hack/kind/soak-restarts.sh) with the
// timings of the v0.6.0 soak's apiserver scenario (#627): the operator's
// restarts while the API server was down show only after the window closed
// (the kubelet reports them late), one more comes out of CrashLoopBackOff
// minutes later, and one comes from a run that started after the chaos but
// lasted less than the grace period: all the scenario's. A restart of a
// container the chaos didn't touch, and one after the operator had run for
// longer than the grace period, are violations.
func TestSoakRestartsDuringChaos(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	const grace = 60
	app := container{name: "app", runningSince: 900}
	operator := container{name: "operator", runningSince: 900}
	steps := []struct {
		at      int64
		call    string
		op, app container
	}{
		{1000, "sample_restarts baseline", operator, app},
		{1100, "chaos_begin apiserver 'stopped for 20 s'", operator, app},
		// The API server answers again; the kubelet hasn't reported yet.
		{1130, "chaos_stop", operator, app},
		{1192, "sample_restarts", container{"operator", 7, 0, 1110, 1125}, app},
		{1314, "sample_restarts", container{"operator", 8, 1310, 1110, 1125}, app},
		{1340, "sample_restarts", container{"operator", 9, 1338, 1310, 1335}, app},
		{1400, "sample_restarts", container{"operator", 9, 1338, 1310, 1335}, container{"app", 1, 1398, 900, 1395}},
		{1505, "sample_restarts", container{"operator", 10, 1503, 1338, 1500}, container{"app", 1, 1398, 900, 1395}},
	}

	dir := t.TempDir()
	script := []string{
		"set -euo pipefail",
		fmt.Sprintf("OUT=%q work=%q grace=%d", dir, dir, grace),
		"watched=(inkwall-system)",
		". ./soak-restarts.sh",
		"fake_now=0",
		`soak_now() { echo "$fake_now"; }`,
		`fake_kubectl() { cat "$work/pods-$fake_now.json"; }`,
		"KUBECTL=(fake_kubectl)",
		`: >"$OUT/violations.jsonl"`,
		`: >"$OUT/samples.jsonl"`,
	}
	for _, s := range steps {
		pods := map[string]any{"items": []any{
			map[string]any{
				"metadata": map[string]any{"namespace": "inkwall-system", "name": "op"},
				"status":   map[string]any{"containerStatuses": []any{status(s.op)}},
			},
			map[string]any{
				"metadata": map[string]any{"namespace": "inkwall-system", "name": "app"},
				"status":   map[string]any{"containerStatuses": []any{status(s.app)}},
			},
		}}
		b, err := json.Marshal(pods)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("pods-%d.json", s.at)), b, 0o600); err != nil {
			t.Fatal(err)
		}
		script = append(script, fmt.Sprintf("fake_now=%d", s.at), s.call)
	}
	cmd := exec.Command("bash", "-c", strings.Join(script, "\n"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}

	type record struct {
		Time        int64
		Kind        string
		Message     string
		Restart     string
		DuringChaos bool
		Scenario    string
	}
	read := func(name string) []record {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var rs []record
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var r record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("%s: %v: %s", name, err, sc.Text())
			}
			rs = append(rs, r)
		}
		return rs
	}

	var got []string
	for _, v := range read("violations.jsonl") {
		got = append(got, fmt.Sprintf("%d %s: %s", v.Time, v.Kind, v.Message))
	}
	want := []string{
		"1400 restart: inkwall-system/app/app restarted 1 time(s)",
		"1505 restart: inkwall-system/op/operator restarted 1 time(s)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	got = nil
	for _, r := range read("samples.jsonl") {
		if r.DuringChaos {
			got = append(got, fmt.Sprintf("%d %s %s", r.Time, r.Restart, r.Scenario))
		}
	}
	want = []string{
		"1192 inkwall-system/op/operator apiserver",
		"1314 inkwall-system/op/operator apiserver",
		"1340 inkwall-system/op/operator apiserver",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("restarts counted as chaos's:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
