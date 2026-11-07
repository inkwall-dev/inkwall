// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package ci tests the scripts the CI workflows run (#397).
package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The fuzz matrix is every Fuzz function of the repository's tests.
func TestFuzzTargets(t *testing.T) {
	out, err := exec.Command("./fuzz-targets.sh").Output()
	if err != nil {
		t.Fatal(err)
	}
	var targets []struct{ Package, Target, Name string }
	if err := json.Unmarshal(out, &targets); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := map[string]bool{}
	re := regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]*)\(`)
	err = filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			want["./"+filepath.ToSlash(filepath.Dir(strings.TrimPrefix(p, "../../")))+" "+m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.Package+" "+tg.Target] = true
		if tg.Name != strings.TrimPrefix(tg.Package, "./")+" "+tg.Target {
			t.Errorf("name %q for %s %s", tg.Name, tg.Package, tg.Target)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("%s is not in the matrix", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s is in the matrix but not a Fuzz function", k)
		}
	}
	if len(targets) < 20 {
		t.Errorf("%d targets: the search is broken", len(targets))
	}
}

// fakeGH puts a gh on PATH that logs its arguments and answers
// `gh issue list` with list.
func fakeGH(t *testing.T, list string) (env []string, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	script := `#!/usr/bin/env bash
echo "$*" >>"` + log + `"
case "$1 $2" in
"issue list") echo "` + list + `" ;;
"issue create") echo "https://github.com/o/r/issues/9" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH")), log
}

func report(t *testing.T, list string, args ...string) string {
	t.Helper()
	env, log := fakeGH(t, list)
	cmd := exec.Command("./report-scheduled.sh", args...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	b, _ := os.ReadFile(log)
	return string(b)
}

// A failure opens a pinned issue, or comments on the open one; a pass
// closes it; a cancelled run changes nothing.
func TestReportScheduled(t *testing.T) {
	calls := report(t, "", "fuzz", "failure", "https://run/1", "Failing targets: pkg/x FuzzY")
	for _, want := range []string{"issue create --title Scheduled workflow failing: fuzz --label ci-scheduled-failure", "Failing targets: pkg/x FuzzY", "issue pin https://github.com/o/r/issues/9"} {
		if !strings.Contains(calls, want) {
			t.Errorf("new failure: no %q in\n%s", want, calls)
		}
	}
	calls = report(t, "7", "fuzz", "failure", "https://run/2")
	if !strings.Contains(calls, "issue comment 7 --body The scheduled run failed: https://run/2") || strings.Contains(calls, "issue create") {
		t.Errorf("repeated failure:\n%s", calls)
	}
	calls = report(t, "7", "fuzz", "success", "https://run/3")
	if !strings.Contains(calls, "issue close 7 --comment The scheduled run passes again: https://run/3") {
		t.Errorf("passing again:\n%s", calls)
	}
	calls = report(t, "", "fuzz", "success", "https://run/4")
	if strings.Contains(calls, "close") || strings.Contains(calls, "create") {
		t.Errorf("passing, no issue:\n%s", calls)
	}
	calls = report(t, "7", "fuzz", "cancelled", "https://run/5")
	if strings.Contains(calls, "comment") || strings.Contains(calls, "close") {
		t.Errorf("cancelled:\n%s", calls)
	}
}
