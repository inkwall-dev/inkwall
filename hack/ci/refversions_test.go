// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// git runs git in dir and returns its trimmed output.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files (path: content) in dir's repository and commits them.
func commit(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for p, c := range files {
		p = filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "c")
	return git(t, dir, "rev-parse", "HEAD")
}

// The versions a release branch is qualified with (#618): its
// hack/versions.env from 0.5 on; before it, the Helm version its own CI
// workflow pinned; neither is an error, never an empty version.
func TestRefVersions(t *testing.T) {
	script, err := filepath.Abs("ref-versions.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	none := commit(t, dir, map[string]string{"Makefile": "all:\n"})
	old := commit(t, dir, map[string]string{".github/workflows/ci.yaml": `jobs:
  helm:
    steps:
      - uses: actions/checkout@v7
      - uses: azure/setup-helm@v5
        with:
          version: v3.18.4
      - run: make helm-lint
  e2e:
    steps:
      - uses: azure/setup-helm@v5
        with:
          version: v3.18.4
`})
	current := commit(t, dir, map[string]string{"hack/versions.env": "# comment\nKIND_VERSION=v0.1.0\nHELM_VERSION=v3.20.1\n\n"})

	run := func(c string) (string, string, error) {
		cmd := exec.Command(script, c)
		cmd.Dir = dir
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}
	out, _, err := run(current)
	if err != nil || out != "KIND_VERSION=v0.1.0\nHELM_VERSION=v3.20.1\n" {
		t.Errorf("with hack/versions.env: %q, %v", out, err)
	}
	out, stderr, err := run(old)
	if err != nil || out != "HELM_VERSION=v3.18.4\n" || !strings.Contains(stderr, "no hack/versions.env") {
		t.Errorf("before hack/versions.env: %q (stderr %q), %v", out, stderr, err)
	}
	if out, _, err := run(none); err == nil || out != "" {
		t.Errorf("no version anywhere: %q, %v; want an error and nothing", out, err)
	}
	if out, _, err := run("no-such-ref"); err == nil || out != "" {
		t.Errorf("no such ref: %q, %v; want an error and nothing", out, err)
	}
}
