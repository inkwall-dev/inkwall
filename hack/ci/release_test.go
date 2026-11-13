// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/yaml"
)

type releaseStep struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	If              string            `json:"if"`
	Uses            string            `json:"uses"`
	Run             string            `json:"run"`
	With            map[string]string `json:"with"`
	ContinueOnError bool              `json:"continue-on-error"`
}

type releaseWorkflow struct {
	Jobs map[string]struct {
		Steps []releaseStep `json:"steps"`
	} `json:"jobs"`
}

func readRelease(t *testing.T) releaseWorkflow {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

var publishRun = regexp.MustCompile(`\b(helm push|goreleaser release|gh release (upload|create)|cosign sign|cosign attest|docker push)\b`)

func publishes(s releaseStep) bool {
	return publishRun.MatchString(s.Run) ||
		strings.HasPrefix(s.Uses, "docker/build-push-action@") && s.With["push"] == "true" ||
		strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") && s.With["install-only"] != "true"
}

// A release job installs every tool it needs before it publishes anything
// (#541): on v0.5.0-rc.1 the cosign download failed after the images were
// pushed, and left an unsigned image on GHCR.
func TestReleaseInstallsToolsBeforePublishing(t *testing.T) {
	wf := readRelease(t)
	installers := []string{
		"sigstore/cosign-installer@",
		"azure/setup-helm@",
		"anchore/sbom-action/download-syft@",
		"goreleaser/goreleaser-action@",
		"docker/setup-buildx-action@",
	}
	publishers := 0
	for name, job := range wf.Jobs {
		firstPublish, lastInstall := -1, -1
		for i, s := range job.Steps {
			installs := false
			for _, p := range installers {
				if strings.HasPrefix(s.Uses, p) {
					installs = true
				}
			}
			if installs {
				lastInstall = i
			}
			if publishes(s) && firstPublish < 0 {
				firstPublish = i
			}
		}
		if firstPublish < 0 {
			continue
		}
		publishers++
		if lastInstall >= firstPublish {
			t.Errorf("release.yaml job %s installs a tool in step %d, at or after it first publishes (step %d)", name, lastInstall+1, firstPublish+1)
		}
	}
	if publishers < 3 {
		t.Errorf("found %d publishing jobs in release.yaml, want the images, chart and binaries jobs", publishers)
	}
}

// A release job that publishes checks that keyless signing works before it
// publishes anything, retries signing, and says what it left unsigned when
// signing fails anyway (#586): on v0.5.1 cosign failed to fetch the job's
// OIDC token after the chart was pushed, and left it unsigned on GHCR.
func TestReleaseChecksSigningBeforePublishing(t *testing.T) {
	wf := readRelease(t)
	cosignRun := regexp.MustCompile(`\bcosign (sign|attest)\b`)
	publishers := 0
	for name, job := range wf.Jobs {
		firstPublish, check, summary := -1, -1, false
		var attests []releaseStep
		for i, s := range job.Steps {
			if strings.Contains(s.Run, "hack/ci/sigstore.sh check") && check < 0 {
				check = i
			}
			if publishes(s) && firstPublish < 0 {
				firstPublish = i
			}
			for _, line := range strings.Split(s.Run, "\n") {
				if cosignRun.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "hack/ci/sigstore.sh retry cosign ") {
					t.Errorf("release.yaml job %s signs without retrying: %q", name, strings.TrimSpace(line))
				}
			}
			if strings.HasPrefix(s.Uses, "actions/attest-build-provenance@") {
				attests = append(attests, s)
			}
			if strings.Contains(s.If, "failure()") && strings.Contains(s.Run, "GITHUB_STEP_SUMMARY") && strings.Contains(s.Run, "::error::") {
				summary = true
			}
		}
		if firstPublish < 0 {
			continue
		}
		publishers++
		if check < 0 || check > firstPublish {
			t.Errorf("release.yaml job %s doesn't check that signing works (hack/ci/sigstore.sh check) before it first publishes (step %d)", name, firstPublish+1)
		}
		if !summary {
			t.Errorf("release.yaml job %s has no step that writes an error to the job summary on failure", name)
		}
		// An action can't be wrapped in a retry: attempts as steps, each
		// but the last allowed to fail.
		if len(attests) == 1 {
			t.Errorf("release.yaml job %s attests once, without a retry", name)
		}
		for i, s := range attests {
			if i < len(attests)-1 && !s.ContinueOnError {
				t.Errorf("release.yaml job %s: attestation attempt %d of %d stops the job on failure", name, i+1, len(attests))
			}
			if i > 0 && !strings.Contains(s.If, attests[i-1].ID+".outcome == 'failure'") {
				t.Errorf("release.yaml job %s: attestation attempt %d doesn't run only after attempt %d failed (if: %q)", name, i+1, i, s.If)
			}
		}
	}
	if publishers < 3 {
		t.Errorf("found %d publishing jobs in release.yaml, want the images, chart and binaries jobs", publishers)
	}
}

// sigstore.sh check fetches the OIDC token for Sigstore, retried, and fails
// when no token comes back; retry runs a command until it passes, a bounded
// number of times.
func TestSigstoreScript(t *testing.T) {
	var calls, bad atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "bearer request-token" || r.URL.Query().Get("audience") != "sigstore" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// GitHub's transient error on v0.5.1: a body that isn't JSON.
		if bad.Add(-1) >= 0 {
			fmt.Fprint(w, "upstream request timeout")
			return
		}
		fmt.Fprint(w, `{"value":"eyJ.token"}`)
	}))
	t.Cleanup(srv.Close)
	run := func(env []string, args ...string) (string, error) {
		cmd := exec.Command("./sigstore.sh", args...)
		cmd.Env = append(os.Environ(), append([]string{"SIGSTORE_DELAY=0"}, env...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	tokenEnv := []string{"ACTIONS_ID_TOKEN_REQUEST_URL=" + srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=request-token"}

	bad.Store(2)
	calls.Store(0)
	if out, err := run(tokenEnv, "check"); err != nil {
		t.Errorf("check after two bad answers: %v: %s", err, out)
	} else if strings.Contains(out, "eyJ.token") {
		t.Errorf("check printed the token: %s", out)
	}
	if calls.Load() != 3 {
		t.Errorf("check made %d requests, want 3", calls.Load())
	}

	bad.Store(100)
	calls.Store(0)
	if out, err := run(tokenEnv, "check"); err == nil {
		t.Errorf("check passed with no token: %s", out)
	}
	if calls.Load() != 5 {
		t.Errorf("check made %d requests, want 5 attempts", calls.Load())
	}

	if out, err := run(nil, "check"); err == nil || !strings.Contains(out, "id-token: write") {
		t.Errorf("check without the token request variables: %v: %s", err, out)
	}

	count := filepath.Join(t.TempDir(), "count")
	failTwice := `echo x >>"` + count + `"; [ "$(wc -l <"` + count + `")" -ge 3 ]`
	if out, err := run(nil, "retry", "sh", "-c", failTwice); err != nil {
		t.Errorf("retry of a command failing twice: %v: %s", err, out)
	}
	if out, err := run([]string{"SIGSTORE_ATTEMPTS=2"}, "retry", "false"); err == nil {
		t.Errorf("retry of a command that always fails passed: %s", out)
	}
	if out, err := run(nil, "retry"); err == nil {
		t.Errorf("retry of nothing passed: %s", out)
	}
}
