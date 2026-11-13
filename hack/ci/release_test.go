// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// A release job installs every tool it needs before it publishes anything
// (#541): on v0.5.0-rc.1 the cosign download failed after the images were
// pushed, and left an unsigned image on GHCR.
func TestReleaseInstallsToolsBeforePublishing(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string            `json:"name"`
				Uses string            `json:"uses"`
				Run  string            `json:"run"`
				With map[string]string `json:"with"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	installers := []string{
		"sigstore/cosign-installer@",
		"azure/setup-helm@",
		"anchore/sbom-action/download-syft@",
		"goreleaser/goreleaser-action@",
		"docker/setup-buildx-action@",
	}
	publishRun := regexp.MustCompile(`\b(helm push|goreleaser release|gh release (upload|create)|cosign sign|cosign attest|docker push)\b`)
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
			publishes := publishRun.MatchString(s.Run) ||
				strings.HasPrefix(s.Uses, "docker/build-push-action@") && s.With["push"] == "true" ||
				strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") && s.With["install-only"] != "true"
			if installs {
				lastInstall = i
			}
			if publishes && firstPublish < 0 {
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

// releaseWorkflow is release.yaml's jobs and steps, as the tests read them.
type releaseWorkflow struct {
	Jobs map[string]struct {
		Permissions map[string]string `json:"permissions"`
		Steps       []releaseStep     `json:"steps"`
	} `json:"jobs"`
}

type releaseStep struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	If              string            `json:"if"`
	Uses            string            `json:"uses"`
	Run             string            `json:"run"`
	With            map[string]string `json:"with"`
	ContinueOnError bool              `json:"continue-on-error"`
}

func readReleaseWorkflow(t *testing.T) releaseWorkflow {
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

// pushes reports whether a step puts an artifact where users get it.
func (s releaseStep) pushes() bool {
	return regexp.MustCompile(`\b(helm push|goreleaser release|gh release (upload|create)|docker push)\b`).MatchString(s.Run) ||
		strings.HasPrefix(s.Uses, "docker/build-push-action@") && s.With["push"] == "true" ||
		strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") && s.With["install-only"] != "true"
}

// signingPreflight reports whether a step checks that keyless signing can
// work: it fetches the workflow's OIDC token for Sigstore.
func (s releaseStep) signingPreflight() bool {
	return strings.Contains(s.Run, "ACTIONS_ID_TOKEN_REQUEST_URL") && strings.Contains(s.Run, "audience=sigstore")
}

// A release job that signs checks that it can sign before it publishes
// anything, retries signing on transient errors, and says loudly when an
// artifact stays unsigned (#586): on v0.5.1 the chart was pushed, then
// cosign couldn't fetch the OIDC token, and the chart stayed unsigned on
// GHCR until a rerun, with only the skipped check job to tell.
func TestReleaseChecksSigningBeforePublishing(t *testing.T) {
	wf := readReleaseWorkflow(t)
	signers := 0
	for name, job := range wf.Jobs {
		if job.Permissions["id-token"] != "write" {
			continue
		}
		firstPush, preflight, summary := -1, -1, false
		for i, s := range job.Steps {
			if s.signingPreflight() && preflight < 0 {
				preflight = i
			}
			if s.pushes() && firstPush < 0 {
				firstPush = i
			}
			if regexp.MustCompile(`\bcosign sign\b`).MatchString(s.Run) && !regexp.MustCompile(`\bretry\b[^\n]*\bcosign sign\b`).MatchString(s.Run) {
				t.Errorf("release.yaml job %s step %d signs without retrying: %q", name, i+1, s.Run)
			}
			if strings.Contains(s.If, "failure()") && strings.Contains(s.Run, "GITHUB_STEP_SUMMARY") && strings.Contains(s.Run, "::error") {
				summary = true
			}
		}
		if firstPush < 0 {
			continue
		}
		signers++
		switch {
		case preflight < 0:
			t.Errorf("release.yaml job %s publishes (step %d) without checking first that it can sign", name, firstPush+1)
		case preflight > firstPush:
			t.Errorf("release.yaml job %s publishes in step %d before it checks that it can sign (step %d)", name, firstPush+1, preflight+1)
		}
		if !summary {
			t.Errorf("release.yaml job %s has no failure() step writing an error to the job summary", name)
		}
	}
	if signers < 3 {
		t.Errorf("found %d jobs that publish and sign, want the images, chart and binaries jobs", signers)
	}
}
