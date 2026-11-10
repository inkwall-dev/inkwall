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
