// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

type fake struct{}

func (fake) githubRelease(repo string) (string, error) {
	return map[string]string{"envoyproxy/gateway": "v1.10.0", "istio/istio": "1.31.3"}[repo], nil
}

func (fake) helmChart(_, chart string) (string, string, error) { return "42.0.1", "v3.8.0", nil }

func (fake) dockerTag(image, prefix string) (string, error) { return prefix + ".30", nil }

const file = `# A comment.
# source: github-release envoyproxy/gateway
ENVOY_GATEWAY_VERSION=v1.9.3
# source: github-release istio/istio
ISTIO_VERSION=1.31.3
# source: helm-chart https://traefik.github.io/charts traefik TRAEFIK_VERSION
TRAEFIK_CHART_VERSION=41.6.1
TRAEFIK_VERSION=v3.7.13
# source: docker-tag haproxy 3.2
HAPROXY_VERSION=3.2.26
HELM_VERSION=v3.19.0
`

// Each entry with a source gets its latest version; a helm chart also its
// app's; the others stay (#393).
func TestBump(t *testing.T) {
	entries := parse(file)
	if len(entries) != 6 || entries[5].src != nil || entries[0].src.kind != "github-release" {
		t.Fatalf("entries %+v", entries)
	}
	got, err := bumps(entries, fake{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ENVOY_GATEWAY_VERSION": "v1.10.0", "ISTIO_VERSION": "1.31.3", "TRAEFIK_CHART_VERSION": "42.0.1",
		"TRAEFIK_VERSION": "v3.8.0", "HAPROXY_VERSION": "3.2.30"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bumps %v, want %v", got, want)
	}
	out := apply(file, got)
	for _, e := range parse(out) {
		if w, ok := want[e.key]; ok && e.value != w || !ok && e.value != "v3.19.0" {
			t.Errorf("%s=%s after apply", e.key, e.value)
		}
	}
}

// Only the marked paragraphs change, with or without the "v".
func TestApplyDoc(t *testing.T) {
	doc := "Envoy Gateway v1.9.3 elsewhere.\n\n" +
		"<!-- versions: ENVOY_GATEWAY_VERSION -->\n" +
		"helm install eg --version v1.9.3\nTested with Envoy Gateway 1.9.3, not 11.9.3.\n\n" +
		"After: v1.9.3.\n"
	got := applyDoc(doc, map[string][2]string{"ENVOY_GATEWAY_VERSION": {"v1.9.3", "v1.10.0"}})
	want := "Envoy Gateway v1.9.3 elsewhere.\n\n" +
		"<!-- versions: ENVOY_GATEWAY_VERSION -->\n" +
		"helm install eg --version v1.10.0\nTested with Envoy Gateway 1.10.0, not 11.9.3.\n\n" +
		"After: v1.9.3.\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestLess(t *testing.T) {
	for _, c := range [][2]string{{"1.9.3", "1.10.0"}, {"v3.2.9", "v3.2.26"}, {"41.6.1", "42"}} {
		if !less(c[0], c[1]) || less(c[1], c[0]) {
			t.Errorf("less(%s, %s)", c[0], c[1])
		}
	}
}
