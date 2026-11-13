// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func TestImageVersion(t *testing.T) {
	for image, want := range map[string]string{
		"ghcr.io/inkwall-dev/inkwall-engine:0.4.1":                   "0.4.1",
		"ghcr.io/inkwall-dev/inkwall-engine:v0.5.0":                  "0.5.0",
		"ghcr.io/inkwall-dev/inkwall-engine:0.6.0-rc.1":              "0.6.0",
		"ghcr.io/inkwall-dev/inkwall-engine:0.5.0@sha256:0123abcdef": "0.5.0",
		"registry.local:5000/inkwall-engine:0.4.0":                   "0.4.0",
		// Not a release: unknown.
		"registry.local:5000/inkwall-engine":                "",
		"ghcr.io/inkwall-dev/inkwall-engine@sha256:0123abc": "",
		"ghcr.io/inkwall-dev/inkwall-engine:latest":         "",
		"inkwall-engine:dev":                                "",
		"inkwall-engine:0.5":                                "",
		"inkwall-engine:sha-0123abc":                        "",
	} {
		v, ok := ImageVersion(image)
		got := ""
		if ok {
			got = v.String()
		}
		if got != want {
			t.Errorf("ImageVersion(%q) = %q, want %q", image, got, want)
		}
	}
}

// An engine pinned in spec.engine.image gets only the flags its release
// knows: an older engine exits on an unknown flag, so its pod would never
// be ready (#536). A tag that isn't a release gets only the flags every
// release knows; the operator's own engine gets them all.
func TestPinnedEngineFlags(t *testing.T) {
	hops := int32(2)
	settings := wafv1alpha1.EngineSpec{
		LogLevel: wafv1alpha1.LogLevelDebug, PolicyMetrics: true, JSONDenials: true,
		BootstrapMode: wafv1alpha1.BootstrapDenyAll,
		ClientIP:      &wafv1alpha1.ClientIPSpec{TrustedProxies: []wafv1alpha1.CIDR{"10.0.0.0/8"}, TrustedHops: &hops},
	}
	newer := []string{"--log-level=debug", "--policy-metrics", "--json-denials", "--trusted-hops=2"}
	allSettings := []string{"spec.engine.clientIP.trustedHops", "spec.engine.logLevel", "spec.engine.policyMetrics", "spec.engine.jsonDenials"}
	// Flags every release takes, pinned or not.
	always := []string{"--bootstrap=deny", "--bundle-secret=inkwall-system/inkwall-bundle",
		"--trusted-proxies=127.0.0.1/32,::1/128,10.0.0.0/8"}
	for _, tc := range []struct {
		image   string
		all     bool
		leftOut []string
	}{
		{image: "", all: true},
		{image: "ghcr.io/inkwall-dev/inkwall-engine:0.5.0", all: true},
		{image: "ghcr.io/inkwall-dev/inkwall-engine:0.6.0-rc.1@sha256:0123abc", all: true},
		{image: "ghcr.io/inkwall-dev/inkwall-engine:0.4.1", leftOut: allSettings},
		{image: "ghcr.io/inkwall-dev/inkwall-engine:0.3.3", leftOut: allSettings},
		{image: "registry.local:5000/inkwall-engine:custom", leftOut: allSettings},
		{image: "ghcr.io/inkwall-dev/inkwall-engine@sha256:0123abc", leftOut: allSettings},
	} {
		e := settings
		e.Image = tc.image
		s := sidecar.Configured(e)
		engine, _ := Engine(s)
		for _, f := range always {
			if !slices.Contains(engine.Args, f) {
				t.Errorf("%q: %s missing from %v", tc.image, f, engine.Args)
			}
		}
		for _, f := range newer {
			if got := slices.Contains(engine.Args, f); got != tc.all {
				t.Errorf("%q: %s passed: %v, want %v", tc.image, f, got, tc.all)
			}
		}
		if got := s.LeftOut(); !slices.Equal(got, tc.leftOut) {
			t.Errorf("%q: LeftOut() = %v, want %v", tc.image, got, tc.leftOut)
		}
	}

	// Settings left unset are not reported left out.
	s := sidecar.Configured(wafv1alpha1.EngineSpec{Image: "ghcr.io/inkwall-dev/inkwall-engine:0.4.1", JSONDenials: true})
	if got := s.LeftOut(); !slices.Equal(got, []string{"spec.engine.jsonDenials"}) {
		t.Errorf("LeftOut() = %v, want only spec.engine.jsonDenials", got)
	}
}

// EngineConfigured says which settings the engine is injected without, and
// why.
func TestEngineConfiguredCondition(t *testing.T) {
	for _, tc := range []struct {
		name   string
		e      wafv1alpha1.EngineSpec
		ok     bool
		reason string
		says   []string
	}{
		{name: "operator's engine", e: wafv1alpha1.EngineSpec{JSONDenials: true}, ok: true, reason: ReasonEngineConfigured},
		{name: "pinned, new enough", e: wafv1alpha1.EngineSpec{Image: "x/inkwall-engine:0.5.0", LogLevel: wafv1alpha1.LogLevelWarn}, ok: true, reason: ReasonEngineConfigured},
		{name: "pinned, nothing newer set", e: wafv1alpha1.EngineSpec{Image: "x/inkwall-engine:0.4.1"}, ok: true, reason: ReasonEngineConfigured},
		{name: "pinned, too old", e: wafv1alpha1.EngineSpec{Image: "x/inkwall-engine:0.4.1", JSONDenials: true, LogLevel: wafv1alpha1.LogLevelWarn},
			reason: ReasonEngineTooOld, says: []string{"x/inkwall-engine:0.4.1", "0.4.1", "spec.engine.logLevel", "spec.engine.jsonDenials", "0.5.0"}},
		{name: "pinned, unknown", e: wafv1alpha1.EngineSpec{Image: "x/inkwall-engine:custom", PolicyMetrics: true},
			reason: ReasonEngineVersionUnknown, says: []string{"x/inkwall-engine:custom", "spec.engine.policyMetrics"}},
	} {
		c := EngineConfiguredCondition(tc.e, 7)
		if c.Type != wafv1alpha1.ConditionEngineConfigured || (c.Status == "True") != tc.ok || c.Reason != tc.reason || c.ObservedGeneration != 7 {
			t.Errorf("%s: %+v, want ok %v reason %s", tc.name, c, tc.ok, tc.reason)
		}
		for _, w := range tc.says {
			if !strings.Contains(c.Message, w) {
				t.Errorf("%s: message %q doesn't say %q", tc.name, c.Message, w)
			}
		}
	}
}
