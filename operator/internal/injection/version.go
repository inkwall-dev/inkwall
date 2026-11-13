// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Version is an engine release, MAJOR.MINOR.PATCH.
type Version [3]int

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// ImageVersion returns the release an engine image runs, read from its
// tag: "ghcr.io/inkwall-dev/inkwall-engine:0.4.1", with or without a
// leading "v", a pre-release suffix or a digest after it. False when the
// tag isn't a release (latest, a branch, a digest alone): a custom build.
func ImageVersion(image string) (Version, bool) {
	var v Version
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	i := strings.LastIndexByte(image, ':')
	if i < 0 || strings.Contains(image[i:], "/") {
		return v, false // No tag; the colon is a registry's port.
	}
	tag := strings.TrimPrefix(image[i+1:], "v")
	if j := strings.IndexAny(tag, "-+"); j >= 0 {
		tag = tag[:j]
	}
	parts := strings.Split(tag, ".")
	if len(parts) != 3 {
		return v, false
	}
	for k, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[k] = n
	}
	return v, true
}

// option is an InkwallConfig setting injected as a flag that not every
// engine release knows: an engine exits on a flag it doesn't know, so its
// proxy pod would never be ready (#536).
type option struct {
	setting string
	since   Version
	set     func(Sidecar) bool
}

// The options, in the order Engine passes them.
var (
	optTrustedHops   = option{"spec.engine.clientIP.trustedHops", Version{0, 5, 0}, func(s Sidecar) bool { return s.TrustedHops > 0 }}
	optLogLevel      = option{"spec.engine.logLevel", Version{0, 5, 0}, func(s Sidecar) bool { return s.LogLevel != "" }}
	optPolicyMetrics = option{"spec.engine.policyMetrics", Version{0, 5, 0}, func(s Sidecar) bool { return s.PolicyMetrics }}
	optJSONDenials   = option{"spec.engine.jsonDenials", Version{0, 5, 0}, func(s Sidecar) bool { return s.JSONDenials }}
	options          = []option{optTrustedHops, optLogLevel, optPolicyMetrics, optJSONDenials}
)

// passes reports whether Engine passes o: s sets it, and s's engine knows
// it. The operator's own engine knows every flag; an engine pinned in
// spec.engine.image those of its release, and only those every release
// knows when its tag isn't one.
func (s Sidecar) passes(o option) bool {
	if !o.set(s) {
		return false
	}
	if !s.Pinned {
		return true
	}
	v, ok := ImageVersion(s.Image)
	return ok && slices.Compare(v[:], o.since[:]) >= 0
}

// LeftOut returns the settings s sets that its engine is injected without,
// because its release (or a custom build) may not know their flags.
func (s Sidecar) LeftOut() []string {
	var out []string
	for _, o := range options {
		if o.set(s) && !s.passes(o) {
			out = append(out, o.setting)
		}
	}
	return out
}

// Reasons of the InkwallConfig's EngineConfigured condition.
const (
	ReasonEngineConfigured = "Configured"
	// ReasonEngineTooOld: the engine pinned in spec.engine.image is a
	// release too old for some settings, which it is injected without.
	ReasonEngineTooOld = "EngineTooOld"
	// ReasonEngineVersionUnknown: the pinned engine's tag isn't a
	// release, so it is injected without the settings some releases
	// don't know.
	ReasonEngineVersionUnknown = "EngineVersionUnknown"
)

// EngineConfiguredCondition says whether the engine is injected with every
// spec.engine setting e sets: False, naming those left out and why, when
// spec.engine.image pins an engine that may not know them.
func EngineConfiguredCondition(e wafv1alpha1.EngineSpec, generation int64) metav1.Condition {
	c := metav1.Condition{Type: wafv1alpha1.ConditionEngineConfigured, Status: metav1.ConditionTrue,
		Reason: ReasonEngineConfigured, ObservedGeneration: generation,
		Message: "the engine is injected with every spec.engine setting"}
	s := Sidecar{}.Configured(e)
	leftOut := s.LeftOut()
	if len(leftOut) == 0 {
		return c
	}
	c.Status = metav1.ConditionFalse
	var need Version
	for _, o := range options {
		if slices.Contains(leftOut, o.setting) && slices.Compare(o.since[:], need[:]) > 0 {
			need = o.since
		}
	}
	list := strings.Join(leftOut, ", ")
	if v, ok := ImageVersion(s.Image); ok {
		c.Reason = ReasonEngineTooOld
		c.Message = fmt.Sprintf("engine image %s runs %s, which doesn't know %s (%s or later): the engine is injected without them, so it starts; pin %s or later to apply them",
			s.Image, v, list, need, need)
		return c
	}
	c.Reason = ReasonEngineVersionUnknown
	c.Message = fmt.Sprintf("the tag of engine image %s isn't a release version, so the engine is injected without %s, which an engine before %s doesn't know; tag the image with its version (such as :%s, optionally with @sha256:...) to apply them",
		s.Image, list, need, need)
	return c
}
