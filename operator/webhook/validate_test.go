// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func wantInvalid(t *testing.T, err error, field, detail string) {
	t.Helper()
	if !apierrors.IsInvalid(err) {
		t.Fatalf("got %v, want an Invalid error", err)
	}
	if !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), detail) {
		t.Fatalf("error %q does not name %s with %q", err, field, detail)
	}
}

func TestRuleSetValidation(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFRuleSet]{validate: validateWAFRuleSet}
	rs := func(src wafv1alpha1.RuleSetSource) *wafv1alpha1.WAFRuleSet {
		return &wafv1alpha1.WAFRuleSet{ObjectMeta: metav1.ObjectMeta{Name: "rules"}, Spec: wafv1alpha1.WAFRuleSetSpec{Source: src}}
	}

	if _, err := v.ValidateCreate(ctx, rs(wafv1alpha1.RuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4})); err != nil {
		t.Errorf("builtin: %v", err)
	}
	_, err := v.ValidateCreate(ctx, rs(wafv1alpha1.RuleSetSource{SecLang: "\n\nSecRule ARGS \"@nosuchop a\" \"id:100001,phase:1,deny\""}))
	wantInvalid(t, err, "spec.source.seclang", "line 3: ")
	if strings.Contains(err.Error(), "nosuchop a") {
		t.Errorf("error echoes the rules: %q", err)
	}

	// An update that leaves the spec alone is accepted even when the spec
	// no longer compiles, so objects stay editable and deletable.
	broken := rs(wafv1alpha1.RuleSetSource{SecLang: "SecRuleEngine Off"})
	relabeled := broken.DeepCopy()
	relabeled.Labels = map[string]string{"a": "b"}
	if _, err := v.ValidateUpdate(ctx, broken, relabeled); err != nil {
		t.Errorf("metadata-only update: %v", err)
	}
	changed := broken.DeepCopy()
	changed.Spec.Source.SecLang = "SecRuleEngine DetectionOnly"
	_, err = v.ValidateUpdate(ctx, broken, changed)
	wantInvalid(t, err, "spec.source.seclang", `directive "secruleengine" is not allowed`)

	warnings, err := v.ValidateCreate(ctx, rs(wafv1alpha1.RuleSetSource{ConfigMapRef: &wafv1alpha1.ConfigMapKeyRef{Name: "r", Key: "k"}}))
	if err != nil || len(warnings) != 1 {
		t.Errorf("ConfigMap rules: warnings %q, error %v", warnings, err)
	}
}

func TestClusterRuleSetValidation(t *testing.T) {
	v := specValidator[*wafv1alpha1.ClusterWAFRuleSet]{validate: validateClusterWAFRuleSet}
	_, err := v.ValidateCreate(context.Background(), &wafv1alpha1.ClusterWAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rules"},
		Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{SecLang: "SecDebugLog /tmp/debug.log"}},
	})
	wantInvalid(t, err, "spec.source.seclang", `directive "secdebuglog" is not allowed`)
}

func TestPolicyValidation(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy}
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shop"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "shop"}},
			Skip: &wafv1alpha1.SkipSpec{
				Paths:     []wafv1alpha1.PathPattern{"/healthz", "/static/*"},
				BodyPaths: []wafv1alpha1.PathPattern{"/upload"},
			},
			Exclusions: []wafv1alpha1.Exclusion{{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Path: "/search", Argument: "q"}}},
		},
	}
	if _, err := v.ValidateCreate(ctx, p); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*wafv1alpha1.WAFPolicy)
		field string
	}{
		{"dot segment", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Skip.Paths[1] = "/static/./x" }, "spec.skip.paths[1]"},
		{"double slash", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Skip.BodyPaths[0] = "//upload" }, "spec.skip.bodyPaths[0]"},
		{"dot-dot in an exclusion", func(p *wafv1alpha1.WAFPolicy) { p.Spec.Exclusions[0].When.Path = "/a/../search" }, "spec.exclusions[0].when.path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := p.DeepCopy()
			tc.edit(q)
			_, err := v.ValidateCreate(ctx, q)
			wantInvalid(t, err, tc.field, "not clean")
		})
	}
	// WebSocket rules the engine wouldn't compile: the CRD schema rejects
	// these too, but an engine refusing one entry refuses the whole bundle.
	ws := p.DeepCopy()
	ws.Spec.WebSocket = &wafv1alpha1.WebSocketSpec{
		AllowedOrigins:  []wafv1alpha1.WebSocketOrigin{"https://app.example.com", "https://*.example.net"},
		RequiredHeaders: []wafv1alpha1.HeaderName{"Authorization"},
	}
	if _, err := v.ValidateCreate(ctx, ws); err != nil {
		t.Fatalf("valid webSocket: %v", err)
	}
	ws.Spec.WebSocket.AllowedOrigins[1] = "wss://app.example.com"
	_, err := v.ValidateCreate(ctx, ws)
	wantInvalid(t, err, "spec.webSocket.allowedOrigins[1]", "not http or https")
	ws.Spec.WebSocket.AllowedOrigins[1] = "https://a.example"
	ws.Spec.WebSocket.RequiredHeaders[0] = "X Api"
	_, err = v.ValidateCreate(ctx, ws)
	wantInvalid(t, err, "spec.webSocket.requiredHeaders[0]", "not a header name")
}

// A policy that inspects responses gets a warning for its Ingress and
// IngressRoute targets: Traefik serves them, and can't send responses to the
// engine. It is accepted: its requests are inspected, and its status says
// the responses are not.
func TestPolicyResponsesWarning(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy}
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shop"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{
				{Kind: "Ingress", Name: "web"},
				{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "api"},
				{Group: "traefik.io", Kind: "IngressRoute", Name: "admin"},
			},
			Responses: &wafv1alpha1.ResponsesSpec{Inspect: true},
		},
	}
	warnings, err := v.ValidateCreate(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "spec.responses: Ingress web and IngressRoute admin are served by Traefik") {
		t.Errorf("warnings %q", warnings)
	}
	p.Spec.TargetRefs = p.Spec.TargetRefs[1:2]
	if warnings, _ := v.ValidateCreate(ctx, p); len(warnings) != 0 {
		t.Errorf("HTTPRoute only: warnings %q", warnings)
	}
	p.Spec.TargetRefs = []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}
	p.Spec.Responses.Inspect = false
	if warnings, _ := v.ValidateCreate(ctx, p); len(warnings) != 0 {
		t.Errorf("responses off: warnings %q", warnings)
	}
}

func TestConfigValidation(t *testing.T) {
	ctx := context.Background()
	v := configValidator{}
	cfg := func(socketDir string) *wafv1alpha1.InkwallConfig {
		return &wafv1alpha1.InkwallConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       wafv1alpha1.InkwallConfigSpec{Engine: wafv1alpha1.EngineSpec{SocketDir: socketDir}}, //nolint:staticcheck // the deprecated field
		}
	}

	if warnings, err := v.ValidateCreate(ctx, cfg("")); err != nil || len(warnings) != 0 {
		t.Errorf("no socketDir: warnings %q, error %v", warnings, err)
	}
	if warnings, err := v.ValidateCreate(ctx, cfg("/run/x")); err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "socketDir") {
		t.Errorf("socketDir set: warnings %q, error %v", warnings, err)
	}
	if warnings, err := v.ValidateUpdate(ctx, cfg(""), cfg("/run/x")); err != nil || len(warnings) != 1 {
		t.Errorf("socketDir added: warnings %q, error %v", warnings, err)
	}
	// The old default, kept by an update, doesn't warn on every apply.
	if warnings, err := v.ValidateUpdate(ctx, cfg("/var/run/inkwall"), cfg("/var/run/inkwall")); err != nil || len(warnings) != 0 {
		t.Errorf("socketDir kept: warnings %q, error %v", warnings, err)
	}
}
