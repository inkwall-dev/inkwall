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

	// CRS settings the engine wouldn't apply.
	crs := p.DeepCopy()
	crs.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{
		Ref:           wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"},
		ParanoiaLevel: ptr(int32(2)),
		CRS: &wafv1alpha1.CRSSettings{
			AllowedMethods:             []wafv1alpha1.HTTPMethodToken{"GET", "PUT", "PROPFIND"},
			AllowedRequestContentTypes: []wafv1alpha1.MediaType{"application/json", "application/vnd.api+json"},
			DetectionParanoiaLevel:     ptr(int32(3)),
			OutboundAnomalyThreshold:   ptr(int32(5)),
		},
	}}
	if _, err := v.ValidateCreate(ctx, crs); err != nil {
		t.Fatalf("valid crs: %v", err)
	}
	for _, tc := range []struct {
		name, field, detail string
		edit                func(*wafv1alpha1.CRSSettings)
	}{
		{"method", "spec.ruleSets[0].crs.allowedMethods[1]", "not an HTTP method", func(s *wafv1alpha1.CRSSettings) { s.AllowedMethods[1] = "P UT" }},
		{"media type", "spec.ruleSets[0].crs.allowedRequestContentTypes[0]", "not a media type", func(s *wafv1alpha1.CRSSettings) { s.AllowedRequestContentTypes[0] = "json" }},
		{"detection below blocking", "spec.ruleSets[0].crs.detectionParanoiaLevel", "paranoia level", func(s *wafv1alpha1.CRSSettings) { s.DetectionParanoiaLevel = ptr(int32(1)) }},
		{"outbound threshold", "spec.ruleSets[0].crs.outboundAnomalyThreshold", "positive", func(s *wafv1alpha1.CRSSettings) { s.OutboundAnomalyThreshold = ptr(int32(0)) }},
	} {
		t.Run("crs "+tc.name, func(t *testing.T) {
			q := crs.DeepCopy()
			tc.edit(q.Spec.RuleSets[0].CRS)
			_, err := v.ValidateCreate(ctx, q)
			wantInvalid(t, err, tc.field, tc.detail)
		})
	}
}

// A policy that inspects responses gets a warning for its targets whose
// responses may not be inspected, whichever proxy serves them (#380): the
// webhook doesn't resolve the proxy, so it names none as the one. It is
// accepted: its requests are inspected, and each target's Programmed
// condition says whether its responses are.
func TestPolicyResponsesWarning(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy}
	ingress := wafv1alpha1.TargetRef{Kind: "Ingress", Name: "web"}
	route := wafv1alpha1.TargetRef{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "api"}
	ingressRoute := wafv1alpha1.TargetRef{Group: "traefik.io", Kind: "IngressRoute", Name: "admin"}
	vs := wafv1alpha1.TargetRef{Group: "networking.istio.io", Kind: "VirtualService", Name: "shop"}
	for _, tc := range []struct {
		name    string
		targets []wafv1alpha1.TargetRef
		want    string
	}{
		{"Ingress", []wafv1alpha1.TargetRef{ingress}, "the responses of Ingress web may not be inspected"},
		{"IngressRoute", []wafv1alpha1.TargetRef{ingressRoute}, "the responses of IngressRoute admin may not be inspected"},
		{"HTTPRoute", []wafv1alpha1.TargetRef{route}, "the responses of HTTPRoute api may not be inspected"},
		{"VirtualService", []wafv1alpha1.TargetRef{vs}, "the responses of VirtualService shop may not be inspected"},
		{"all", []wafv1alpha1.TargetRef{ingress, route, ingressRoute, vs},
			"the responses of Ingress web, HTTPRoute api, IngressRoute admin and VirtualService shop may not be inspected"},
	} {
		p := &wafv1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "shop"},
			Spec: wafv1alpha1.WAFPolicySpec{
				TargetRefs: tc.targets,
				Responses:  &wafv1alpha1.ResponsesSpec{Inspect: true},
			},
		}
		warnings, err := v.ValidateCreate(ctx, p)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(warnings) != 1 {
			t.Fatalf("%s: warnings %q", tc.name, warnings)
		}
		w := warnings[0]
		if !strings.HasPrefix(w, "spec.responses: "+tc.want) {
			t.Errorf("%s: warning %q, want it to start with %q", tc.name, w, tc.want)
		}
		// It names the proxies that can't send responses, and the
		// condition that says which applies, never one proxy as the
		// target's.
		for _, s := range []string{"Traefik", "HAProxy", "Istio", "Programmed", "ResponsesNotInspected"} {
			if !strings.Contains(w, s) {
				t.Errorf("%s: warning %q doesn't mention %s", tc.name, w, s)
			}
		}
		for _, s := range []string{"served by Traefik", "only Envoy Gateway"} {
			if strings.Contains(w, s) {
				t.Errorf("%s: warning %q says %q", tc.name, w, s)
			}
		}
	}
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shop"},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{ingress}, Responses: &wafv1alpha1.ResponsesSpec{Inspect: false}},
	}
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
	// Client IP settings the engine would refuse are rejected; trusting
	// every address draws a warning.
	two := int32(2)
	clientIP := func(c wafv1alpha1.ClientIPSpec) *wafv1alpha1.InkwallConfig {
		x := cfg("")
		x.Spec.Engine.ClientIP = &c
		return x
	}
	if warnings, err := v.ValidateCreate(ctx, clientIP(wafv1alpha1.ClientIPSpec{TrustedProxies: []wafv1alpha1.CIDR{"10.0.0.0/8", "192.0.2.1"}, TrustedHops: &two})); err != nil || len(warnings) != 0 {
		t.Errorf("valid clientIP: warnings %q, error %v", warnings, err)
	}
	_, err := v.ValidateCreate(ctx, clientIP(wafv1alpha1.ClientIPSpec{TrustedProxies: []wafv1alpha1.CIDR{"10.0.0.0/8", "10.0.0.0/33"}}))
	wantInvalid(t, err, "spec.engine.clientIP.trustedProxies[1]", "10.0.0.0/33")
	if warnings, err := v.ValidateUpdate(ctx, cfg(""), clientIP(wafv1alpha1.ClientIPSpec{TrustedProxies: []wafv1alpha1.CIDR{"0.0.0.0/0"}})); err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "0.0.0.0/0") {
		t.Errorf("trusting every address: warnings %q, error %v", warnings, err)
	}

	// The old default, kept by an update, doesn't warn on every apply.
	if warnings, err := v.ValidateUpdate(ctx, cfg("/var/run/inkwall"), cfg("/var/run/inkwall")); err != nil || len(warnings) != 0 {
		t.Errorf("socketDir kept: warnings %q, error %v", warnings, err)
	}
}

func ptr[T any](v T) *T { return &v }
