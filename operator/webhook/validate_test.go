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

	// The LLM checks' IDs are reserved, for exclusions (design 0012 §3.4).
	_, err = v.ValidateCreate(ctx, rs(wafv1alpha1.RuleSetSource{SecLang: "SecRule ARGS \"@contains a\" \"id:100001,phase:2,deny\"\nSecRule ARGS \"@contains b\" \"id:4800003,phase:2,deny\""}))
	wantInvalid(t, err, "spec.source.seclang", "line 2: rule ID 4800003 is reserved for Inkwall's LLM checks")
}

// TestPolicyLLMCompiles: endpoint paths the CRD finds distinct but the
// engine reads as one are refused at admission, as the engine would refuse
// the bundle.
func TestPolicyLLMCompiles(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	for _, tc := range []struct {
		paths [][]wafv1alpha1.PathPattern
		ok    bool
	}{
		{[][]wafv1alpha1.PathPattern{{"/v1/chat"}, {"/v1/messages"}}, true},
		{[][]wafv1alpha1.PathPattern{{"/v1/chat"}, {"/v1/chat/"}}, false},
		{[][]wafv1alpha1.PathPattern{{"/v1/chat"}, {"/V1/Chat"}}, false},
		{[][]wafv1alpha1.PathPattern{{"/v1/chat", "/V1/CHAT/"}}, false},
		{[][]wafv1alpha1.PathPattern{{"/v1/./chat"}}, false},
		{[][]wafv1alpha1.PathPattern{{"/v1//chat"}}, false},
	} {
		var eps []wafv1alpha1.LLMEndpoint
		for _, ps := range tc.paths {
			eps = append(eps, wafv1alpha1.LLMEndpoint{Paths: ps, Format: wafv1alpha1.LLMOpenAIChat})
		}
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}, LLM: &wafv1alpha1.LLMSpec{Endpoints: eps}}}
		_, err := v.ValidateCreate(ctx, p)
		if tc.ok && err != nil || !tc.ok && (err == nil || !strings.Contains(err.Error(), "spec.llm")) {
			t.Errorf("%v: %v", tc.paths, err)
		}
	}
}

// TestPolicyLLMWarnings: an endpoint path that a skip path covers draws a
// warning: the skip wins.
func TestPolicyLLMWarnings(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	for _, tc := range []struct {
		skip     wafv1alpha1.SkipSpec
		endpoint wafv1alpha1.PathPattern
		want     string
	}{
		{wafv1alpha1.SkipSpec{BodyPaths: []wafv1alpha1.PathPattern{"/v1/chat/completions"}}, "/v1/chat/completions", "spec.llm.endpoints[0].paths[0]: /v1/chat/completions is also in spec.skip.bodyPaths (/v1/chat/completions)"},
		{wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/v1/*"}}, "/v1/chat/completions", "also in spec.skip.paths (/v1/*)"},
		{wafv1alpha1.SkipSpec{BodyPaths: []wafv1alpha1.PathPattern{"/v1/chat/x"}}, "/v1/chat/*", "also in spec.skip.bodyPaths (/v1/chat/x)"},
		{wafv1alpha1.SkipSpec{BodyPaths: []wafv1alpha1.PathPattern{"/v1/chat/"}}, "/v1/chat", "also in spec.skip.bodyPaths"},
		{wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/healthz"}, BodyPaths: []wafv1alpha1.PathPattern{"/upload/*"}}, "/v1/chat/completions", ""},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}, Skip: &tc.skip,
			LLM: &wafv1alpha1.LLMSpec{Endpoints: []wafv1alpha1.LLMEndpoint{{Paths: []wafv1alpha1.PathPattern{tc.endpoint}, Format: wafv1alpha1.LLMOpenAIChat}}},
		}}
		warnings, err := v.ValidateCreate(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(warnings, "\n")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%v and %s: warnings %q, want %q", tc.skip, tc.endpoint, got, tc.want)
		}
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
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
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
		Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"},
		CRS: &wafv1alpha1.CRSSettings{
			ParanoiaLevel:              ptr(int32(2)),
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
	// The deprecated binding-level paranoia level still counts (#714).
	old := crs.DeepCopy()
	old.Spec.RuleSets[0].CRS.ParanoiaLevel = nil
	old.Spec.RuleSets[0].ParanoiaLevel = ptr(int32(4)) //nolint:staticcheck // the deprecated field
	_, err = v.ValidateCreate(ctx, old)
	wantInvalid(t, err, "spec.ruleSets[0].crs.detectionParanoiaLevel", "paranoia level")
}

// A rule set reference's namespace draws a warning (#715): another
// namespace is never resolved, the policy's own does nothing; v1 drops it.
func TestPolicyRuleSetNamespaceWarning(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	ref := func(ns string) wafv1alpha1.RuleSetBinding {
		return wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "rules", Namespace: ns}} //nolint:staticcheck // the deprecated field
	}
	for _, tc := range []struct {
		ns, want string
	}{
		{ns: ""},
		{ns: "shop", want: "spec.ruleSets[0].ref.namespace is the policy's own"},
		{ns: "security", want: "spec.ruleSets[0].ref.namespace security: rule sets in other namespaces can't be used, so the policy won't be Accepted"},
	} {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "shop"}}
		p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{ref(tc.ns)}
		warnings, err := v.ValidateCreate(ctx, p)
		if err != nil || (tc.want == "") != (len(warnings) == 0) || len(warnings) > 1 {
			t.Errorf("namespace %q: warnings %q, error %v", tc.ns, warnings, err)
			continue
		}
		if tc.want != "" && (!strings.Contains(warnings[0], tc.want) || !strings.Contains(warnings[0], "v1 removes the field")) {
			t.Errorf("namespace %q: warning %q doesn't say %q", tc.ns, warnings[0], tc.want)
		}
	}
}

// The binding-level paranoiaLevel and inboundAnomalyThreshold are
// deprecated for crs's (#714): each draws a warning, crs's none.
func TestPolicyCRSWarnings(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	ref := wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "shop"}}
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: ref, CRS: &wafv1alpha1.CRSSettings{ParanoiaLevel: ptr(int32(2)), InboundAnomalyThreshold: ptr(int32(7))}}}
	if warnings, err := v.ValidateCreate(ctx, p); err != nil || len(warnings) != 0 {
		t.Errorf("crs: warnings %q, error %v", warnings, err)
	}
	p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: ref, ParanoiaLevel: ptr(int32(2)), InboundAnomalyThreshold: ptr(int32(7))}) //nolint:staticcheck // the deprecated fields
	warnings, err := v.ValidateCreate(ctx, p)
	want := []string{
		"spec.ruleSets[1].paranoiaLevel is deprecated: set spec.ruleSets[1].crs.paranoiaLevel instead",
		"spec.ruleSets[1].inboundAnomalyThreshold is deprecated: set spec.ruleSets[1].crs.inboundAnomalyThreshold instead",
	}
	if err != nil || len(warnings) != len(want) {
		t.Fatalf("deprecated fields: warnings %q, error %v", warnings, err)
	}
	for i, w := range want {
		if !strings.Contains(warnings[i], w) {
			t.Errorf("warning %q doesn't say %q", warnings[i], w)
		}
	}
}

// The deprecation warnings are for what an update sets, not for what it
// leaves as it was: another spec change draws none, as the InkwallConfig's.
func TestPolicyDeprecationWarningsOnUpdate(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	crs := wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}
	old := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "shop"}}
	old.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		{Ref: crs, ParanoiaLevel: ptr(int32(2))},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "rules", Namespace: "shop"}}, //nolint:staticcheck // the deprecated field
	}
	changed := old.DeepCopy()
	changed.Spec.Mode = wafv1alpha1.PolicyBlock
	if warnings, err := v.ValidateUpdate(ctx, old, changed); err != nil || len(warnings) != 0 {
		t.Errorf("unchanged deprecated fields: warnings %q, error %v", warnings, err)
	}
	// A new value, or a newly set field, warns again.
	changed.Spec.RuleSets[0].ParanoiaLevel = ptr(int32(3))           //nolint:staticcheck // the deprecated field
	changed.Spec.RuleSets[0].InboundAnomalyThreshold = ptr(int32(7)) //nolint:staticcheck // the deprecated field
	warnings, err := v.ValidateUpdate(ctx, old, changed)
	if err != nil || len(warnings) != 2 || !strings.Contains(warnings[0], "spec.ruleSets[0].paranoiaLevel is deprecated") ||
		!strings.Contains(warnings[1], "spec.ruleSets[0].inboundAnomalyThreshold is deprecated") {
		t.Errorf("changed deprecated fields: warnings %q, error %v", warnings, err)
	}
	// Creating the same policy warns of each.
	if warnings, err := v.ValidateCreate(ctx, old); err != nil || len(warnings) != 2 {
		t.Errorf("create: warnings %q, error %v", warnings, err)
	}
}

// A rule set placed before the CRS can't be the CRS, so a binding that
// places one there can't carry the CRS's settings (#423).
func TestPolicyValidationPlacement(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "shop"}}
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}, CRS: &wafv1alpha1.CRSSettings{ParanoiaLevel: ptr(int32(2))}, Placement: wafv1alpha1.PlacementAfterCRS},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "tune"}, Placement: wafv1alpha1.PlacementBeforeCRS},
	}
	if _, err := v.ValidateCreate(ctx, p); err != nil {
		t.Fatalf("valid placement: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*wafv1alpha1.RuleSetBinding)
	}{
		{"paranoia level", func(b *wafv1alpha1.RuleSetBinding) { b.ParanoiaLevel = ptr(int32(2)) }}, //nolint:staticcheck // the deprecated field
		{"crs paranoia level", func(b *wafv1alpha1.RuleSetBinding) { b.CRS = &wafv1alpha1.CRSSettings{ParanoiaLevel: ptr(int32(2))} }},
		{"threshold", func(b *wafv1alpha1.RuleSetBinding) { b.InboundAnomalyThreshold = ptr(int32(10)) }}, //nolint:staticcheck // the deprecated field
		{"crs", func(b *wafv1alpha1.RuleSetBinding) {
			b.CRS = &wafv1alpha1.CRSSettings{AllowedMethods: []wafv1alpha1.HTTPMethodToken{"GET"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := p.DeepCopy()
			tc.edit(&q.Spec.RuleSets[1])
			_, err := v.ValidateCreate(ctx, q)
			wantInvalid(t, err, "spec.ruleSets[1].placement", "only for SecLang rule sets")
		})
	}
}

// A policy that inspects responses gets a warning for its targets whose
// responses may not be inspected, whichever proxy serves them (#380): the
// webhook doesn't resolve the proxy, so it names none as the one. It is
// accepted: its requests are inspected, and each target's Programmed
// condition says whether its responses are. VirtualServices are Istio's,
// which sends responses since #374: no warning.
func TestPolicyResponsesWarning(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
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
		{"all", []wafv1alpha1.TargetRef{ingress, route, ingressRoute, vs},
			"the responses of Ingress web, HTTPRoute api and IngressRoute admin may not be inspected"},
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
		for _, s := range []string{"Traefik can't", "Envoy Gateway, Istio and the HAProxy Kubernetes Ingress Controller can", "Programmed", "ResponsesNotInspected"} {
			if !strings.Contains(w, s) {
				t.Errorf("%s: warning %q doesn't mention %s", tc.name, w, s)
			}
		}
		// HAProxy sends responses since #470: not named as unable.
		for _, s := range []string{"served by Traefik", "only Envoy Gateway", "HAProxy Kubernetes Ingress Controller can't"} {
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
	p.Spec = wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{vs}, Responses: &wafv1alpha1.ResponsesSpec{Inspect: true}}
	if warnings, _ := v.ValidateCreate(ctx, p); len(warnings) != 0 {
		t.Errorf("VirtualService only: warnings %q", warnings)
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

// An integration's adapter is ignored: setting or changing it draws one
// warning per integration, keeping or removing it none.
func TestConfigAdapterWarning(t *testing.T) {
	ctx := context.Background()
	v := configValidator{}
	cfg := func(integrations ...wafv1alpha1.IntegrationSpec) *wafv1alpha1.InkwallConfig {
		return &wafv1alpha1.InkwallConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       wafv1alpha1.InkwallConfigSpec{Integrations: integrations},
		}
	}
	in := func(controller string, adapter wafv1alpha1.AdapterKind) wafv1alpha1.IntegrationSpec {
		return wafv1alpha1.IntegrationSpec{Controller: controller, Adapter: adapter} //nolint:staticcheck // the deprecated field
	}
	traefik := in("traefik", wafv1alpha1.AdapterForwardAuth)
	haproxy := in("haproxy", wafv1alpha1.AdapterSPOE)

	for _, tc := range []struct {
		name     string
		old, cfg *wafv1alpha1.InkwallConfig // old nil: create
		want     []string                   // the integrations warned of
	}{
		{name: "absent on create", cfg: cfg(in("traefik", ""))},
		{name: "set on create", cfg: cfg(traefik, haproxy), want: []string{"[0].adapter (traefik)", "[1].adapter (haproxy)"}},
		{name: "absent on update", old: cfg(), cfg: cfg(in("traefik", ""))},
		{name: "unchanged", old: cfg(traefik, haproxy), cfg: cfg(haproxy, traefik)},
		{name: "added", old: cfg(in("traefik", "")), cfg: cfg(traefik), want: []string{"[0].adapter (traefik)"}},
		{name: "changed", old: cfg(traefik, haproxy), cfg: cfg(in("traefik", wafv1alpha1.AdapterExtAuthz), haproxy), want: []string{"[0].adapter (traefik)"}},
		{name: "removed", old: cfg(traefik), cfg: cfg(in("traefik", ""))},
	} {
		var warnings []string
		var err error
		if tc.old == nil {
			warnings, err = v.ValidateCreate(ctx, tc.cfg)
		} else {
			warnings, err = v.ValidateUpdate(ctx, tc.old, tc.cfg)
		}
		if err != nil || len(warnings) != len(tc.want) {
			t.Errorf("%s: warnings %q, error %v; want %d", tc.name, warnings, err, len(tc.want))
			continue
		}
		for i, w := range warnings {
			for _, s := range []string{"spec.integrations" + tc.want[i], "deprecated and ignored", "v1 removes"} {
				if !strings.Contains(w, s) {
					t.Errorf("%s: warning %q doesn't say %q", tc.name, w, s)
				}
			}
		}
	}
}

// jsonDenials is deprecated for denialFormat: turning it on warns, keeping
// it on or using denialFormat doesn't.
func TestConfigJSONDenialsWarning(t *testing.T) {
	ctx := context.Background()
	v := configValidator{}
	cfg := func(e wafv1alpha1.EngineSpec) *wafv1alpha1.InkwallConfig {
		return &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wafv1alpha1.InkwallConfigSpec{Engine: e}}
	}
	on := cfg(wafv1alpha1.EngineSpec{JSONDenials: true}) //nolint:staticcheck // the deprecated field
	off := cfg(wafv1alpha1.EngineSpec{})
	format := cfg(wafv1alpha1.EngineSpec{DenialFormat: wafv1alpha1.DenialJSON})
	for _, tc := range []struct {
		name     string
		old, cfg *wafv1alpha1.InkwallConfig // old nil: create
		warn     bool
	}{
		{name: "set on create", cfg: on, warn: true},
		{name: "denialFormat on create", cfg: format},
		{name: "turned on", old: off, cfg: on, warn: true},
		{name: "kept on", old: on, cfg: on},
		{name: "moved to denialFormat", old: on, cfg: format},
	} {
		var warnings []string
		var err error
		if tc.old == nil {
			warnings, err = v.ValidateCreate(ctx, tc.cfg)
		} else {
			warnings, err = v.ValidateUpdate(ctx, tc.old, tc.cfg)
		}
		if err != nil || (len(warnings) == 1) != tc.warn || len(warnings) > 1 {
			t.Errorf("%s: warnings %q, error %v; want a warning: %t", tc.name, warnings, err, tc.warn)
			continue
		}
		if tc.warn && (!strings.Contains(warnings[0], "spec.engine.jsonDenials is deprecated") || !strings.Contains(warnings[0], "denialFormat: JSON")) {
			t.Errorf("%s: warning %q", tc.name, warnings[0])
		}
	}
}

// A controller that isn't a DNS label draws a warning when it is added
// (#712): v1 refuses it.
func TestConfigControllerWarning(t *testing.T) {
	ctx := context.Background()
	v := configValidator{}
	cfg := func(controllers ...string) *wafv1alpha1.InkwallConfig {
		c := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
		for _, n := range controllers {
			c.Spec.Integrations = append(c.Spec.Integrations, wafv1alpha1.IntegrationSpec{Controller: n})
		}
		return c
	}
	for _, tc := range []struct {
		name     string
		old, cfg *wafv1alpha1.InkwallConfig // old nil: create
		want     []string
	}{
		{name: "DNS labels", cfg: cfg("traefik", "envoy-gateway", "istio-ingress")},
		{name: "not DNS labels", cfg: cfg("traefik", "Traefik", "ingress_nginx"), want: []string{`[1].controller "Traefik"`, `[2].controller "ingress_nginx"`}},
		{name: "added", old: cfg("traefik"), cfg: cfg("traefik", "HAProxy"), want: []string{`[1].controller "HAProxy"`}},
		{name: "kept", old: cfg("HAProxy"), cfg: cfg("traefik", "HAProxy")},
	} {
		var warnings []string
		var err error
		if tc.old == nil {
			warnings, err = v.ValidateCreate(ctx, tc.cfg)
		} else {
			warnings, err = v.ValidateUpdate(ctx, tc.old, tc.cfg)
		}
		if err != nil || len(warnings) != len(tc.want) {
			t.Errorf("%s: warnings %q, error %v; want %d", tc.name, warnings, err, len(tc.want))
			continue
		}
		for i, w := range warnings {
			for _, s := range []string{"spec.integrations" + tc.want[i], "not a DNS label", "v1 refuses it"} {
				if !strings.Contains(w, s) {
					t.Errorf("%s: warning %q doesn't say %q", tc.name, w, s)
				}
			}
		}
	}
}

// Repeats in the lists v1 makes sets, and an exclusion header that isn't a
// header name, draw warnings (#717); the objects stay accepted.
func TestListWarnings(t *testing.T) {
	ctx := context.Background()
	pv := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, deprecated: policyDeprecations}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "shop"}}
	p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/a", "/b"}, BodyPaths: []wafv1alpha1.PathPattern{"/up"}}
	p.Spec.Exclusions = []wafv1alpha1.Exclusion{{RuleIDs: []int32{942100, 942200}, When: &wafv1alpha1.ExclusionMatch{Header: "Referer"}}}
	if warnings, err := pv.ValidateCreate(ctx, p); err != nil || len(warnings) != 0 {
		t.Errorf("no repeats: warnings %q, error %v", warnings, err)
	}
	p.Spec.Skip.Paths = append(p.Spec.Skip.Paths, "/a")
	p.Spec.Skip.BodyPaths = append(p.Spec.Skip.BodyPaths, "/up", "/up")
	p.Spec.Exclusions[0].RuleIDs = append(p.Spec.Exclusions[0].RuleIDs, 942100)
	p.Spec.Exclusions[0].When.Header = "X-Forwarded[0]"
	warnings, err := pv.ValidateCreate(ctx, p)
	want := []string{
		"spec.skip.paths[2]: /a is also spec.skip.paths[0]",
		"spec.skip.bodyPaths[1]: /up is also spec.skip.bodyPaths[0]",
		"spec.skip.bodyPaths[2]: /up is also spec.skip.bodyPaths[0]",
		"spec.exclusions[0].ruleIDs[2]: 942100 is also spec.exclusions[0].ruleIDs[0]",
		`spec.exclusions[0].when.header: "X-Forwarded[0]" is not a header name; v1 refuses it`,
	}
	if err != nil || len(warnings) != len(want) {
		t.Fatalf("warnings %q, error %v; want %d", warnings, err, len(want))
	}
	for i, w := range want {
		if !strings.Contains(warnings[i], w) {
			t.Errorf("warning %q doesn't say %q", warnings[i], w)
		}
	}

	lv := specValidator[*wafv1alpha1.WAFIPList]{validate: validateWAFIPList}
	l := &wafv1alpha1.WAFIPList{ObjectMeta: metav1.ObjectMeta{Name: "l"}, Spec: wafv1alpha1.WAFIPListSpec{Entries: []wafv1alpha1.IPListEntry{
		{CIDR: "203.0.113.0/24"}, {CIDR: "192.0.2.1"}, {CIDR: "203.0.113.0/24", Description: "again"},
	}}}
	warnings, err = lv.ValidateCreate(ctx, l)
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "spec.entries[2]: 203.0.113.0/24 is also spec.entries[0]") ||
		!strings.Contains(warnings[0], "v1 keys the entries by cidr") {
		t.Errorf("IP list repeat: warnings %q, error %v", warnings, err)
	}
}

func ptr[T any](v T) *T { return &v }

// TestIPListValidation: a WAFIPList's entries must parse as the engine
// parses them (#358); the CRD's pattern lets 999.1.1.1 through.
func TestIPListValidation(t *testing.T) {
	ctx := context.Background()
	v := specValidator[*wafv1alpha1.WAFIPList]{validate: validateWAFIPList}
	l := &wafv1alpha1.WAFIPList{ObjectMeta: metav1.ObjectMeta{Name: "bad"}, Spec: wafv1alpha1.WAFIPListSpec{Entries: []wafv1alpha1.IPListEntry{
		{CIDR: "203.0.113.0/24"}, {CIDR: "2001:db8::/32"}, {CIDR: "192.0.2.1"},
	}}}
	if _, err := v.ValidateCreate(ctx, l); err != nil {
		t.Fatalf("valid list: %v", err)
	}
	l.Spec.Entries[1].CIDR = "999.1.1.1"
	_, err := v.ValidateCreate(ctx, l)
	wantInvalid(t, err, "spec.entries[1].cidr", "999.1.1.1")
}

// A JSON denial must be a JSON document with the request ID in it, which
// the CRD can't check; the engine would serve it as it is (#725).
func TestDenyResponseValidation(t *testing.T) {
	ctx := context.Background()
	pv := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy}
	policy := func(d *wafv1alpha1.DenyResponse) *wafv1alpha1.WAFPolicy {
		return &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "shop"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "shop"}}, DenyResponse: d}}
	}
	cv := configValidator{}
	config := func(d *wafv1alpha1.DenyResponse) *wafv1alpha1.InkwallConfig {
		return &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: wafv1alpha1.InkwallConfigSpec{Engine: wafv1alpha1.EngineSpec{DenyResponse: d}}}
	}
	for _, d := range []*wafv1alpha1.DenyResponse{
		{ContentType: "application/json", Body: `{"error":"blocked","request_id":"{{request_id}}"}`},
		{ContentType: "text/html; charset=utf-8", Body: "<p>{{request_id}}</p>"},
	} {
		if _, err := pv.ValidateCreate(ctx, policy(d)); err != nil {
			t.Errorf("policy %q: %v", d.Body, err)
		}
		if _, err := cv.ValidateCreate(ctx, config(d)); err != nil {
			t.Errorf("InkwallConfig %q: %v", d.Body, err)
		}
	}
	bad := &wafv1alpha1.DenyResponse{ContentType: "application/problem+json", Body: `{"request_id":{{request_id}}}`}
	_, err := pv.ValidateCreate(ctx, policy(bad))
	wantInvalid(t, err, "spec.denyResponse", "not a JSON document")
	_, err = cv.ValidateCreate(ctx, config(bad))
	wantInvalid(t, err, "spec.engine.denyResponse", "not a JSON document")
	_, err = cv.ValidateUpdate(ctx, config(nil), config(bad))
	wantInvalid(t, err, "spec.engine.denyResponse", "not a JSON document")
}
