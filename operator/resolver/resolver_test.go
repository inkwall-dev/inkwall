// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// policy returns a WAFPolicy in namespace shop targeting Ingresses. A lower
// age means created earlier.
func policy(name string, age int, targets ...string) wafv1alpha1.WAFPolicy {
	p := wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "shop",
		Name:              name,
		CreationTimestamp: metav1.NewTime(t0.Add(time.Duration(age) * time.Minute)),
	}}
	for _, t := range targets {
		p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Kind: "Ingress", Name: t})
	}
	return p
}

func ingress(name string, rules ...networkingv1.IngressRule) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec:       networkingv1.IngressSpec{Rules: rules},
	}
}

func rule(host string, paths ...networkingv1.HTTPIngressPath) networkingv1.IngressRule {
	return networkingv1.IngressRule{Host: host, IngressRuleValue: networkingv1.IngressRuleValue{
		HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths},
	}}
}

func ipath(p string, t networkingv1.PathType) networkingv1.HTTPIngressPath {
	return networkingv1.HTTPIngressPath{Path: p, PathType: &t}
}

func prefix(host, value string) *bundlev1.RouteMatch {
	return &bundlev1.RouteMatch{Host: host, Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: value}}
}

func exact(host, value string) *bundlev1.RouteMatch {
	return &bundlev1.RouteMatch{Host: host, Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT, Value: value}}
}

func seclangRuleSet(name, rules string) wafv1alpha1.WAFRuleSet {
	return wafv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: rules}},
	}
}

func useRuleSet(p *wafv1alpha1.WAFPolicy, name string) {
	p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
}

func key(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: "shop", Name: name}
}

func ptr[T any](v T) *T { return &v }

func wantStatus(t *testing.T, res Result, name string, accepted bool, reason, msg string) {
	t.Helper()
	st, ok := res.PolicyStatus[key(name)]
	if !ok {
		t.Fatalf("no status for %s", name)
	}
	if st.Accepted != accepted || st.Reason != reason || !strings.Contains(st.Message, msg) {
		t.Fatalf("%s: status %+v, want accepted=%v reason=%s and a message containing %q", name, st, accepted, reason, msg)
	}
}

func findPolicy(res Result, id string) *bundlev1.Policy {
	for _, p := range res.Policies {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

func wantProto(t *testing.T, got, want proto.Message) {
	t.Helper()
	if !proto.Equal(got, want) {
		t.Fatalf("got\n  %v\nwant\n  %v", got, want)
	}
}

func TestResolvePolicy(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.Mode = wafv1alpha1.PolicyBlock
	p.Spec.FailureMode = wafv1alpha1.FailOpen
	p.Spec.Timeout = &metav1.Duration{Duration: 100 * time.Millisecond}
	p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/healthz"}, BodyPaths: []wafv1alpha1.PathPattern{"/upload"}}
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"},
			CRS: &wafv1alpha1.CRSSettings{
				ParanoiaLevel:              ptr(int32(2)),
				InboundAnomalyThreshold:    ptr(int32(7)),
				AllowedMethods:             []wafv1alpha1.HTTPMethodToken{"GET", "PUT"},
				AllowedRequestContentTypes: []wafv1alpha1.MediaType{"application/json"},
				DetectionParanoiaLevel:     ptr(int32(3)),
				OutboundAnomalyThreshold:   ptr(int32(8)),
			}},
		{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "custom"}},
	}
	p.Spec.Exclusions = []wafv1alpha1.Exclusion{
		{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Path: "/search", Argument: "q"}},
		{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Cookie: "session"}},
		{RuleIDs: []int32{913100}, When: &wafv1alpha1.ExclusionMatch{Path: "/api/*", Header: "User-Agent"}},
		{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{ArgumentName: "q"}},
		{RuleIDs: []int32{920350}},
	}
	p.Spec.Body = &wafv1alpha1.BodySpec{MaxBytes: ptr(int64(1024)), OnOversize: wafv1alpha1.OversizeDeny,
		GRPCMessages: wafv1alpha1.GRPCMessagesInspect, GRPCStreams: wafv1alpha1.GRPCStreamsPerMessage, GRPC: wafv1alpha1.GRPCDeny}
	p.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true, MaxBytes: ptr(int64(4096)), OnOversize: wafv1alpha1.OversizeAllow,
		Streams: wafv1alpha1.StreamsInspect}
	p.Spec.WebSocket = &wafv1alpha1.WebSocketSpec{
		AllowedOrigins:     []wafv1alpha1.WebSocketOrigin{"https://shop.example.com", "https://*.shop.example.com"},
		AllowMissingOrigin: true,
		RequiredHeaders:    []wafv1alpha1.HeaderName{"Authorization"},
	}
	p.Spec.RateLimits = []wafv1alpha1.RateLimit{
		{Name: "login", Requests: 10, Period: metav1.Duration{Duration: time.Minute}, Burst: ptr(int64(20)),
			Key:   &wafv1alpha1.RateLimitKey{ClientIP: &wafv1alpha1.ClientIPKey{IPv6PrefixLength: ptr(int32(64))}},
			Match: &wafv1alpha1.RateLimitMatch{Paths: []wafv1alpha1.PathPattern{"/login", "/api/session/*"}, Methods: []wafv1alpha1.RateLimitMethod{"POST"}}},
		{Name: "api", Requests: 600, Period: metav1.Duration{Duration: time.Minute}, Mode: wafv1alpha1.PolicyDetect,
			Key: &wafv1alpha1.RateLimitKey{Header: &wafv1alpha1.HeaderKey{Name: "X-Api-Key"}}},
		// No key: the client IP, by the engine's default prefix.
		{Name: "all", Requests: 1, Period: metav1.Duration{Duration: time.Second}, Key: &wafv1alpha1.RateLimitKey{ClientIP: &wafv1alpha1.ClientIPKey{}}},
	}
	// Sorted in the bundle, so a reordered list is the same bundle.
	p.Spec.Geo = &wafv1alpha1.GeoSpec{Deny: []wafv1alpha1.CountryCode{"RU", "KP"}, Unknown: wafv1alpha1.GeoUnknownDeny, Mode: wafv1alpha1.GeoModeDetect}
	p.Spec.DenyResponse = &wafv1alpha1.DenyResponse{ContentType: "text/html", Body: "<p>Blocked: {{request_id}}</p>"}
	p.Spec.LLM = &wafv1alpha1.LLMSpec{
		Endpoints: []wafv1alpha1.LLMEndpoint{
			{Paths: []wafv1alpha1.PathPattern{"/v1/chat/completions", "/openai/*"}, Format: wafv1alpha1.LLMOpenAIChat},
			{Paths: []wafv1alpha1.PathPattern{"/v1/messages"}, Format: wafv1alpha1.LLMAnthropicMessages},
			{Paths: []wafv1alpha1.PathPattern{"/v1/responses"}, Format: wafv1alpha1.LLMOpenAIResponses},
			{Paths: []wafv1alpha1.PathPattern{"/v1/embeddings"}, Format: wafv1alpha1.LLMOpenAIEmbeddings},
		},
		MaxBodyBytes: ptr(int64(2 << 20)),
		RuleSetBody:  wafv1alpha1.LLMRuleSetBodyInspect,
		Request: &wafv1alpha1.LLMRequestSpec{
			Models:         []wafv1alpha1.LLMModelPattern{"llama-3.1-8b-instruct", "qwen2.5-*"},
			MaxPromptBytes: ptr(int64(262144)), MaxMessages: ptr(int32(256)), MaxChoices: ptr(int32(1)), MaxOutputTokens: ptr(int64(4096)),
			RequireOutputTokens: true,
			ClientRoles:         []wafv1alpha1.LLMRole{"user", "assistant"},
			Tools:               &wafv1alpha1.LLMToolsSpec{Allow: wafv1alpha1.LLMToolsListed, Names: []wafv1alpha1.LLMToolName{"search_docs"}},
			Mode:                wafv1alpha1.PolicyDetect,
		},
	}

	res := Resolve(Input{
		Policies: []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop",
			rule("Shop.Example.com",
				ipath("/", networkingv1.PathTypePrefix),
				ipath("/api/", networkingv1.PathTypeImplementationSpecific),
				ipath("/login", networkingv1.PathTypeExact)),
			rule("*.shop.example.com", ipath("/static", networkingv1.PathTypePrefix)),
		)},
		RuleSets: []wafv1alpha1.WAFRuleSet{seclangRuleSet("custom", "SecMarker X"), seclangRuleSet("unused", "SecMarker Y")},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "crs"},
			Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
		}},
	})

	wantStatus(t, res, "shop", true, ReasonAccepted, "valid")
	if !res.PolicyStatus[key("shop")].Applied {
		t.Error("an accepted policy must be applied")
	}
	if len(res.Policies) != 1 {
		t.Fatalf("got %d policies", len(res.Policies))
	}
	wantProto(t, res.Policies[0], &bundlev1.Policy{
		Id: "shop/shop",
		Routes: []*bundlev1.RouteMatch{
			prefix("shop.example.com", "/"),
			prefix("shop.example.com", "/api"), // ImplementationSpecific: a prefix; the trailing slash dropped
			exact("shop.example.com", "/login"),
			prefix("*.shop.example.com", "/static"),
		},
		Mode:          bundlev1.Mode_MODE_BLOCK,
		FailureMode:   bundlev1.FailureMode_FAILURE_MODE_OPEN,
		Timeout:       durationpb.New(100 * time.Millisecond),
		SkipPaths:     []string{"/healthz"},
		SkipBodyPaths: []string{"/upload"},
		RuleSets: []*bundlev1.RuleSetBinding{
			{RuleSetId: "ClusterWAFRuleSet/crs", ParanoiaLevel: 2, InboundAnomalyThreshold: 7, Crs: &bundlev1.CRSSettings{
				AllowedMethods:             []string{"GET", "PUT"},
				AllowedRequestContentTypes: []string{"application/json"},
				DetectionParanoiaLevel:     3,
				OutboundAnomalyThreshold:   8,
			}},
			{RuleSetId: "WAFRuleSet/shop/custom"},
		},
		Exclusions: []*bundlev1.Exclusion{
			{RuleIds: []uint32{942100}, Path: "/search", Argument: "q"},
			{RuleIds: []uint32{920350}},
		},
		// Apart, so that an older engine ignores them instead of turning
		// the rules off entirely.
		TargetExclusions: []*bundlev1.Exclusion{
			{RuleIds: []uint32{942100}, Cookie: "session"},
			{RuleIds: []uint32{913100}, Path: "/api/*", Header: "User-Agent"},
			{RuleIds: []uint32{942100}, ArgumentName: "q"},
		},
		Body: &bundlev1.BodyConfig{Inspect: true, MaxBytes: 1024, OnOversize: bundlev1.OversizeAction_OVERSIZE_ACTION_DENY,
			GrpcMessages: true, DenyGrpc: true, GrpcPerMessage: true},
		Responses: &bundlev1.ResponseConfig{Inspect: true, MaxBytes: 4096, OnOversize: bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW, Streams: true},
		Websocket: &bundlev1.WebSocketConfig{
			AllowedOrigins:     []string{"https://shop.example.com", "https://*.shop.example.com"},
			AllowMissingOrigin: true,
			RequiredHeaders:    []string{"Authorization"},
		},
		RateLimits: []*bundlev1.RateLimit{
			{Name: "login", Requests: 10, Period: durationpb.New(time.Minute), Burst: 20,
				Key:   &bundlev1.RateLimitKey{Key: &bundlev1.RateLimitKey_ClientIp{ClientIp: &bundlev1.ClientIPKey{Ipv6PrefixLength: 64}}},
				Paths: []string{"/login", "/api/session/*"}, Methods: []string{"POST"}},
			// The header lower case, for the engine's lookup.
			{Name: "api", Requests: 600, Period: durationpb.New(time.Minute), Detect: true,
				Key: &bundlev1.RateLimitKey{Key: &bundlev1.RateLimitKey_Header{Header: &bundlev1.HeaderKey{Name: "x-api-key"}}}},
			{Name: "all", Requests: 1, Period: durationpb.New(time.Second)},
		},
		Geo:          &bundlev1.Geo{Deny: []string{"KP", "RU"}, UnknownDeny: true, Detect: true},
		DenyResponse: &bundlev1.DenyResponse{ContentType: "text/html", Body: "<p>Blocked: {{request_id}}</p>"},
		Llm: &bundlev1.LLM{
			Endpoints: []*bundlev1.LLMEndpoint{
				{Paths: []string{"/v1/chat/completions", "/openai/*"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_CHAT},
				{Paths: []string{"/v1/messages"}, Format: bundlev1.LLMFormat_LLM_FORMAT_ANTHROPIC_MESSAGES},
				{Paths: []string{"/v1/responses"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_RESPONSES},
				{Paths: []string{"/v1/embeddings"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_EMBEDDINGS},
			},
			MaxBodyBytes: 2 << 20,
			RuleSetBody:  true,
			Request: &bundlev1.LLMRequestChecks{
				Models:         []string{"llama-3.1-8b-instruct", "qwen2.5-*"},
				MaxPromptBytes: 262144, MaxMessages: 256, MaxChoices: 1, MaxOutputTokens: 4096, RequireOutputTokens: true,
				ClientRoles: []bundlev1.LLMRole{bundlev1.LLMRole_LLM_ROLE_USER, bundlev1.LLMRole_LLM_ROLE_ASSISTANT},
				Tools:       bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_LISTED, ToolNames: []string{"search_docs"},
				Detect: true,
			},
		},
	})
	// Only the rule sets in use are in the bundle; all of them get a status.
	var ids []string
	for _, rs := range res.RuleSets {
		ids = append(ids, rs.GetId())
	}
	if !slices.Equal(ids, []string{"ClusterWAFRuleSet/crs", "WAFRuleSet/shop/custom"}) {
		t.Errorf("rule sets %v", ids)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/unused"]; !st.Accepted {
		t.Errorf("unused rule set status %+v", st)
	}
}

// TestLLMDefaults: an unset maxBodyBytes and ruleSetBody are the engine's
// defaults (1 MiB, Skip), and no request checks leaves only the parser's.
func TestLLMDefaults(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.LLM = &wafv1alpha1.LLMSpec{Endpoints: []wafv1alpha1.LLMEndpoint{{Paths: []wafv1alpha1.PathPattern{"/v1/*"}, Format: wafv1alpha1.LLMOpenAIChat}},
		Request: &wafv1alpha1.LLMRequestSpec{Tools: &wafv1alpha1.LLMToolsSpec{Allow: wafv1alpha1.LLMToolsNone}}}
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("", ipath("", networkingv1.PathTypePrefix)))},
	})
	wantProto(t, res.Policies[0].GetLlm(), &bundlev1.LLM{
		Endpoints: []*bundlev1.LLMEndpoint{{Paths: []string{"/v1/*"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_CHAT}},
		Request:   &bundlev1.LLMRequestChecks{Tools: bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_NONE},
	})
}

func TestDefaults(t *testing.T) {
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{policy("shop", 0, "shop")},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("", ipath("", networkingv1.PathTypePrefix)))},
	})
	// Detect mode, no host (any), an empty path is "/".
	wantProto(t, res.Policies[0], &bundlev1.Policy{
		Id:     "shop/shop",
		Mode:   bundlev1.Mode_MODE_DETECT,
		Routes: []*bundlev1.RouteMatch{prefix("", "/")},
	})
}

// A body or response limit is in the bundle only when the policy sets one:
// unset, the engine's own applies (its --max-body-bytes for bodies), as
// before 0.7.0.
func TestBodyLimitDefaults(t *testing.T) {
	limits := policy("limits", 0)
	limits.Spec.Body = &wafv1alpha1.BodySpec{OnOversize: wafv1alpha1.OversizeAllow}
	limits.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true}
	set := policy("set", 0)
	set.Spec.Body = &wafv1alpha1.BodySpec{MaxBytes: ptr(int64(1024))}
	set.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true, MaxBytes: ptr(int64(2048))}
	off := policy("off", 0)
	off.Spec.Body = &wafv1alpha1.BodySpec{Inspect: ptr(false)}
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{limits, set, off}})
	for name, want := range map[string]*bundlev1.Policy{
		"limits": {Body: &bundlev1.BodyConfig{Inspect: true, OnOversize: bundlev1.OversizeAction_OVERSIZE_ACTION_ALLOW},
			Responses: &bundlev1.ResponseConfig{Inspect: true}},
		"set": {Body: &bundlev1.BodyConfig{Inspect: true, MaxBytes: 1024}, Responses: &bundlev1.ResponseConfig{Inspect: true, MaxBytes: 2048}},
		"off": {Body: &bundlev1.BodyConfig{}},
	} {
		want.Id, want.Mode = "shop/"+name, bundlev1.Mode_MODE_DETECT
		wantProto(t, findPolicy(res, "shop/"+name), want)
	}
}

func TestDefaultBackend(t *testing.T) {
	only := ingress("default-only")
	only.Spec.DefaultBackend = &networkingv1.IngressBackend{}
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{policy("shop", 0, "default-only")}, Ingresses: []networkingv1.Ingress{only}})
	wantProto(t, res.Policies[0].GetRoutes()[0], prefix("", "/"))
}

func TestMissingTarget(t *testing.T) {
	res := Resolve(Input{
		Policies:  []wafv1alpha1.WAFPolicy{policy("shop", 0, "shop", "gone")},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "Ingress gone not found; the policy applies to its other targets")
	if !res.PolicyStatus[key("shop")].Applied {
		t.Error("a policy with a missing target still applies to the others")
	}
	if p := findPolicy(res, "shop/shop"); p == nil || len(p.GetRoutes()) != 1 {
		t.Fatalf("the policy must still cover its existing target: %v", p)
	}
}

func TestMissingRuleSet(t *testing.T) {
	p := policy("shop", 0, "shop")
	useRuleSet(&p, "custom")
	in := Input{
		Policies:  []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	}

	// Never resolved: left out.
	res := Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "WAFRuleSet custom not found")
	if len(res.Policies) != 0 {
		t.Fatalf("an unresolvable new policy must be left out: %v", res.Policies)
	}

	// Resolved before: the previous version stays, with its rule set.
	in.RuleSets = []wafv1alpha1.WAFRuleSet{seclangRuleSet("custom", "SecMarker OLD")}
	good := Resolve(in)
	prev := &bundlev1.Bundle{Version: 7, Policies: good.Policies, RuleSets: good.RuleSets}

	in.RuleSets = nil
	in.Previous = prev
	in.Policies[0].Spec.Mode = wafv1alpha1.PolicyBlock // an edit that can't take effect
	res = Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "the previous version of the policy stays in force")
	if res.PolicyStatus[key("shop")].Applied {
		t.Error("a fallback to the previous version is not the current spec applied")
	}
	wantProto(t, findPolicy(res, "shop/shop"), prev.Policies[0])
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker OLD" {
		t.Fatalf("the previous rule set must stay: %v", res.RuleSets)
	}
}

func TestCrossNamespaceRuleSet(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "theirs", Namespace: "other"}}} //nolint:staticcheck // the deprecated field
	res := Resolve(Input{Policies: []wafv1alpha1.WAFPolicy{p}})
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "use a ClusterWAFRuleSet")
}

func TestConflict(t *testing.T) {
	older, newer := policy("older", 0, "shop"), policy("newer", 1, "shop")
	newer.Spec.Mode = wafv1alpha1.PolicyBlock
	res := Resolve(Input{
		// Input order doesn't matter: creation time decides.
		Policies:  []wafv1alpha1.WAFPolicy{newer, older},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
	})
	wantStatus(t, res, "older", true, ReasonAccepted, "valid")
	wantStatus(t, res, "newer", false, ReasonConflict, "older WAFPolicy older")
	if len(res.Policies) != 1 || res.Policies[0].GetId() != "shop/older" {
		t.Fatalf("only the older policy applies: %v", res.Policies)
	}
}

func TestSharedRoute(t *testing.T) {
	// Two Ingresses with the same host and path, each with its policy: the
	// older policy gets the route, the newer keeps its other routes.
	res := Resolve(Input{
		Policies: []wafv1alpha1.WAFPolicy{policy("a", 0, "a"), policy("b", 1, "b")},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix), ipath("/b", networkingv1.PathTypePrefix))),
		},
	})
	wantStatus(t, res, "b", true, ReasonAccepted, "shop.example.com/ (older policy shop/a)")
	if got := findPolicy(res, "shop/b").GetRoutes(); len(got) != 1 || got[0].GetPath().GetValue() != "/b" {
		t.Fatalf("policy b routes: %v", got)
	}
}

func TestConfigMapRules(t *testing.T) {
	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "rules"},
		Data:       map[string]string{"good.conf": "SecMarker GOOD", "bad.conf": "SecRuleEngine Off"},
	}
	fromCM := func(name, k string) wafv1alpha1.WAFRuleSet {
		return wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{ConfigMapRef: &wafv1alpha1.ConfigMapKeyRef{Name: "rules", Key: k}}},
		}
	}
	check := func(rules string) error {
		if strings.Contains(rules, "SecRuleEngine") {
			return errors.New(`line 1: directive "secruleengine" is not allowed`)
		}
		return nil
	}
	in := Input{
		RuleSets:   []wafv1alpha1.WAFRuleSet{fromCM("good", "good.conf"), fromCM("bad", "bad.conf"), fromCM("nokey", "missing.conf")},
		CheckRules: check,
	}

	res := Resolve(in)
	if st := res.RuleSetStatus["WAFRuleSet/shop/good"]; st.Accepted || !strings.Contains(st.Message, "not labeled "+RulesLabel) {
		t.Errorf("ConfigMap not watched: %+v", st)
	}

	in.ConfigMaps = []corev1.ConfigMap{cm}
	p := policy("shop", 0)
	useRuleSet(&p, "good")
	q := policy("broken", 0)
	useRuleSet(&q, "bad")
	in.Policies = []wafv1alpha1.WAFPolicy{p, q}
	res = Resolve(in)
	if st := res.RuleSetStatus["WAFRuleSet/shop/good"]; !st.Accepted {
		t.Errorf("good: %+v", st)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/bad"]; st.Accepted || st.Reason != ReasonRuleCompileError || !strings.Contains(st.Message, "line 1") {
		t.Errorf("bad: %+v", st)
	}
	if st := res.RuleSetStatus["WAFRuleSet/shop/nokey"]; st.Accepted || !strings.Contains(st.Message, `no key "missing.conf"`) {
		t.Errorf("nokey: %+v", st)
	}
	wantStatus(t, res, "broken", false, ReasonInvalidRef, "WAFRuleSet bad is not usable: ConfigMap shop/rules key \"bad.conf\": line 1")
	if len(res.RuleSets) != 1 || res.RuleSets[0].GetSeclang() != "SecMarker GOOD" {
		t.Fatalf("the ConfigMap's rules must be inlined: %v", res.RuleSets)
	}
}

// The paranoia level and inbound threshold go to the same bundle fields
// from crs or from the deprecated binding fields; crs wins (CEL refuses
// both, so only the operator's reading order is tested). CRS settings on a
// rule set that isn't the built-in CRS are noted as ignored (#714).
func TestResolveCRSSettingsLocation(t *testing.T) {
	crs := wafv1alpha1.ClusterWAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "crs"},
		Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
	}
	ref := wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: "crs"}
	settings := &wafv1alpha1.CRSSettings{ParanoiaLevel: ptr(int32(3)), InboundAnomalyThreshold: ptr(int32(9))}
	moved := policy("moved", 0)
	moved.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: ref, CRS: settings}}
	old := policy("old", 0)
	old.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: ref, ParanoiaLevel: ptr(int32(3)), InboundAnomalyThreshold: ptr(int32(9))}}
	both := policy("both", 0)
	both.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: ref, ParanoiaLevel: ptr(int32(1)), InboundAnomalyThreshold: ptr(int32(5)), CRS: settings}}
	seclang := policy("seclang", 0)
	seclang.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{{Ref: ref}, {Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "custom"}, CRS: settings}}

	res := Resolve(Input{
		Policies:        []wafv1alpha1.WAFPolicy{moved, old, both, seclang},
		RuleSets:        []wafv1alpha1.WAFRuleSet{seclangRuleSet("custom", "SecMarker X")},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{crs},
	})
	for _, name := range []string{"moved", "old", "both"} {
		wantStatus(t, res, name, true, ReasonAccepted, PolicyValid)
		if st := res.PolicyStatus[key(name)]; st.Message != PolicyValid {
			t.Errorf("%s: message %q, want only %q", name, st.Message, PolicyValid)
		}
		// No Crs: the bundle is the one the binding-level fields made.
		wantProto(t, findPolicy(res, "shop/"+name), &bundlev1.Policy{
			Id: "shop/" + name, Mode: bundlev1.Mode_MODE_DETECT,
			RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "ClusterWAFRuleSet/crs", ParanoiaLevel: 3, InboundAnomalyThreshold: 9}},
		})
	}
	wantStatus(t, res, "seclang", true, ReasonAccepted,
		"spec.ruleSets[1] sets CRS settings, which are ignored: WAFRuleSet custom isn't the built-in CRS; remove them")
}

// A rule set placed before the CRS (#423) goes into the bundle with its
// placement; AfterCRS, the default, leaves the binding as before. The
// built-in CRS can't be placed before itself, and a BeforeCRS rule set
// can't hold directives that change loaded rules: they would reach no CRS
// rule.
func TestResolvePlacement(t *testing.T) {
	crs := wafv1alpha1.ClusterWAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "crs"},
		Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
	}
	bind := func(kind, name string, placement wafv1alpha1.RuleSetPlacement) wafv1alpha1.RuleSetBinding {
		return wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: kind, Name: name}, Placement: placement}
	}
	p := policy("shop", 0)
	p.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{
		bind("ClusterWAFRuleSet", "crs", ""),
		bind("WAFRuleSet", "tune", wafv1alpha1.PlacementBeforeCRS),
		bind("WAFRuleSet", "custom", wafv1alpha1.PlacementAfterCRS),
	}
	builtin := policy("builtin", 0)
	builtin.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{bind("ClusterWAFRuleSet", "crs", wafv1alpha1.PlacementBeforeCRS)}
	remove := policy("remove", 0)
	remove.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{bind("ClusterWAFRuleSet", "crs", ""), bind("WAFRuleSet", "exclusions", wafv1alpha1.PlacementBeforeCRS)}
	// The same rule set after the CRS is fine.
	after := policy("after", 0)
	after.Spec.RuleSets = []wafv1alpha1.RuleSetBinding{bind("ClusterWAFRuleSet", "crs", ""), bind("WAFRuleSet", "exclusions", "")}

	res := Resolve(Input{
		Policies: []wafv1alpha1.WAFPolicy{p, builtin, remove, after},
		RuleSets: []wafv1alpha1.WAFRuleSet{
			seclangRuleSet("tune", `SecAction "id:100100,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2"`),
			seclangRuleSet("custom", "SecMarker X"),
			seclangRuleSet("exclusions", "SecMarker Y\nSecRuleRemoveById 920350"),
		},
		ClusterRuleSets: []wafv1alpha1.ClusterWAFRuleSet{crs},
	})
	wantStatus(t, res, "shop", true, ReasonAccepted, "valid")
	wantProto(t, findPolicy(res, "shop/shop"), &bundlev1.Policy{
		Id:   "shop/shop",
		Mode: bundlev1.Mode_MODE_DETECT,
		RuleSets: []*bundlev1.RuleSetBinding{
			{RuleSetId: "ClusterWAFRuleSet/crs"},
			{RuleSetId: "WAFRuleSet/shop/tune", Placement: bundlev1.RuleSetPlacement_RULE_SET_PLACEMENT_BEFORE_CRS},
			{RuleSetId: "WAFRuleSet/shop/custom"},
		},
	})
	wantStatus(t, res, "builtin", false, ReasonInvalidRef, "ClusterWAFRuleSet crs is the built-in CRS: it can't be placed before itself")
	wantStatus(t, res, "remove", false, ReasonInvalidRef, "WAFRuleSet exclusions can't be placed before the CRS: line 2")
	wantStatus(t, res, "after", true, ReasonAccepted, "valid")
	if findPolicy(res, "shop/builtin") != nil || findPolicy(res, "shop/remove") != nil {
		t.Error("a policy whose rule set can't be placed before the CRS is in the bundle")
	}
}

func TestDeterministic(t *testing.T) {
	var in Input
	for i := range 20 {
		name := string(rune('a' + i))
		p := policy(name, i%3, name, "shared")
		in.Policies = append(in.Policies, p)
		in.Ingresses = append(in.Ingresses, ingress(name, rule(name+".example.com", ipath("/", networkingv1.PathTypePrefix))))
	}
	in.Ingresses = append(in.Ingresses, ingress("shared", rule("shared.example.com", ipath("/", networkingv1.PathTypePrefix))))
	want := Resolve(in)
	for range 10 {
		rand.Shuffle(len(in.Policies), func(i, j int) { in.Policies[i], in.Policies[j] = in.Policies[j], in.Policies[i] })
		rand.Shuffle(len(in.Ingresses), func(i, j int) { in.Ingresses[i], in.Ingresses[j] = in.Ingresses[j], in.Ingresses[i] })
		got := Resolve(in)
		wantProto(t, &bundlev1.Bundle{Policies: got.Policies, RuleSets: got.RuleSets}, &bundlev1.Bundle{Policies: want.Policies, RuleSets: want.RuleSets})
	}
}

func ipList(name string, cidrs ...string) wafv1alpha1.WAFIPList {
	l := wafv1alpha1.WAFIPList{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}}
	for _, c := range cidrs {
		l.Spec.Entries = append(l.Spec.Entries, wafv1alpha1.IPListEntry{CIDR: wafv1alpha1.CIDR(c)})
	}
	return l
}

// TestIPLists: a policy's IP lists are resolved into its CIDRs, merged
// and without repeats; a missing list, or one in another namespace, fails
// the policy (#358).
func TestIPLists(t *testing.T) {
	p := policy("shop", 0, "shop")
	p.Spec.IPLists = &wafv1alpha1.IPListsSpec{Allow: []wafv1alpha1.IPListName{"monitors"}, Deny: []wafv1alpha1.IPListName{"bad", "worse"}}
	other := ipList("bad", "192.0.2.0/24")
	other.Namespace = "elsewhere"
	in := Input{
		Policies:  []wafv1alpha1.WAFPolicy{p},
		Ingresses: []networkingv1.Ingress{ingress("shop", rule("shop.example.com", ipath("/", networkingv1.PathTypePrefix)))},
		IPLists: []wafv1alpha1.WAFIPList{
			ipList("monitors", "10.0.0.0/8"),
			ipList("bad", "203.0.113.0/24", "2001:db8::/32"),
			ipList("worse", "203.0.113.0/24", "198.51.100.7"),
			other,
		},
	}
	res := Resolve(in)
	wantStatus(t, res, "shop", true, ReasonAccepted, "")
	if len(res.Policies) != 1 {
		t.Fatalf("%d policies", len(res.Policies))
	}
	got := res.Policies[0].GetIpLists()
	if !slices.Equal(got.GetAllow(), []string{"10.0.0.0/8"}) || !slices.Equal(got.GetDeny(), []string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7"}) {
		t.Errorf("IP lists %v", got)
	}

	in.IPLists = in.IPLists[:2]
	res = Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "WAFIPList worse not found")
	in.IPLists = []wafv1alpha1.WAFIPList{ipList("monitors", "10.0.0.0/8"), ipList("worse", "1.2.3.4"), other}
	res = Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "WAFIPList bad not found")
	in.IPLists = []wafv1alpha1.WAFIPList{ipList("monitors", "10.0.0.0/8"), ipList("bad", "lb.example.com"), ipList("worse", "1.2.3.4")}
	res = Resolve(in)
	wantStatus(t, res, "shop", false, ReasonInvalidRef, "WAFIPList bad: ")

	// Every list gets its own status, used or not (#719).
	want := map[string]Status{
		"monitors": {Accepted: true, Reason: ReasonAccepted, Message: IPListValid},
		"worse":    {Accepted: true, Reason: ReasonAccepted, Message: IPListValid},
	}
	for name, st := range want {
		if got := res.IPListStatus[key(name)]; got != st {
			t.Errorf("%s: status %+v, want %+v", name, got, st)
		}
	}
	if got := res.IPListStatus[key("bad")]; got.Accepted || got.Reason != ReasonInvalidEntries || !strings.Contains(got.Message, "lb.example.com") {
		t.Errorf("bad: status %+v, want InvalidEntries naming lb.example.com", got)
	}
}
