// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

const llmPolicy = `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: storefront, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: storefront}]
  mode: Block
  llm:
    endpoints: [{paths: ["/v1/chat/completions"], format: OpenAIChat}]
    request: {maxOutputTokens: 1000, clientRoles: [user, assistant]}
`

// An llm event: the check, where in the body, its cause and fix, and the
// exclusion of its rule ID on the path, verified.
func TestExplainRequestLLM(t *testing.T) {
	policy := writeFile(t, "policy.yaml", llmPolicy)
	log := writeFile(t, "engine.log", `{"time":"2026-11-21T10:00:00Z","level":"WARN","msg":"security event","phase":"request","status":400,"client_ip":"198.51.100.7","method":"POST","host":"shop.example.com","policy":"shop/storefront","action":"deny","reason":"llm","interrupting_rule_id":4800006,"rule_ids":[4800006],"matches":[{"rule_id":4800006,"variable":"LLM"}],"llm_check":"llm-client-role","llm_format":"OpenAIChat","llm_message_index":0,"llm_offset":13,"path":"/v1/chat/completions","request_id":"req-llm"}
{"time":"2026-11-21T10:00:01Z","level":"WARN","msg":"security event","phase":"request","status":400,"client_ip":"198.51.100.7","method":"POST","host":"shop.example.com","policy":"shop/storefront","action":"deny","reason":"llm","interrupting_rule_id":4800000,"rule_ids":[4800000],"matches":[{"rule_id":4800000,"variable":"LLM"}],"llm_check":"llm-malformed","llm_format":"OpenAIChat","llm_message_index":-1,"llm_offset":40,"path":"/v1/chat/completions","request_id":"req-malformed"}
`)
	_, out, _ := runCLI(t, "explain", "request", "--file", log, "--policy", policy, "--ingress", "testdata/policy/ingress.yaml", "-o", "json", "req-llm")
	var re RequestExplanation
	if err := json.Unmarshal([]byte(out), &re); err != nil || len(re.Events) != 1 {
		t.Fatalf("%v: %s", err, out)
	}
	ev := re.Events[0]
	if l := ev.LLM; l == nil || l.Check != "llm-client-role" || l.RuleID != 4800006 || l.Offset != 13 || !strings.Contains(l.Cause, "clientRoles") || l.Fix == "" {
		t.Fatalf("llm %+v", ev.LLM)
	}
	if len(ev.Suggestions) != 1 || !strings.Contains(ev.Suggestions[0].YAML, "4800006") || !strings.Contains(ev.Suggestions[0].YAML, "/v1/chat/completions") || !ev.Suggestions[0].Verified {
		t.Errorf("suggestions %+v", ev.Suggestions)
	}
	_, text, _ := runCLI(t, "explain", "request", "--file", log, "--policy", policy, "--ingress", "testdata/policy/ingress.yaml", "req-llm")
	for _, want := range []string{"LLM check: llm-client-role (rule ID 4800006)", "message 0 (from 0), byte 13 of the body", "format OpenAIChat"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	// A malformed body: fix the client, nothing to exclude.
	_, out, _ = runCLI(t, "explain", "request", "--file", log, "--policy", policy, "--ingress", "testdata/policy/ingress.yaml", "-o", "json", "req-malformed")
	if err := json.Unmarshal([]byte(out), &re); err != nil || len(re.Events) != 1 || len(re.Events[0].Suggestions) != 0 || re.Events[0].LLM.RuleID != 4800000 {
		t.Errorf("malformed: %v %s", err, out)
	}
}

func TestExplainPolicyLLM(t *testing.T) {
	p := failingPolicy("", "", "")
	p.Spec.LLM = &wafv1alpha1.LLMSpec{
		Endpoints: []wafv1alpha1.LLMEndpoint{{Paths: []wafv1alpha1.PathPattern{"/v1/chat/completions", "/openai/*"}, Format: wafv1alpha1.LLMOpenAIChat}},
		Request: &wafv1alpha1.LLMRequestSpec{Models: []wafv1alpha1.LLMModelPattern{"llama-*"}, MaxOutputTokens: ptr.To[int64](4096), RequireOutputTokens: true,
			Tools: &wafv1alpha1.LLMToolsSpec{Allow: wafv1alpha1.LLMToolsNone}, Mode: wafv1alpha1.PolicyDetect},
	}
	p.Spec.RateLimits = []wafv1alpha1.RateLimit{{Name: "tokens", Requests: 200000, Period: metav1.Duration{Duration: time.Minute}, Cost: wafv1alpha1.RateLimitLLMTokens}}
	ec, _ := explainTestCluster(t, p)
	withExplainCluster(t, ec)
	_, out, errOut := runCLI(t, "explain", "policy", "shop/web")
	for _, want := range []string{
		"LLM endpoints (Detect: logs only): OpenAIChat: /v1/chat/completions, /openai/*; bodies up to 1048576 bytes, which the rule sets skip",
		"llm-model: only llama-*", "llm-max-output-tokens: an output limit required, at most 4096", "llm-tools: no client-defined tools",
		"Rate limit tokens: each engine serving the policy allows 200000 LLM tokens per 1m0s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain policy lacks %q: %s%s", want, out, errOut)
		}
	}
}

// tune suggests an LLM check's exclusion on its path, without --broad,
// but never llm-malformed's.
func TestTuneLLM(t *testing.T) {
	evs := []tuneEvent{
		{Policy: "shop/web", Path: "/v1/chat/completions", Reason: "llm", Matches: []tuneMatch{{RuleID: 4800005, Variable: "LLM"}}},
		{Policy: "shop/web", Path: "/v1/chat/completions", Reason: "llm", Matches: []tuneMatch{{RuleID: 4800000, Variable: "LLM"}}},
	}
	rep := tune(evs, false, 1)
	got := rep.Suggestions["shop/web"]
	if len(got) != 1 || len(got[0].RuleIDs) != 1 || got[0].RuleIDs[0] != 4800005 || got[0].When.Path != "/v1/chat/completions" {
		t.Errorf("suggestions %+v", got)
	}
	skipped := false
	for _, g := range rep.Groups {
		if g.RuleID == 4800000 && strings.Contains(g.Skip, "malformed") {
			skipped = true
		}
	}
	if !skipped {
		t.Error("llm-malformed suggested")
	}
}
