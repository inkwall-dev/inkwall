// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package llmtest is the policy the adapters' tests check LLM endpoints
// with (design 0012): each adapter must read an endpoint's body to its own
// limit, deny a failed check with 400 and the request ID, and keep the
// rules off the body.
package llmtest

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
)

// Path is the policy's chat endpoint.
const Path = "/v1/chat/completions"

// BodyLimit is the policy's body.maxBytes, which Clean and Over are over:
// read whole only as an endpoint's.
const BodyLimit = 1024

var prompt = strings.Repeat("Tell me about the attack on Pearl Harbor. ", 40)

// Clean is a chat request that passes the checks, longer than BodyLimit,
// whose prompt has the word the rules deny ("attack").
var Clean = `{"model":"llama-3","messages":[{"role":"user","content":"` + prompt + `"}],"max_tokens":10}`

// Over asks for more output tokens than the policy allows
// (llm-max-output-tokens).
var Over = `{"model":"llama-3","messages":[{"role":"user","content":"` + prompt + `"}],"max_tokens":1000}`

// Bundle is one Block policy on every route: rules that deny a body with
// "attack", a 1 KiB body limit, and a chat endpoint that caps the output
// limit at 100.
func Bundle() *bundlev1.Bundle {
	return &bundlev1.Bundle{
		Version: 1,
		Policies: []*bundlev1.Policy{{
			Id:       "ai/chat",
			Mode:     bundlev1.Mode_MODE_BLOCK,
			Routes:   []*bundlev1.RouteMatch{{Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}}},
			Timeout:  durationpb.New(10 * time.Second),
			RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "WAFRuleSet/ai/body"}},
			Body:     &bundlev1.BodyConfig{Inspect: true, MaxBytes: BodyLimit},
			Llm: &bundlev1.LLM{
				Endpoints: []*bundlev1.LLMEndpoint{{Paths: []string{Path}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_CHAT}},
				Request:   &bundlev1.LLMRequestChecks{MaxOutputTokens: 100},
			},
		}},
		RuleSets: []*bundlev1.RuleSet{{Id: "WAFRuleSet/ai/body",
			Source: &bundlev1.RuleSet_Seclang{Seclang: `SecRule REQUEST_BODY "@contains attack" "id:100001,phase:2,deny,status:403,log"`}}},
	}
}

// Set is Bundle, compiled.
func Set(t testing.TB) *policy.Set {
	t.Helper()
	s, err := policy.Compile(Bundle(), policy.Options{BodyLimit: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Small is a chat request of 11 tokens (a 2-byte prompt, 10 output).
const Small = `{"model":"llama-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10,"stream":true}`

// StreamUsage is a streamed answer (Server-Sent Events) whose last chunk
// says the request used 5,000 tokens.
const StreamUsage = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n" +
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4990,\"completion_tokens\":10}}\n\n" +
	"data: [DONE]\n\n"

// TokenSet is Bundle with responses inspected (streams event by event
// too, if streams) and a token limit of 1,000 an hour by the X-Api-Key
// header, compiled: two Small requests fit, unless the first's streamed
// usage (StreamUsage) settles it as debt.
func TokenSet(t testing.TB, streams bool) *policy.Set {
	t.Helper()
	b := Bundle()
	b.Policies[0].Responses = &bundlev1.ResponseConfig{Inspect: true, MaxBytes: 64 << 10, Streams: streams}
	b.Policies[0].RateLimits = []*bundlev1.RateLimit{{Name: "tokens", Requests: 1000, Period: durationpb.New(time.Hour),
		Key:  &bundlev1.RateLimitKey{Key: &bundlev1.RateLimitKey_Header{Header: &bundlev1.HeaderKey{Name: "X-Api-Key"}}},
		Cost: bundlev1.RateLimitCost_RATE_LIMIT_COST_LLM_TOKENS}}
	s, err := policy.Compile(b, policy.Options{BodyLimit: 64 << 10, RateLimits: ratelimit.New(1024, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
