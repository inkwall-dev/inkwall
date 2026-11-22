// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/llm"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// llmBundle is testBundle with LLM endpoints on shop/admin, whose rules
// read no bodies.
func llmBundle(exclusions ...*bundlev1.Exclusion) *bundlev1.Bundle {
	b := testBundle()
	p := b.Policies[2]
	p.Llm = &bundlev1.LLM{
		Endpoints: []*bundlev1.LLMEndpoint{
			{Paths: []string{"/v1/chat/completions"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_CHAT},
			{Paths: []string{"/v1/embeddings"}, Format: bundlev1.LLMFormat_LLM_FORMAT_OPENAI_EMBEDDINGS},
		},
		Request: &bundlev1.LLMRequestChecks{
			Models: []string{"llama-*"}, MaxOutputTokens: 100, MaxMessages: 4,
			ClientRoles: []bundlev1.LLMRole{bundlev1.LLMRole_LLM_ROLE_USER, bundlev1.LLMRole_LLM_ROLE_ASSISTANT},
			Tools:       bundlev1.LLMToolsAllow_LLM_TOOLS_ALLOW_LISTED, ToolNames: []string{"search"},
		},
	}
	p.Exclusions = exclusions
	return b
}

func post(uri, body string) *request.Request {
	r := req("admin.example.com", uri)
	r.Method, r.Body = "POST", []byte(body)
	r.Headers.Set("Content-Type", "application/json")
	return r
}

func TestLLM(t *testing.T) {
	m := llm.NewMetrics()
	set, err := Compile(llmBundle(), Options{BodyLimit: 65536, LLMMetrics: m})
	if err != nil {
		t.Fatal(err)
	}
	// The endpoint reads 1 MiB, though the policy's rules read no body.
	if got := set.BodyLimit(req("admin.example.com", "/v1/chat/completions"), MaxBodyBytes); got != pipeline.DefaultLLMBodyBytes {
		t.Errorf("endpoint body limit %d", got)
	}
	if got := set.BodyLimit(req("admin.example.com", "/other"), MaxBodyBytes); got != 0 {
		t.Errorf("other path's body limit %d", got)
	}
	for _, tc := range []struct {
		name   string
		r      *request.Request
		status int
		check  llm.Check
	}{
		{"clean", post("/v1/chat/completions", `{"model":"llama-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`), 0, llm.CheckNone},
		{"output cap", post("/v1/chat/completions", `{"model":"llama-3","messages":[],"max_tokens":101}`), 400, llm.CheckMaxOutputTokens},
		{"model", post("/v1/chat/completions", `{"model":"gpt-4o","messages":[]}`), 400, llm.CheckModel},
		{"tools", post("/v1/chat/completions", `{"model":"llama-3","tools":[{"type":"function","function":{"name":"shell"}}]}`), 400, llm.CheckTools},
		{"roles", post("/v1/chat/completions", `{"model":"llama-3","messages":[{"role":"developer","content":"x"}]}`), 400, llm.CheckClientRole},
		{"embeddings", post("/v1/embeddings", `{"model":"llama-embed","input":["a","b","c","d","e"]}`), 413, llm.CheckMaxMessages},
		{"malformed", post("/v1/embeddings", `{"model":"llama-embed","input":"a",}`), 400, llm.CheckMalformed},
	} {
		v := set.Check(context.Background(), tc.r)
		switch {
		case tc.check == llm.CheckNone && v.Action != pipeline.ActionAllow:
			t.Errorf("%s: %s %s", tc.name, v.Action, v.Reason)
		case tc.check != llm.CheckNone && (v.Action != pipeline.ActionDeny || v.Status != tc.status || v.LLM == nil || v.LLM.Check != tc.check || v.Policy != "shop/admin"):
			t.Errorf("%s: %s %d %s %+v", tc.name, v.Action, v.Status, v.Reason, v.LLM)
		}
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(m.Collectors()...)
	if n := testutil.ToFloat64(m.Collectors()[0].(*prometheus.CounterVec).WithLabelValues("openai_chat", "request")); n != 5 {
		t.Errorf("%v chat requests counted, want 5", n)
	}
	if n := testutil.ToFloat64(m.Collectors()[2].(*prometheus.CounterVec).WithLabelValues("llm-max-messages", "deny")); n != 1 {
		t.Errorf("%v llm-max-messages denials counted", n)
	}
	if n := testutil.ToFloat64(m.Collectors()[1].(*prometheus.CounterVec).WithLabelValues("openai_embeddings", "request")); n != 1 {
		t.Errorf("%v malformed embeddings counted", n)
	}
	if n := testutil.ToFloat64(m.Collectors()[3].(*prometheus.CounterVec).WithLabelValues("estimated")); n != 1+10 {
		t.Errorf("%v tokens estimated, want 11", n)
	}
}

// TestLLMExclusions: an exclusion of a check's rule ID turns it off, on
// its path or everywhere; one narrowed to an argument, a cookie or a
// header doesn't, nor a target exclusion.
func TestLLMExclusions(t *testing.T) {
	over := `{"model":"llama-3","messages":[],"max_tokens":101}`
	for _, tc := range []struct {
		name    string
		ex      []*bundlev1.Exclusion
		targets []*bundlev1.Exclusion
		denied  bool
	}{
		{"none", nil, nil, true},
		{"on its path", []*bundlev1.Exclusion{{RuleIds: []uint32{4800005}, Path: "/v1/chat/*"}}, nil, false},
		{"everywhere", []*bundlev1.Exclusion{{RuleIds: []uint32{942100, 4800005}}}, nil, false},
		{"another check", []*bundlev1.Exclusion{{RuleIds: []uint32{4800001}}}, nil, true},
		{"another path", []*bundlev1.Exclusion{{RuleIds: []uint32{4800005}, Path: "/v2/*"}}, nil, true},
		{"narrowed to an argument", []*bundlev1.Exclusion{{RuleIds: []uint32{4800005}, Argument: "max_tokens"}}, nil, true},
		{"a target exclusion", nil, []*bundlev1.Exclusion{{RuleIds: []uint32{4800005}, Header: "X-A"}}, true},
	} {
		b := llmBundle(tc.ex...)
		b.Policies[2].TargetExclusions = tc.targets
		set, err := Compile(b, Options{BodyLimit: 65536})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if v := set.Check(context.Background(), post("/v1/chat/completions", over)); (v.Action == pipeline.ActionDeny) != tc.denied {
			t.Errorf("%s: %s %s", tc.name, v.Action, v.Reason)
		}
	}
}

// TestLLMCompileErrors: a bundle the CRD would refuse doesn't compile.
func TestLLMCompileErrors(t *testing.T) {
	for _, mod := range []func(*bundlev1.LLM){
		func(l *bundlev1.LLM) { l.Endpoints = nil },
		func(l *bundlev1.LLM) { l.Endpoints[0].Paths = []string{"no-slash"} },
		func(l *bundlev1.LLM) { l.Endpoints[1].Paths = l.Endpoints[0].Paths },
		func(l *bundlev1.LLM) { l.Request.ToolNames = nil },
		func(l *bundlev1.LLM) { l.Request.Models = []string{"*"} },
	} {
		b := llmBundle()
		mod(b.Policies[2].Llm)
		if _, err := Compile(b, Options{}); err == nil || !strings.Contains(err.Error(), "shop/admin") {
			t.Errorf("compiled: %v", err)
		}
	}
}
