// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/llmtest"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// An LLM endpoint's body, which Traefik's Buffering Middleware sends, is
// read past the policy's body limit and checked (design 0012): a failed
// check is a 400 with the request ID, and the rules don't read the prompt.
func TestLLMEndpoint(t *testing.T) {
	var logs bytes.Buffer
	h, err := New(llmtest.Set(t), Config{MaxBodyBytes: policy.MaxBodyBytes, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(h, subrequest("POST", llmtest.Path, "application/json", llmtest.Clean)); w.Code != 200 {
		t.Fatalf("a clean request: %d %s", w.Code, w.Body.String())
	}
	w := serve(h, subrequest("POST", llmtest.Path, "application/json", llmtest.Over))
	if w.Code != 400 || w.Header().Get("X-Request-Id") == "" || w.Body.String() != "Bad Request\n" {
		t.Fatalf("over the output cap: %d %q, X-Request-Id %q", w.Code, w.Body.String(), w.Header().Get("X-Request-Id"))
	}
	if l := logs.String(); !strings.Contains(l, `"reason":"llm"`) || !strings.Contains(l, `"llm_check":"llm-max-output-tokens"`) || strings.Contains(l, "Pearl Harbor") {
		t.Errorf("log: %s", l)
	}
}
