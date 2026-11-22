// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpcheck

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/llmtest"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// The check API reads an LLM endpoint's body past the policy's body limit
// and checks it (design 0012): a failed check is a 400 with REASON_LLM and
// its rule ID, and the rules don't read the prompt.
func TestLLMEndpoint(t *testing.T) {
	var logs bytes.Buffer
	h, err := New(llmtest.Set(t), Config{MaxBodyBytes: policy.MaxBodyBytes, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if out := send(t, h, checkRequest("POST", llmtest.Path, "application/json", llmtest.Clean)); out.GetAction() != enginev1.Action_ACTION_ALLOW {
		t.Fatalf("a clean request: %v %v", out.GetAction(), out.GetReason())
	}
	out := send(t, h, checkRequest("POST", llmtest.Path, "application/json", llmtest.Over))
	if out.GetAction() != enginev1.Action_ACTION_DENY || out.GetStatus() != 400 || out.GetReason() != enginev1.Reason_REASON_LLM {
		t.Fatalf("over the output cap: %v %d %v", out.GetAction(), out.GetStatus(), out.GetReason())
	}
	if l := logs.String(); !strings.Contains(l, `"llm_check":"llm-max-output-tokens"`) || strings.Contains(l, "Pearl Harbor") {
		t.Errorf("log: %s", l)
	}
}
