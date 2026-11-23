// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/llmtest"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// An LLM endpoint's body is read past the policy's body limit and checked
// (design 0012): a failed check is a 400 with the request ID, and the
// rules don't read the prompt.
func TestLLMEndpoint(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, llmtest.Set(t), policy.MaxBodyBytes, &logs)
	send := func(b string) int {
		t.Helper()
		resps := e.exchange(t, withMode(headers("POST", llmtest.Path, false, "content-type", "application/json", "content-length", strconv.Itoa(len(b))),
			filterv3.ProcessingMode_BUFFERED), body(b, true))
		if len(resps) != 2 {
			t.Fatalf("answers %v: the verdict must wait for the body", resps)
		}
		return denied(t, resps[1])
	}
	if got := send(llmtest.Clean); got != 0 {
		t.Fatalf("a clean request: %d", got)
	}
	if got := send(llmtest.Over); got != 400 {
		t.Fatalf("over the output cap: %d, want 400", got)
	}
	if l := logs.String(); !strings.Contains(l, `"reason":"llm"`) || !strings.Contains(l, `"llm_check":"llm-max-output-tokens"`) || strings.Contains(l, "Pearl Harbor") {
		t.Errorf("log: %s", l)
	}
}
