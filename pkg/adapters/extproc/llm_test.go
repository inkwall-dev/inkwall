// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

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

// A streamed answer's usage settles the request's token limit as Envoy
// streams it (mode_override: STREAMED), whether the stream is inspected
// event by event or not: the stream that used 5,000 tokens of a 1,000 an
// hour limit puts the key in debt, so its next request is refused.
func TestLLMStreamUsage(t *testing.T) {
	for _, streams := range []bool{false, true} {
		e := newEnvoy(t, llmtest.TokenSet(t, streams), policy.MaxBodyBytes, io.Discard)
		request := func() []*extprocv3.ProcessingRequest {
			return []*extprocv3.ProcessingRequest{
				withModes(headers("POST", llmtest.Path, false, "content-type", "application/json", "x-api-key", "k1",
					"content-length", strconv.Itoa(len(llmtest.Small))), filterv3.ProcessingMode_BUFFERED, filterv3.ProcessingMode_BUFFERED_PARTIAL),
				body(llmtest.Small, true),
			}
		}
		half := len(llmtest.StreamUsage) / 2
		resps := e.exchange(t, append(request(), respHeaders(200, false, "content-type", "text/event-stream"),
			respBody(llmtest.StreamUsage[:half], false), respBody(llmtest.StreamUsage[half:], true))...)
		if len(resps) != 5 || denied(t, resps[1]) != 0 {
			t.Fatalf("streams %v: answers %v", streams, resps)
		}
		if m := resps[2].GetModeOverride().GetResponseBodyMode(); m != filterv3.ProcessingMode_STREAMED {
			t.Errorf("streams %v: response body mode %v, want STREAMED", streams, m)
		}
		resps = e.exchange(t, request()...)
		if got := denied(t, resps[len(resps)-1]); got != 429 {
			t.Errorf("streams %v: after a stream that used 5,000 tokens: %d, want 429", streams, got)
		}
	}
}
