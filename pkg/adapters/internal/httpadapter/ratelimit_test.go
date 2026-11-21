// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		v    pipeline.Verdict
		want string
	}{
		{pipeline.Verdict{Status: http.StatusTooManyRequests, RetryAfter: 6 * time.Second}, "6"},
		{pipeline.Verdict{Status: http.StatusTooManyRequests, RetryAfter: 1500 * time.Millisecond}, "2"},
		{pipeline.Verdict{Status: http.StatusTooManyRequests}, ""},
		// Only a 429 carries it: a rule's 403 never does.
		{pipeline.Verdict{Status: http.StatusForbidden, RetryAfter: time.Second}, ""},
	} {
		if got := RetryAfter(tc.v); got != tc.want {
			t.Errorf("RetryAfter(%d, %v) = %q, want %q", tc.v.Status, tc.v.RetryAfter, got, tc.want)
		}
	}
	h := http.Header{}
	SetRetryAfter(h, pipeline.Verdict{Status: http.StatusTooManyRequests, RetryAfter: 30 * time.Second})
	if h.Get("Retry-After") != "30" {
		t.Errorf("SetRetryAfter: %q", h.Get("Retry-After"))
	}
}

// A limited request is an event only when the pipeline sampled it.
func TestIsEventRateLimit(t *testing.T) {
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 429, Reason: pipeline.ReasonRateLimit}
	if IsEvent(v) {
		t.Error("an unsampled limited request is an event")
	}
	v.SampledEvent = true
	if !IsEvent(v) {
		t.Error("a sampled limited request isn't an event")
	}
}
