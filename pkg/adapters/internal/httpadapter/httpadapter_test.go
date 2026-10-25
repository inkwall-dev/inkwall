// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func TestRequestID(t *testing.T) {
	for id, want := range map[string]string{
		"":                       "",
		"abc-123_DEF.4:5":        "abc-123_DEF.4:5",
		"has space":              "",
		"inject\nnewline":        "",
		"<script>":               "",
		strings.Repeat("a", 128): strings.Repeat("a", 128),
		strings.Repeat("a", 129): "",
	} {
		if got := RequestID(id); got != want {
			t.Errorf("RequestID(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestIsEvent(t *testing.T) {
	for _, tc := range []struct {
		v    pipeline.Verdict
		want bool
	}{
		{pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule}, true},
		{pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonRule}, true},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonTimeout}, true},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonOverload}, true},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNone}, false},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonSkipped}, false},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonCanceled}, false},
		// Uninspected by configuration: counted, not logged per request.
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonNoPolicy}, false},
		{pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonSuspended}, false},
	} {
		if got := IsEvent(tc.v); got != tc.want {
			t.Errorf("%s/%s: IsEvent = %v, want %v", tc.v.Action, tc.v.Reason, got, tc.want)
		}
	}
}
