// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// TestDenyGRPC (#367): with DenyGRPC, a request with a gRPC or gRPC-Web
// content type is denied (logged in detect mode) before the rules, body or
// not; other content types, and routes the policy skips, are unaffected.
func TestDenyGRPC(t *testing.T) {
	req := func(ct string) *request.Request {
		h := http.Header{}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		return &request.Request{Method: http.MethodPost, RawURI: "/svc.Echo/Say", Headers: h, Body: []byte{0, 0, 0, 0, 1, 'x'}}
	}
	for _, mode := range []Mode{ModeBlock, ModeDetect} {
		eval := &recordingEvaluator{}
		p := New(eval, Config{Mode: mode, DenyGRPC: true})
		for _, tc := range []struct {
			ct     string
			denied bool
		}{
			{"application/grpc", true},
			{"application/grpc+proto", true},
			{"Application/GRPC; charset=utf-8", true},
			{"application/grpc+json", true},
			{"application/grpc-web", true},
			{"application/grpc-web-text+proto", true},
			{"application/json", false},
			{"", false},
		} {
			eval.got = nil
			r := req(tc.ct)
			v := p.Check(context.Background(), r)
			want := ActionAllow
			if tc.denied {
				want = ActionDeny
				if mode == ModeDetect {
					want = ActionLog
				}
			}
			if v.Action != want || tc.denied && (v.Reason != ReasonGRPC || mode == ModeBlock && v.Status != http.StatusForbidden) {
				t.Errorf("mode %d, %q: %s/%s %d, want %s/grpc", mode, tc.ct, v.Action, v.Reason, v.Status, want)
			}
			// Block mode denies without running the rules or reading
			// the body; detect mode still runs them.
			if tc.denied && mode == ModeBlock && (eval.got != nil || p.BodyLimit(r, 100) != 0) {
				t.Errorf("%q: evaluated or body read in block mode", tc.ct)
			}
		}
	}
	// Allow (the default) changes nothing.
	p := New(&recordingEvaluator{}, Config{Mode: ModeBlock})
	if v := p.Check(context.Background(), req("application/grpc")); v.Reason == ReasonGRPC {
		t.Errorf("without DenyGRPC: %s/%s", v.Action, v.Reason)
	}
	if ReasonGRPC.String() != "grpc" {
		t.Errorf("reason %q", ReasonGRPC)
	}
}
