// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/iplist"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// TestIPLists (#358): a denied client is denied (logged in detect mode)
// before the rules and skip paths; an allowed one skips inspection; deny
// wins over allow; others are inspected as usual.
func TestIPLists(t *testing.T) {
	allow, err := iplist.Parse([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	deny, err := iplist.Parse([]string{"203.0.113.0/24", "10.6.6.6", "2001:db8:bad::/48"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []Mode{ModeBlock, ModeDetect} {
		eval := &recordingEvaluator{res: blocked}
		p := New(eval, Config{Mode: mode, IPAllow: allow, IPDeny: deny})
		for _, tc := range []struct {
			client string
			action Action
			reason Reason
			eval   bool
		}{
			{"203.0.113.9", ActionDeny, ReasonIPDeny, false},
			{"10.6.6.6", ActionDeny, ReasonIPDeny, false}, // deny wins over allow
			{"2001:db8:bad::1", ActionDeny, ReasonIPDeny, false},
			{"::ffff:203.0.113.9", ActionDeny, ReasonIPDeny, false},
			{"10.1.2.3", ActionAllow, ReasonIPAllow, false},
			{"2001:db8::1", ActionAllow, ReasonIPAllow, false},
			{"198.51.100.7", ActionDeny, ReasonRule, true},
		} {
			eval.got = nil
			r := &request.Request{Method: http.MethodGet, RawURI: "/x", ClientIP: netip.MustParseAddr(tc.client)}
			v := p.Check(context.Background(), r)
			want := tc.action
			if mode == ModeDetect && want == ActionDeny {
				want = ActionLog
			}
			if v.Action != want || v.Reason != tc.reason || (eval.got != nil) != tc.eval {
				t.Errorf("mode %d, %s: %s/%s (evaluated %v), want %s/%s (evaluated %v)", mode, tc.client, v.Action, v.Reason, eval.got != nil, want, tc.reason, tc.eval)
			}
			if v.Action == ActionDeny && v.Status != http.StatusForbidden {
				t.Errorf("%s: status %d", tc.client, v.Status)
			}
			listed := tc.reason == ReasonIPAllow || tc.reason == ReasonIPDeny
			if got := p.BodyLimit(r, 100); (got == 0) != listed {
				t.Errorf("mode %d, %s: body limit %d", mode, tc.client, got)
			}
		}
	}
	if ReasonIPAllow.String() != "ip-allow" || ReasonIPDeny.String() != "ip-deny" {
		t.Errorf("reasons %q %q", ReasonIPAllow, ReasonIPDeny)
	}
}
