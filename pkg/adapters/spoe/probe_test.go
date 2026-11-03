// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// The operator's probe is answered with the probe variable, uninspected;
// one without a valid MAC is inspected as any other, and so is every request when the engine has no probe key.
func TestProbe(t *testing.T) {
	key := bytes.Repeat([]byte{1}, haproxyprobe.KeySize)
	nonce, err := haproxyprobe.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	path := haproxyprobe.PrefixPath("/", nonce)
	mac := haproxyprobe.Request(key, nonce, "shop.example.com", path)
	probe := func(header string) []byte {
		return notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, path),
			argBinary(ArgHeaders, hdrs("host", "shop.example.com", "x-inkwall-probe", header)))
	}
	for _, c := range []struct {
		name      string
		key       []byte
		header    string
		answered  bool
		inspected bool
	}{
		{"probe", key, mac, true, false},
		{"wrong MAC", key, mac[:len(mac)-2] + "00", false, true},
		{"no key", nil, mac, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			insp := &inspector{verdict: pipeline.Verdict{Action: pipeline.ActionAllow}}
			k := c.key
			a := startAgent(t, insp, Config{MaxBodyBytes: 1 << 10, ProbeKey: func() []byte { return k }})
			h := a.dial(t)
			h.hello()
			h.send(probe(c.header))
			_, vars := h.ack()
			got, ok := vars[VarProbe]
			if ok != c.answered {
				t.Fatalf("probe variable %v, want %v: %+v", ok, c.answered, vars)
			}
			if c.answered {
				if !haproxyprobe.Verify(key, nonce, "shop.example.com", path, got.String()) {
					t.Errorf("answer %q doesn't verify", got.String())
				}
				// Denied as well, so a rule set without the probe's
				// return rule doesn't pass it to the app.
				if vars[VarAction].String() != ActionDeny || vars[VarStatus].u != http.StatusForbidden {
					t.Errorf("variables %+v", vars)
				}
			}
			if n := len(insp.requests()); (n > 0) != c.inspected {
				t.Errorf("inspected %d requests", n)
			}
		})
	}
}
