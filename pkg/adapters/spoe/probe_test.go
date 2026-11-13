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
	// A MAC that differs from the right one in every run: the last hex
	// digit changed, never replaced by a fixed value it may already have.
	last := "0"
	if mac[len(mac)-1] == '0' {
		last = "1"
	}
	wrong := mac[:len(mac)-1] + last
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
		{"wrong MAC", key, wrong, false, true},
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

// The probe's response leg (#595): where the request's response is kept,
// the agent lets the probe through (no probe variable, no deny) and answers
// its response, uninspected, with VarResponseProbe, which the route's
// response rules return with status 299; in Block and Detect mode alike,
// as HAProxy waits for both answers. Where it isn't kept (no
// --response-messages, the backend's responses=false, a policy that
// doesn't inspect responses), the request phase answers it as the request
// leg, as an engine before #595 does.
func TestProbeResponseLeg(t *testing.T) {
	key := bytes.Repeat([]byte{1}, haproxyprobe.KeySize)
	nonce, err := haproxyprobe.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	path := haproxyprobe.ResponseURI(haproxyprobe.PrefixPath("/", nonce))
	mac := haproxyprobe.Request(key, nonce, "shop.example.com", path)
	probe := func(extra ...func(*encoder)) []byte {
		return notifyFrame(1, 1, append([]func(*encoder){argString(ArgMethod, "GET"), argString(ArgPath, path),
			argBinary(ArgHeaders, hdrs("host", "shop.example.com", "user-agent", "test/1.0", "accept", "*/*", "x-inkwall-probe", mac))}, extra...)...)
	}
	for _, mode := range []pipeline.Mode{pipeline.ModeBlock, pipeline.ModeDetect} {
		t.Run(string(mode), func(t *testing.T) {
			a := startAgent(t, responsePipeline(t, mode), Config{Responses: true, ProbeKey: func() []byte { return key }})
			h := a.dial(t)
			h.hello()
			h.send(probe())
			_, vars := h.ack()
			if has(vars, VarProbe) || vars[VarAction].String() != ActionAllow || !has(vars, VarResponses) {
				t.Fatalf("request phase: %+v, want it let through and kept", vars)
			}
			vars = h.respond(2, response(vars[VarResponses].String(), vars[VarResponseFailure].String(), 404, "text/html", sqlError)...)
			if vars[VarResponseAction].String() != ActionAllow || !haproxyprobe.VerifyResponse(key, nonce, "shop.example.com", path, vars[VarResponseProbe].String()) {
				t.Fatalf("response phase: %+v, want the response leg's answer", vars)
			}
		})
	}
	for name, c := range map[string]struct {
		p     pipeline.Inspector
		cfg   bool
		extra []func(*encoder)
	}{
		"no --response-messages": {responsePipeline(t, pipeline.ModeBlock), false, nil},
		"responses=false":        {responsePipeline(t, pipeline.ModeBlock), true, []func(*encoder){argBool(ArgResponses, false)}},
		"policy without":         {&inspector{verdict: pipeline.Verdict{Action: pipeline.ActionAllow}}, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			a := startAgent(t, c.p, Config{Responses: c.cfg, ProbeKey: func() []byte { return key }})
			h := a.dial(t)
			h.hello()
			h.send(probe(c.extra...))
			_, vars := h.ack()
			if !haproxyprobe.Verify(key, nonce, "shop.example.com", path, vars[VarProbe].String()) || vars[VarAction].String() != ActionDeny || has(vars, VarResponses) {
				t.Fatalf("%+v, want the request leg's answer", vars)
			}
		})
	}
}
