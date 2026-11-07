// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

// checkRequests checks what inkwallctl test sends the engine: requests
// that encode (protobuf strings must be valid UTF-8), in http or https, with
// a request target in origin form ("*" aside), without the Host header.
// URLs (HAR) lose their fragment; a raw request target is sent as written,
// a raw '#' included, and the engine rejects it.
func checkRequests(t *testing.T, reqs []*enginev1.CheckRequest, fragments bool) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatal("no requests and no error")
	}
	for _, in := range reqs {
		// raw_uri and authority have no raw form: a raw request whose
		// target or Host isn't UTF-8 can't be sent, and inkwallctl says so.
		if _, err := proto.Marshal(in); err != nil && utf8.ValidString(in.GetRawUri()) && utf8.ValidString(in.GetAuthority()) {
			t.Errorf("request %v doesn't encode: %v", in, err)
		}
		if s := in.GetScheme(); s != "http" && s != "https" {
			t.Errorf("scheme %q", s)
		}
		if u := in.GetRawUri(); u != "*" && !strings.HasPrefix(u, "/") || !fragments && strings.ContainsRune(u, '#') {
			t.Errorf("request target %q", u)
		}
		for _, h := range in.GetHeaders() {
			if strings.EqualFold(h.GetName(), "Host") {
				t.Errorf("Host header %q: the authority goes in its own field", h.GetValue())
			}
		}
	}
}

// FuzzSplitURL splits arbitrary URLs: an accepted one is http or https, and
// its request target is in origin form, without the fragment, and exactly
// as written.
func FuzzSplitURL(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw string) {
		scheme, authority, rawURI, err := splitURL(raw)
		if err != nil {
			return
		}
		if scheme != "http" && scheme != "https" {
			t.Errorf("%q: scheme %q", raw, scheme)
		}
		if !strings.HasPrefix(rawURI, "/") || strings.ContainsRune(rawURI, '#') || strings.ContainsAny(authority, "/?#") {
			t.Errorf("%q: authority %q, request target %q", raw, authority, rawURI)
		}
		rest := raw[len(scheme)+len("://"):]
		rest, _, _ = strings.Cut(rest, "#")
		if rest != authority+rawURI && rest != authority+rawURI[1:] {
			t.Errorf("%q: authority %q, request target %q, not as written", raw, authority, rawURI)
		}
	})
}

// FuzzFromRawHTTP reads arbitrary raw HTTP requests, as from --request-file.
func FuzzFromRawHTTP(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte) {
		reqs, err := fromRawHTTP(bytes.NewReader(raw))
		if err != nil {
			return
		}
		checkRequests(t, reqs, true)
	})
}

// FuzzFromHAR reads arbitrary HAR files, as from --har.
func FuzzFromHAR(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte) {
		reqs, err := fromHAR(raw)
		if err != nil {
			return
		}
		checkRequests(t, reqs, false)
		for _, in := range reqs {
			for _, h := range in.GetHeaders() {
				if strings.HasPrefix(h.GetName(), ":") {
					t.Errorf("pseudo-header %q", h.GetName())
				}
			}
		}
	})
}

// FuzzParseSuite reads arbitrary suite files, as from --suite: an accepted
// suite has cases with distinct names, and its inline requests are ones
// inkwallctl test can send.
func FuzzParseSuite(f *testing.F) {
	f.Add([]byte("cases:\n  - name: a\n    request: {uri: /, host: a.example, headers: {X-A: b}}\n    expect: {action: allow}\n"))
	f.Add([]byte("policy: [p.yaml]\ncases:\n  - name: a\n    request: {url: \"http://a/?q=1' OR '1'='1\", method: POST, body: x=1}\n    response: {status: 500, headers: {Content-Type: text/html}, body: err}\n    expect: {action: deny, status: 403, rules: [942100], notRules: [1], phase: response}\n"))
	f.Add([]byte("cases:\n  - name: a\n    request: {file: r.http, clientIP: 192.0.2.1}\n    expect: {exactRules: [1, 2], policy: a/b}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := parseSuite(raw, ".")
		if err != nil {
			return
		}
		names := map[string]bool{}
		for _, c := range s.Cases {
			if c.Name == "" || names[c.Name] {
				t.Errorf("case name %q empty or repeated", c.Name)
			}
			names[c.Name] = true
			if c.Request.File != "" {
				continue
			}
			in, err := inlineRequest(c.Request)
			if err != nil {
				continue
			}
			checkRequests(t, []*enginev1.CheckRequest{in}, true)
		}
	})
}
