// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// FuzzURIPath checks the validation of request targets received from a
// proxy (forward-auth's X-Forwarded-Uri, the check API's raw_uri): an
// accepted target is "*" or in origin form, has no fragment that rules would
// stop reading at, and its path is the one net/url decodes.
func FuzzURIPath(f *testing.F) {
	f.Fuzz(func(t *testing.T, rawURI string) {
		path, err := URIPath(rawURI)
		if err != nil {
			return
		}
		if rawURI == "*" {
			if path != "*" {
				t.Errorf("path of * = %q", path)
			}
			return
		}
		if !strings.HasPrefix(rawURI, "/") || strings.ContainsRune(rawURI, '#') {
			t.Errorf("accepted target %q", rawURI)
		}
		u, err := url.ParseRequestURI(rawURI)
		if err != nil || u.Path != path || u.Host != "" || u.Scheme != "" {
			t.Errorf("target %q: path %q, net/url %+v (%v)", rawURI, path, u, err)
		}
	})
}

// FuzzRequestID checks that a client-supplied request ID, which ends up in
// logs and events, is passed on only if it is a safe correlation ID.
func FuzzRequestID(f *testing.F) {
	f.Fuzz(func(t *testing.T, id string) {
		got := RequestID(id)
		if got == "" {
			return
		}
		if got != id || len(got) > maxRequestIDLen || strings.Trim(got, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-") != "" {
			t.Errorf("RequestID(%q) = %q", id, got)
		}
	})
}

// FuzzGRPCDenial checks the parts of a gRPC denial that come from the
// client: its Content-Type chooses a gRPC answer only for a gRPC media
// type, and its request ID reaches the grpc-message as printable ASCII
// that decodes back to it, so a proxy accepts the header.
func FuzzGRPCDenial(f *testing.F) {
	f.Add("application/grpc-web-text+proto; charset=utf-8", "0123abcd", 403)
	f.Fuzz(func(t *testing.T, contentType, id string, code int) {
		h := http.Header{"Content-Type": {contentType}}
		if g := GRPCOf(h); g != NotGRPC {
			mediaType, _, _ := strings.Cut(contentType, ";")
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(mediaType)), g.ContentType()) {
				t.Errorf("GRPCOf(%q) = %v", contentType, g)
			}
		}
		msg := GRPCMessage(code, id)
		for i := 0; i < len(msg); i++ {
			if msg[i] < 0x20 || msg[i] > 0x7e {
				t.Fatalf("GRPCMessage(%d, %q) = %q", code, id, msg)
			}
		}
		decoded, err := url.PathUnescape(msg)
		if err != nil || !strings.HasSuffix(decoded, " (request ID "+id+")") {
			t.Errorf("GRPCMessage(%d, %q) = %q, decodes to %q (%v)", code, id, msg, decoded, err)
		}
	})
}
