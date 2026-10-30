// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
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
