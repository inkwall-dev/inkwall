// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzWebSocketOrigin: the Origin header is the client's. Checking it never
// panics, and an origin that passes is one of the allowed ones: its host is
// app.example.com or a subdomain of example.net, over https on port 443.
func FuzzWebSocketOrigin(f *testing.F) {
	for _, s := range []string{"https://app.example.com", "https://a.example.net", "https://example.net", "HTTPS://APP.EXAMPLE.COM:443",
		"https://app.example.com.evil", "https://evil.example.net@x", "https://[::1]", "null", "https://app.example.com:", "https://%61pp.example.com"} {
		f.Add(s)
	}
	rules, err := CompileWebSocket(WebSocketConfig{AllowedOrigins: []string{"https://app.example.com", "https://*.example.net"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, origin string) {
		r := handshake("Sec-WebSocket-Version", "13", "Origin", origin)
		if rules.violation(r) != "" {
			return
		}
		u, err := url.Parse(strings.TrimSpace(origin))
		if err != nil {
			t.Fatalf("%q passed but doesn't parse: %v", origin, err)
		}
		host := strings.ToLower(u.Hostname())
		if !strings.EqualFold(u.Scheme, "https") || (u.Port() != "" && u.Port() != "443") ||
			host != "app.example.com" && (!strings.HasSuffix(host, ".example.net") || len(host) == len(".example.net")) {
			t.Fatalf("%q passed: scheme %q host %q port %q", origin, u.Scheme, host, u.Port())
		}
	})
}
