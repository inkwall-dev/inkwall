// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// WebSocketHandshake reports whether r looks like the opening handshake of a
// WebSocket (RFC 6455 §4.1, or RFC 8441 over HTTP/2): an Upgrade header
// naming websocket, or a Sec-WebSocket-Key or Sec-WebSocket-Version header.
// Any one is enough, because proxies drop some: Traefik's ForwardAuth
// removes Upgrade and Connection (hop-by-hop headers) before asking the
// engine, and a WebSocket over HTTP/2 has no Sec-WebSocket-Key. A server
// doesn't upgrade a handshake without Sec-WebSocket-Version, so a real one
// can't hide from this check; a request that only looks like one gets the
// policy's WebSocket rules too, which is the safe side.
func WebSocketHandshake(r *request.Request) bool {
	if len(r.Headers.Values("Sec-Websocket-Key")) > 0 || len(r.Headers.Values("Sec-Websocket-Version")) > 0 {
		return true
	}
	return httpguts.HeaderValuesContainsToken(r.Headers.Values("Upgrade"), "websocket")
}

// WebSocketConfig is what a policy requires of a WebSocket handshake. A
// handshake that doesn't meet it is denied with 403 in block mode (logged
// in detect mode), with ReasonWebSocket, before the rules run. Requests
// that aren't handshakes aren't affected.
type WebSocketConfig struct {
	// AllowedOrigins are the origins a handshake may come from, as
	// "scheme://host" or "scheme://host:port" (http or https). A host may
	// start with "*.": it then matches any subdomain of the rest, at any
	// depth, not the rest itself. Empty: any origin.
	AllowedOrigins []string
	// AllowMissingOrigin lets a handshake without an Origin header through
	// the origin check. Browsers always send one; other clients may not.
	AllowMissingOrigin bool
	// RequiredHeaders are headers a handshake must have, not empty.
	RequiredHeaders []string
}

// WebSocketRules is a compiled WebSocketConfig, for Config.WebSocket.
type WebSocketRules struct {
	exact     map[string]bool // "scheme://host:port"
	suffixes  []originSuffix
	anyOrigin bool
	missingOK bool
	required  []string
}

type originSuffix struct {
	scheme, suffix, port string // suffix: ".example.com"
}

// CompileWebSocket checks and compiles cfg. It returns nil when cfg
// requires nothing.
func CompileWebSocket(cfg WebSocketConfig) (*WebSocketRules, error) {
	if len(cfg.AllowedOrigins) == 0 && len(cfg.RequiredHeaders) == 0 {
		return nil, nil
	}
	w := &WebSocketRules{exact: map[string]bool{}, anyOrigin: len(cfg.AllowedOrigins) == 0, missingOK: cfg.AllowMissingOrigin}
	for _, o := range cfg.AllowedOrigins {
		scheme, host, port, err := splitOrigin(o, true)
		if err != nil {
			return nil, fmt.Errorf("allowed origin %q: %w", o, err)
		}
		if rest, ok := strings.CutPrefix(host, "*"); ok {
			w.suffixes = append(w.suffixes, originSuffix{scheme: scheme, suffix: rest, port: port})
			continue
		}
		w.exact[scheme+"://"+host+":"+port] = true
	}
	for _, name := range cfg.RequiredHeaders {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("required header %q is not a header name", name)
		}
		w.required = append(w.required, http.CanonicalHeaderKey(name))
	}
	return w, nil
}

// splitOrigin parses an origin, "scheme://host[:port]", into its lower-case
// scheme and host and its port, the scheme's default when it has none. A
// pattern's host may start with "*.".
func splitOrigin(origin string, pattern bool) (scheme, host, port string, err error) {
	scheme, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return "", "", "", fmt.Errorf("not scheme://host")
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	default:
		return "", "", "", fmt.Errorf("scheme %q is not http or https", scheme)
	}
	if rest == "" || strings.ContainsAny(rest, "/?#@\\ ") {
		return "", "", "", fmt.Errorf("not scheme://host[:port]")
	}
	u, err := url.Parse("http://" + rest)
	if err != nil {
		return "", "", "", err
	}
	host = strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" {
		port = p
	} else if strings.HasSuffix(rest, ":") {
		return "", "", "", fmt.Errorf("empty port")
	}
	check := host
	if pattern {
		if after, ok := strings.CutPrefix(host, "*."); ok {
			check = after
		}
	}
	if check == "" || strings.Contains(check, "*") || !httpguts.ValidHostHeader(check) {
		return "", "", "", fmt.Errorf("invalid host %q", host)
	}
	return scheme, host, port, nil
}

// violation returns why handshake r doesn't meet the rules, "" when it does.
func (w *WebSocketRules) violation(r *request.Request) string {
	for _, name := range w.required {
		if strings.TrimSpace(r.Headers.Get(name)) == "" {
			return "missing required header " + name
		}
	}
	if w.anyOrigin {
		return ""
	}
	origins := r.Headers.Values("Origin")
	switch len(origins) {
	case 0:
		if w.missingOK {
			return ""
		}
		return "no Origin"
	case 1:
	default:
		return "several Origin headers"
	}
	scheme, host, port, err := splitOrigin(strings.TrimSpace(origins[0]), false)
	if err != nil {
		return "Origin not allowed"
	}
	if w.exact[scheme+"://"+host+":"+port] {
		return ""
	}
	for _, s := range w.suffixes {
		if s.scheme == scheme && s.port == port && len(host) > len(s.suffix) && strings.HasSuffix(host, s.suffix) {
			return ""
		}
	}
	return "Origin not allowed"
}
