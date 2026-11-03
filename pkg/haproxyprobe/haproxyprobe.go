// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package haproxyprobe is the probe the operator sends through HAProxy to
// tell whether a route runs the engine's SPOE filter (0002 §6.4): a GET
// with Header carrying a random nonce and a MAC of the nonce, the host and
// the path under the bundle's probe key. The path is one the route serves:
// PathSuffix under a Prefix path, so the probe reaches no real page of the
// app when the filter isn't there. The SPOE adapter checks the MAC and
// answers with another MAC under the key, which the route's HAProxy rules
// return with Status: only an engine that has the key, behind a route that
// runs the filter, can answer.
package haproxyprobe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const (
	// PathSuffix is the probe's path under a Prefix path, before the
	// nonce: /.well-known/inkwall-probe/<nonce> for the prefix "/".
	PathSuffix = ".well-known/inkwall-probe/"
	// Header carries the request's nonce and MAC ("<nonce>.<mac>"), and the
	// answer's MAC.
	Header = "X-Inkwall-Probe"
	// Status is HAProxy's answer to a probe the engine answered.
	Status = 299
	// KeySize is the size of a probe key.
	KeySize = 32

	minNonce, maxNonce = 16, 64
)

// NewNonce returns a random nonce: 32 base64url characters.
func NewNonce() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// PrefixPath is the probe's path under the Prefix path prefix.
func PrefixPath(prefix, nonce string) string {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + PathSuffix + nonce
}

// Request returns the Header of a probe with nonce to host and uri (path
// and query).
func Request(key []byte, nonce, host, uri string) string {
	return nonce + "." + mac(key, "request", nonce, host, uri)
}

// Check is the engine's side: for a request to uri (path and query) with
// the Host host and the given Header value, it returns the answer to send
// back, and whether the request is a probe made with key.
func Check(key []byte, uri, host, header string) (answer string, ok bool) {
	nonce, sum, found := strings.Cut(header, ".")
	if len(key) == 0 || !found || !validNonce(nonce) {
		return "", false
	}
	if !hmac.Equal([]byte(sum), []byte(mac(key, "request", nonce, host, uri))) {
		return "", false
	}
	return mac(key, "answer", nonce, host, uri), true
}

// Verify is the operator's side: whether answer is the engine's answer to
// the probe with nonce to host and uri.
func Verify(key []byte, nonce, host, uri, answer string) bool {
	if len(key) == 0 || answer == "" {
		return false
	}
	return hmac.Equal([]byte(answer), []byte(mac(key, "answer", nonce, host, uri)))
}

func validNonce(n string) bool {
	if len(n) < minNonce || len(n) > maxNonce {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !nonceByte(n[i]) {
			return false
		}
	}
	return true
}

// nonceByte: base64url's alphabet.
func nonceByte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}

// mac is a hex HMAC-SHA256 of the purpose, nonce, host (lowercased, as
// hosts compare) and URI.
func mac(key []byte, purpose, nonce, host, uri string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("inkwall-haproxy-probe\x00" + purpose + "\x00" + nonce + "\x00" + strings.ToLower(host) + "\x00" + uri))
	return hex.EncodeToString(h.Sum(nil))
}
