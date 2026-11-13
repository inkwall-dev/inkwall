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
//
// Where the proxy discards the engine's answer (Envoy's ext_proc in
// observability mode, a Detect-mode route through Istio), the engine keeps
// a Receipt of each probe it verified instead, and reports its recent
// ones to the operator (#475): another MAC under the key, which the
// operator expects for the probe's nonce, host and URI, and which neither
// the request nor an answer shows.
package haproxyprobe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"time"
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

	// ReceiptSize is the length of a receipt: 32 hex digits, an
	// HMAC-SHA256 cut to 128 bits.
	ReceiptSize = 32
	// MaxReceipts bounds the receipts an engine keeps, and reports: the
	// newest.
	MaxReceipts = 16
	// ReceiptAge is how long an engine keeps a receipt.
	ReceiptAge = time.Minute
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
	nonce, ok := verified(key, uri, host, header)
	if !ok {
		return "", false
	}
	return mac(key, "answer", nonce, host, uri), true
}

// Receipt is the engine's side where its answer is discarded: for a
// request as Check takes it, the receipt to keep, and whether the request
// is a probe made with key.
func Receipt(key []byte, uri, host, header string) (receipt string, ok bool) {
	nonce, ok := verified(key, uri, host, header)
	if !ok {
		return "", false
	}
	return ExpectedReceipt(key, nonce, host, uri), true
}

// ExpectedReceipt is the operator's side: the receipt of the probe with
// nonce to host and uri; "" without a key.
func ExpectedReceipt(key []byte, nonce, host, uri string) string {
	if len(key) == 0 {
		return ""
	}
	return mac(key, "receipt", nonce, host, uri)[:ReceiptSize]
}

// ValidReceipt reports whether r has a receipt's form: ReceiptSize
// lowercase hex digits.
func ValidReceipt(r string) bool {
	if len(r) != ReceiptSize {
		return false
	}
	for i := 0; i < len(r); i++ {
		if c := r[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// verified returns the nonce of a probe made with key, and whether header
// is one for uri and host.
func verified(key []byte, uri, host, header string) (string, bool) {
	nonce, sum, found := strings.Cut(header, ".")
	if len(key) == 0 || !found || !validNonce(nonce) {
		return "", false
	}
	if !hmac.Equal([]byte(sum), []byte(mac(key, "request", nonce, host, uri))) {
		return "", false
	}
	return nonce, true
}

// Receipts are the receipts an engine keeps: at most MaxReceipts, the
// newest, none older than ReceiptAge, each once. The zero value is ready;
// a nil one keeps none.
type Receipts struct {
	// Now is the clock; nil: time.Now.
	Now func() time.Time

	mu   sync.Mutex
	list []stamped
}

type stamped struct {
	receipt string
	at      time.Time
}

func (r *Receipts) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Add keeps a receipt; a malformed one is ignored.
func (r *Receipts) Add(receipt string) {
	if r == nil || !ValidReceipt(receipt) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if slices.ContainsFunc(r.list, func(s stamped) bool { return s.receipt == receipt }) {
		return
	}
	if len(r.list) == MaxReceipts {
		r.list = slices.Delete(r.list, 0, 1)
	}
	r.list = append(r.list, stamped{receipt: receipt, at: r.now()})
}

// Recent returns the receipts kept, oldest first.
func (r *Receipts) Recent() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if len(r.list) == 0 {
		return nil
	}
	out := make([]string, len(r.list))
	for i, s := range r.list {
		out[i] = s.receipt
	}
	return out
}

func (r *Receipts) prune() {
	now := r.now()
	r.list = slices.DeleteFunc(r.list, func(s stamped) bool { return now.Sub(s.at) >= ReceiptAge })
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
