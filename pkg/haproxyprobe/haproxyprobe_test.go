// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package haproxyprobe

import (
	"bytes"
	"strings"
	"testing"
)

var key = bytes.Repeat([]byte{7}, KeySize)

func TestRoundTrip(t *testing.T) {
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	uri := PrefixPath("/", nonce)
	if uri != "/.well-known/inkwall-probe/"+nonce || PrefixPath("/api", nonce) != "/api/.well-known/inkwall-probe/"+nonce {
		t.Fatalf("paths %q, %q", uri, PrefixPath("/api", nonce))
	}
	header := Request(key, nonce, "Shop.Example.com", uri)
	answer, ok := Check(key, uri, "shop.example.com", header)
	if !ok {
		t.Fatal("the engine refused the operator's probe")
	}
	if !Verify(key, nonce, "shop.example.com", uri, answer) {
		t.Fatal("the operator refused the engine's answer")
	}
	if strings.Contains(header, answer) {
		t.Fatal("the answer is in the request: whoever sees the request could forge it")
	}
}

func TestCheckRefuses(t *testing.T) {
	nonce, _ := NewNonce()
	uri := PrefixPath("/", nonce)
	header := Request(key, nonce, "a.example", uri)
	other := bytes.Repeat([]byte{8}, KeySize)
	for name, c := range map[string]struct {
		key               []byte
		uri, host, header string
	}{
		"no key":      {nil, uri, "a.example", header},
		"other key":   {other, uri, "a.example", header},
		"other host":  {key, uri, "b.example", header},
		"other path":  {key, "/login", "a.example", header},
		"no header":   {key, uri, "a.example", ""},
		"no MAC":      {key, uri, "a.example", nonce},
		"bad MAC":     {key, uri, "a.example", nonce + ".00"},
		"short nonce": {key, uri, "a.example", "abc." + strings.SplitN(header, ".", 2)[1]},
		"bad nonce":   {key, uri, "a.example", "/" + header[1:]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := Check(c.key, c.uri, c.host, c.header); ok {
				t.Fatal("accepted")
			}
		})
	}
	if Verify(key, nonce, "a.example", uri, "") || Verify(nil, nonce, "a.example", uri, header) {
		t.Fatal("Verify accepted an empty answer or no key")
	}
}
