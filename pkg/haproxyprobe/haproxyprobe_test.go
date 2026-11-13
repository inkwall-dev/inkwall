// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package haproxyprobe

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
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

// A receipt (#475) is the engine's record that it verified a probe, for a
// route whose answer Envoy discards (observability mode): only a probe made
// with the key gets one, it is the operator's expected receipt for that
// nonce, host and URI only, and it can't be made from what the probe's
// request or answer show on the wire.
func TestReceipt(t *testing.T) {
	nonce, _ := NewNonce()
	uri := PrefixPath("/", nonce)
	header := Request(key, nonce, "Shop.Example.com", uri)
	r, ok := Receipt(key, uri, "shop.example.com", header)
	if !ok || !ValidReceipt(r) || len(r) != ReceiptSize {
		t.Fatalf("receipt %q, %v", r, ok)
	}
	if want := ExpectedReceipt(key, nonce, "shop.example.com", uri); r != want {
		t.Fatalf("receipt %q, the operator expects %q", r, want)
	}
	answer, _ := Check(key, uri, "shop.example.com", header)
	if strings.Contains(header, r) || strings.Contains(answer, r) {
		t.Fatal("the receipt is in the request or the answer: whoever sees them could forge it")
	}
	other, _ := NewNonce()
	for name, want := range map[string]string{
		"another nonce": ExpectedReceipt(key, other, "shop.example.com", uri),
		"another host":  ExpectedReceipt(key, nonce, "other.example.com", uri),
		"another URI":   ExpectedReceipt(key, nonce, "shop.example.com", "/login"),
		"another key":   ExpectedReceipt(bytes.Repeat([]byte{8}, KeySize), nonce, "shop.example.com", uri),
	} {
		if r == want {
			t.Errorf("%s: the same receipt", name)
		}
	}
	if ExpectedReceipt(nil, nonce, "shop.example.com", uri) != "" {
		t.Error("a receipt without a key")
	}
	if _, ok := Receipt(key, uri, "shop.example.com", nonce+".00"); ok {
		t.Error("a receipt for a probe with a wrong MAC")
	}
	if _, ok := Receipt(nil, uri, "shop.example.com", header); ok {
		t.Error("a receipt without a key")
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("g", ReceiptSize), strings.Repeat("A", ReceiptSize), r + "0"} {
		if ValidReceipt(bad) {
			t.Errorf("ValidReceipt(%q)", bad)
		}
	}
}

// The engine keeps the receipts of recent probes only: at most
// MaxReceipts, the newest, none older than ReceiptAge; and once each.
func TestReceipts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rs := &Receipts{Now: func() time.Time { return now }}
	receipt := func(i int) string { return fmt.Sprintf("%032x", i) }
	for i := range MaxReceipts + 3 {
		rs.Add(receipt(i))
	}
	rs.Add(receipt(MaxReceipts + 2))
	got := rs.Recent()
	if len(got) != MaxReceipts || got[0] != receipt(3) || got[len(got)-1] != receipt(MaxReceipts+2) {
		t.Fatalf("recent: %v", got)
	}
	now = now.Add(ReceiptAge / 2)
	rs.Add(receipt(100))
	now = now.Add(ReceiptAge/2 + time.Second)
	if got := rs.Recent(); len(got) != 1 || got[0] != receipt(100) {
		t.Fatalf("after ReceiptAge: %v", got)
	}
	rs.Add("not a receipt")
	if got := rs.Recent(); len(got) != 1 {
		t.Fatalf("kept a malformed receipt: %v", got)
	}
	var none *Receipts
	none.Add(receipt(1))
	if none.Recent() != nil {
		t.Fatal("a nil Receipts kept a receipt")
	}
}
