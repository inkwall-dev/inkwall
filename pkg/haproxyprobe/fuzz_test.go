// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package haproxyprobe

import (
	"strings"
	"testing"
)

// FuzzCheck: whatever a client sends, the engine answers only a probe made
// with the key, and its answer verifies; it keeps a receipt (#475) of
// those only, the one the operator expects; and it takes a request for the
// response leg (#595) only when it is such a probe, whose URI says so.
func FuzzCheck(f *testing.F) {
	uri := PrefixPath("/", "0123456789abcdef0123")
	f.Add(uri, "a.example", Request(key, "0123456789abcdef0123", "a.example", uri))
	f.Add("/", "", "x.y")
	ruri := ResponseURI(uri)
	f.Add(ruri, "a.example", Request(key, "0123456789abcdef0123", "a.example", ruri))
	f.Fuzz(func(t *testing.T, uri, host, header string) {
		answer, ok := Check(key, uri, host, header)
		receipt, kept := Receipt(key, uri, host, header)
		if kept != ok {
			t.Fatalf("Check %v, Receipt %v for %q", ok, kept, header)
		}
		rAnswer, rReceipt, leg := ResponseLeg(key, uri, host, header)
		if leg != (ok && IsResponseURI(uri)) {
			t.Fatalf("ResponseLeg %v for %q, %q", leg, uri, header)
		}
		if !ok {
			return
		}
		nonce, _, _ := strings.Cut(header, ".")
		if header != Request(key, nonce, host, uri) {
			t.Fatalf("accepted header %q for %q", header, uri)
		}
		if !Verify(key, nonce, host, uri, answer) {
			t.Fatal("the answer doesn't verify")
		}
		if receipt != ExpectedReceipt(key, nonce, host, uri) || !ValidReceipt(receipt) {
			t.Fatalf("receipt %q", receipt)
		}
		if leg && (!VerifyResponse(key, nonce, host, uri, rAnswer) || rReceipt != ExpectedResponseReceipt(key, nonce, host, uri) || rReceipt == receipt) {
			t.Fatalf("response leg answer %q, receipt %q", rAnswer, rReceipt)
		}
	})
}
