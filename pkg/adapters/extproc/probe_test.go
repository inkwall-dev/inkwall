// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/test/bufconn"

	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// The operator's probe (#372): a request whose X-Inkwall-Probe header has
// a valid MAC under the bundle's probe key is answered by the engine
// itself, uninspected and never forwarded, with the answer's MAC; one with
// a wrong MAC, or without a key, is an ordinary request.
func TestProbe(t *testing.T) {
	key := bytes.Repeat([]byte{7}, haproxyprobe.KeySize)
	var logs bytes.Buffer
	var current []byte
	s, err := New(newPipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: 64 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		ProbeKey: func() []byte { return current }})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })

	nonce, _ := haproxyprobe.NewNonce()
	uri := "/" + haproxyprobe.PathSuffix + nonce
	probe := func(header string) []string {
		resps := e.exchange(t, headers("GET", uri, true, haproxyprobe.Header, header))
		if len(resps) != 1 {
			t.Fatalf("%d answers", len(resps))
		}
		ir := resps[0].GetImmediateResponse()
		if ir == nil {
			return nil
		}
		var answer []string
		for _, h := range ir.GetHeaders().GetSetHeaders() {
			if strings.EqualFold(h.GetHeader().GetKey(), haproxyprobe.Header) {
				answer = append(answer, string(h.GetHeader().GetRawValue()))
			}
		}
		return answer
	}
	valid := haproxyprobe.Request(key, nonce, "shop.example.com", uri)

	// No key yet: an ordinary request.
	if a := probe(valid); a != nil {
		t.Errorf("without a key: answered %v", a)
	}
	current = key
	a := probe(valid)
	if len(a) != 1 || !haproxyprobe.Verify(key, nonce, "shop.example.com", uri, a[0]) {
		t.Fatalf("probe: answer %v, want the engine's MAC", a)
	}
	if a := probe(haproxyprobe.Request(bytes.Repeat([]byte{8}, haproxyprobe.KeySize), nonce, "shop.example.com", uri)); a != nil {
		t.Errorf("another key's probe answered %v", a)
	}
	if logs.Len() != 0 {
		t.Errorf("a probe was logged as an event: %s", logs.String())
	}
}

// In observability mode (a Detect-mode route) Envoy discards the engine's
// answer, so the engine keeps a receipt of the probe instead (#475), and
// inspects the request as any other, as Envoy forwards it to the app. A
// probe with a wrong MAC, another key's, or one made for another host or
// URI gets no receipt; a probe answered in Block mode needs none.
func TestProbeReceipt(t *testing.T) {
	key := bytes.Repeat([]byte{7}, haproxyprobe.KeySize)
	var logs bytes.Buffer
	receipts := &haproxyprobe.Receipts{}
	s, err := New(newPipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: 64 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		ProbeKey: func() []byte { return key }, ProbeReceipts: receipts})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })

	nonce, _ := haproxyprobe.NewNonce()
	uri := "/" + haproxyprobe.PathSuffix + nonce
	valid := haproxyprobe.Request(key, nonce, "shop.example.com", uri)
	want := haproxyprobe.ExpectedReceipt(key, nonce, "shop.example.com", uri)

	// Block mode: answered, no receipt.
	e.exchange(t, headers("GET", uri, true, haproxyprobe.Header, valid))
	if got := receipts.Recent(); got != nil {
		t.Fatalf("a receipt in Block mode: %v", got)
	}
	e.observe(t, headers("GET", uri, true, haproxyprobe.Header, haproxyprobe.Request(bytes.Repeat([]byte{8}, haproxyprobe.KeySize), nonce, "shop.example.com", uri)))
	e.observe(t, headers("GET", uri, true, haproxyprobe.Header, nonce+".00"))
	e.observe(t, headers("GET", "/login", true, haproxyprobe.Header, valid))
	if got := receipts.Recent(); got != nil {
		t.Fatalf("a receipt of a forged probe: %v", got)
	}
	e.observe(t, headers("GET", uri, true, haproxyprobe.Header, valid))
	if got := receipts.Recent(); len(got) != 1 || got[0] != want {
		t.Fatalf("receipts %v, want [%s]", got, want)
	}
	if logs.Len() != 0 {
		t.Errorf("a probe was logged as an event: %s", logs.String())
	}
	// Inspected as any request: an attack in it is logged.
	attack := uri + "?q=<script>alert(1)</script>"
	e.observe(t, headers("GET", attack, true, haproxyprobe.Header, haproxyprobe.Request(key, nonce, "shop.example.com", attack)))
	if !strings.Contains(logs.String(), `"security event"`) {
		t.Errorf("a probe with an attack wasn't logged in observability mode: %q", logs.String())
	}
}
