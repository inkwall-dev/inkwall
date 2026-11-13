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

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
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

// The probe's response leg (#595): on a route whose policy inspects
// responses, the engine lets the probe through to the app and answers its
// response (Block mode: Envoy waits), or keeps a receipt of it
// (observability mode), with the response leg's MACs; the request phase
// keeps no request receipt for it. Where the response isn't kept (the
// policy doesn't inspect responses), the engine answers at the request
// phase, as an engine before #595 does, so the operator can tell.
func TestProbeResponseLeg(t *testing.T) {
	key := bytes.Repeat([]byte{7}, haproxyprobe.KeySize)
	nonce, _ := haproxyprobe.NewNonce()
	uri := haproxyprobe.ResponseURI("/" + haproxyprobe.PathSuffix + nonce)
	valid := haproxyprobe.Request(key, nonce, "shop.example.com", uri)
	start := func(t *testing.T, p pipeline.Inspector, receipts *haproxyprobe.Receipts, logs *bytes.Buffer) *envoy {
		s, err := New(p, Config{MaxBodyBytes: 64 << 10, Logger: slog.New(slog.NewJSONHandler(logs, nil)),
			ProbeKey: func() []byte { return key }, ProbeReceipts: receipts})
		if err != nil {
			t.Fatal(err)
		}
		ln := bufconn.Listen(1 << 20)
		return startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })
	}
	probeHeader := func(ir *extprocv3.ImmediateResponse) string {
		for _, h := range ir.GetHeaders().GetSetHeaders() {
			if strings.EqualFold(h.GetHeader().GetKey(), haproxyprobe.Header) {
				return string(h.GetHeader().GetRawValue())
			}
		}
		return ""
	}

	t.Run("block", func(t *testing.T) {
		var logs bytes.Buffer
		receipts := &haproxyprobe.Receipts{}
		e := start(t, newResponsePipeline(t, pipeline.ModeBlock, 1024, pipeline.OversizeAuto), receipts, &logs)
		resps := e.exchange(t, withModes(headers("GET", uri, true, haproxyprobe.Header, valid), filterv3.ProcessingMode_NONE, filterv3.ProcessingMode_BUFFERED_PARTIAL),
			respHeaders(404, false, "content-type", "text/html"), respBody("not found", true))
		if len(resps) != 2 || resps[0].GetImmediateResponse() != nil {
			t.Fatalf("the request phase answered: %v", resps)
		}
		ir := resps[1].GetImmediateResponse()
		if ir == nil || ir.GetStatus().GetCode() != 200 || !haproxyprobe.VerifyResponse(key, nonce, "shop.example.com", uri, probeHeader(ir)) {
			t.Fatalf("response phase: %v, want the response leg's answer", resps[1])
		}
		if got := receipts.Recent(); got != nil {
			t.Errorf("receipts in Block mode: %v", got)
		}
		if logs.Len() != 0 {
			t.Errorf("logged: %s", logs.String())
		}
	})
	t.Run("observe", func(t *testing.T) {
		var logs bytes.Buffer
		receipts := &haproxyprobe.Receipts{}
		e := start(t, newResponsePipeline(t, pipeline.ModeDetect, 1024, pipeline.OversizeAuto), receipts, &logs)
		e.observe(t, headers("GET", uri, true, haproxyprobe.Header, valid))
		if got := receipts.Recent(); got != nil {
			t.Fatalf("a receipt before the response: %v", got)
		}
		e.observe(t, headers("GET", uri, true, haproxyprobe.Header, valid), respHeaders(404, false, "content-type", "text/html"), respBody(sqlError, true))
		want := haproxyprobe.ExpectedResponseReceipt(key, nonce, "shop.example.com", uri)
		if got := receipts.Recent(); len(got) != 1 || got[0] != want {
			t.Fatalf("receipts %v, want [%s]", got, want)
		}
		// The response is inspected as any other.
		if evs := securityEvents(t, &logs); len(evs) != 1 {
			t.Errorf("%d events, want the leak's: %s", len(evs), logs.String())
		}
	})
	t.Run("responses not inspected", func(t *testing.T) {
		receipts := &haproxyprobe.Receipts{}
		e := start(t, newPipeline(t, pipeline.ModeBlock), receipts, &bytes.Buffer{})
		resps := e.exchange(t, headers("GET", uri, true, haproxyprobe.Header, valid))
		if len(resps) != 1 || !haproxyprobe.Verify(key, nonce, "shop.example.com", uri, probeHeader(resps[0].GetImmediateResponse())) {
			t.Fatalf("%v, want the request leg's answer", resps)
		}
		e.observe(t, headers("GET", uri, true, haproxyprobe.Header, valid), respHeaders(404, true))
		if got := receipts.Recent(); got != nil {
			t.Fatalf("receipts %v for a response the engine doesn't see", got)
		}
	})
}
