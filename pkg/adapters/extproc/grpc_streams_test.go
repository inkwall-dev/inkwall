// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"strings"
	"testing"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func newPerMessagePipeline(t testing.TB, mode pipeline.Mode, oversize pipeline.OversizeAction) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second, Oversize: oversize,
		GRPCMessages: true, GRPCPerMessage: true})
}

// reqChunkBody returns the body an answer to a request body chunk lets
// through: the chunk's own (no mutation), or the mutation's.
func reqChunkBody(chunk string, r *extprocv3.ProcessingResponse) string {
	m := r.GetRequestBody().GetResponse().GetBodyMutation()
	if m == nil {
		return chunk
	}
	return string(m.GetBody())
}

const sqli = "1' OR '1'='1' -- "

// A gRPC call whose policy inspects messages one by one (#315): it is
// decided on its headers, Envoy is told to stream the body, and each
// message is inspected as it completes. In block mode a message's bytes
// are held until it is whole and allowed; a denied message ends the call
// with its gRPC status, and nothing of it, nor any later, is let through.
func TestGRPCPerMessage(t *testing.T) {
	bp := filterv3.ProcessingMode_BUFFERED_PARTIAL
	msgs := grpcMessages("hello", "world", sqli, "never")
	one, two := len(grpcMessages("hello")), len(grpcMessages("hello", "world"))
	three := len(grpcMessages("hello", "world", sqli))
	// The stream in chunks that cut messages, as HTTP/2 DATA frames may.
	chunks := []string{msgs[:3], msgs[3 : one+4], msgs[one+4 : two], msgs[two : three-2], msgs[three-2:]}

	t.Run("block", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAuto), 64, &logs)
		in := []*extprocv3.ProcessingRequest{withMode(grpcHeaders("/chat.Chat/Talk"), bp)}
		for _, c := range chunks {
			in = append(in, body(c, false))
		}
		resps := e.exchange(t, in...)
		continued(t, resps[0])
		m := resps[0].GetModeOverride()
		if m.GetRequestBodyMode() != filterv3.ProcessingMode_STREAMED {
			t.Fatalf("mode override %v, want the request body STREAMED", m)
		}
		// The rest of the mode is the route's, so Envoy doesn't start
		// sending what it didn't: nothing of the response here.
		if m.GetResponseHeaderMode() != filterv3.ProcessingMode_SKIP || m.GetResponseBodyMode() != filterv3.ProcessingMode_NONE {
			t.Errorf("mode override %v: the response stages should stay off", m)
		}
		var out strings.Builder
		deniedAt := -1
		for i, r := range resps[1:] {
			if r.GetImmediateResponse() != nil {
				deniedAt = i
				ir, _ := immediate(t, r)
				if ir.GetGrpcStatus().GetStatus() != 7 {
					t.Errorf("denial %v, want grpc-status 7", ir)
				}
				break
			}
			out.WriteString(reqChunkBody(chunks[i], r))
		}
		if deniedAt != 4 {
			t.Fatalf("denied at chunk %d, want 4 (the one that completes the attack); events %s", deniedAt, logs.String())
		}
		if got := out.String(); got != grpcMessages("hello", "world") {
			t.Errorf("let through %q, want the two clean messages whole and nothing of the attack", got)
		}
		evs := securityEvents(t, &logs)
		if len(evs) != 1 || evs[0]["phase"] != "request" || evs[0]["stream_event"] != float64(3) || evs[0]["action"] != "deny" {
			t.Errorf("events %v, want one request deny for message 3", evs)
		}
	})

	t.Run("detect", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeDetect, pipeline.OversizeAuto), 64, &logs)
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp), body(msgs[:two], false), body(msgs[two:], true))
		for i, r := range resps[1:] {
			if r.GetImmediateResponse() != nil || r.GetRequestBody().GetResponse().GetBodyMutation() != nil {
				t.Fatalf("chunk %d held or denied in detect mode: %v", i, r)
			}
		}
		if evs := securityEvents(t, &logs); len(evs) != 1 || evs[0]["action"] != "log" || evs[0]["stream_event"] != float64(3) {
			t.Errorf("events %v", evs)
		}
	})

	// A bidirectional call: the client sends a message, waits for the
	// server's, then sends the next. Each message is let through as it
	// completes, so the call never waits for the client's end.
	t.Run("bidirectional", func(t *testing.T) {
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp),
			body(grpcMessages("hello"), false),
			respHeaders(200, false, "content-type", "application/grpc"),
			body(grpcMessages("world"), false))
		for i, c := range []string{grpcMessages("hello"), "", grpcMessages("world")} {
			r := resps[i+1]
			if c == "" {
				continue
			}
			if got := reqChunkBody(c, r); got != c {
				t.Errorf("message %d: let through %q, want it whole", i, got)
			}
		}
	})

	t.Run("message over the limit", func(t *testing.T) {
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		long := grpcMessages(strings.Repeat("a", 100))
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp), body(grpcMessages("hi"), false), body(long, false))
		if got := reqChunkBody(grpcMessages("hi"), resps[1]); got != grpcMessages("hi") {
			t.Errorf("first message: %q", got)
		}
		ir, _ := immediate(t, resps[2])
		if ir.GetStatus().GetCode() != 413 || ir.GetGrpcStatus().GetStatus() != 8 {
			t.Errorf("long message: %v, want 413, grpc-status 8", ir)
		}
	})

	// A body that isn't gRPC messages is denied whatever onOversize says:
	// under Allow it would otherwise pass uninspected (a JSON body labelled
	// gRPC).
	t.Run("not gRPC framing", func(t *testing.T) {
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAllow), 64, &bytes.Buffer{})
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp), body(`{"q":"`+sqli+`"}`, true))
		if ir, _ := immediate(t, resps[1]); ir.GetGrpcStatus().GetStatus() == 0 {
			t.Errorf("unframed body: %v, want a gRPC denial", ir)
		}
	})

	// A message the stream ends inside is cut: oversize.
	t.Run("ends inside a message", func(t *testing.T) {
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp), body(grpcMessages("hello")[:4], true))
		if ir, _ := immediate(t, resps[1]); ir.GetGrpcStatus().GetStatus() != 8 {
			t.Errorf("cut message: %v, want grpc-status 8", ir)
		}
	})

	// gRPC-Web, and a policy that doesn't ask for it, are buffered as
	// before: no mode override.
	t.Run("buffered otherwise", func(t *testing.T) {
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeBlock, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		resps := e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk", "content-type", "application/grpc-web"), bp))
		if resps[0].GetModeOverride() != nil {
			t.Errorf("gRPC-Web: mode override %v", resps[0].GetModeOverride())
		}
		eval, err := coraza.New(coraza.Config{})
		if err != nil {
			t.Fatal(err)
		}
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: true})
		e = newEnvoy(t, p, 64, &bytes.Buffer{})
		resps = e.exchange(t, withMode(grpcHeaders("/chat.Chat/Talk"), bp))
		if resps[0].GetModeOverride() != nil {
			t.Errorf("buffered policy: mode override %v", resps[0].GetModeOverride())
		}
	})

	// Observability mode: Envoy streams the body anyway; each message is
	// inspected and logged, however long the call.
	t.Run("observability mode", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newPerMessagePipeline(t, pipeline.ModeDetect, pipeline.OversizeAuto), 64, &logs)
		h := grpcHeaders("/chat.Chat/Talk")
		h.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: filterv3.ProcessingMode_STREAMED}
		h.ObservabilityMode = true
		// More than the limit in all: the call isn't oversized, each
		// message is within it.
		long := grpcMessages(strings.Repeat("x", 50), strings.Repeat("y", 50))
		e.observe(t, h, body(long, false), body(msgs[two:three], false), body("", true))
		if evs := securityEvents(t, &logs); len(evs) != 1 || evs[0]["stream_event"] != float64(3) {
			t.Errorf("events %v, want message 3 logged", evs)
		}
	})
}

// The response modes the override carries are the route's for a policy
// that inspects responses: Envoy still sends the response.
func TestGRPCPerMessageKeepsResponses(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: true, GRPCPerMessage: true,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 256, Streams: true}})
	e := newEnvoy(t, p, 64, &bytes.Buffer{})
	resps := e.exchange(t, withModes(grpcHeaders("/chat.Chat/Talk"), filterv3.ProcessingMode_BUFFERED_PARTIAL, filterv3.ProcessingMode_BUFFERED_PARTIAL))
	m := resps[0].GetModeOverride()
	if m.GetRequestBodyMode() != filterv3.ProcessingMode_STREAMED || m.GetResponseHeaderMode() != filterv3.ProcessingMode_SEND ||
		m.GetResponseBodyMode() != filterv3.ProcessingMode_BUFFERED_PARTIAL {
		t.Errorf("mode override %v", m)
	}
}
