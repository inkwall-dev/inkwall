// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func newStreamPipeline(t testing.TB, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 256, Streams: true}})
}

// chunkBody returns the body an answer to a response body chunk lets
// through: the chunk's own (no mutation), or the mutation's.
func chunkBody(chunk string, r *extprocv3.ProcessingResponse) string {
	m := r.GetResponseBody().GetResponse().GetBodyMutation()
	if m == nil {
		return chunk
	}
	return string(m.GetBody())
}

const leakEvent = "data: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version\n\n"

// A streamed response is inspected event by event (#323): Envoy is told to
// stream it; in block mode the bytes of an event are held until it is
// whole and inspected, then let through; a leaking event ends the stream
// (an immediate response, which Envoy turns into a reset) before any of
// it goes out. Detect mode logs it.
func TestStreamedResponse(t *testing.T) {
	bp := filterv3.ProcessingMode_BUFFERED_PARTIAL
	sse := "text/event-stream"
	t.Run("block", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeBlock), 64, &logs)
		chunks := []string{"data: hel", "lo\n\nda", "ta: wor", "ld\n\n", leakEvent[:30], leakEvent[30:], "data: never\n\n"}
		msgs := []*extprocv3.ProcessingRequest{withModes(headers("GET", "/chat", true), 0, bp), respHeaders(200, false, "content-type", sse)}
		for _, c := range chunks {
			msgs = append(msgs, respBody(c, false))
		}
		resps := e.exchange(t, msgs...)
		if m := resps[1].GetModeOverride(); m.GetResponseBodyMode() != filterv3.ProcessingMode_STREAMED {
			t.Fatalf("mode override %v, want STREAMED", m)
		}
		var out strings.Builder
		for i, r := range resps[2:] {
			if denied(t, r) != 0 {
				if i != 5 {
					t.Fatalf("denied at chunk %d, want 5", i)
				}
				break
			}
			out.WriteString(chunkBody(chunks[i], r))
		}
		if got := out.String(); got != "data: hello\n\ndata: world\n\n" {
			t.Errorf("let through %q, want the two clean events whole and nothing of the leak", got)
		}
		if len(resps) != 2+6 {
			t.Errorf("%d answers: the stream should end at the leaking event", len(resps))
		}
		evs := securityEvents(t, &logs)
		if len(evs) != 1 || evs[0]["phase"] != "response" || evs[0]["stream_event"] != float64(3) {
			t.Errorf("events %v, want one response event for stream event 3", evs)
		}
	})
	t.Run("detect", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeDetect), 64, &logs)
		resps := e.exchange(t, withModes(headers("GET", "/chat", true), 0, bp), respHeaders(200, false, "content-type", sse),
			respBody(leakEvent, false), respBody("data: after\n\n", true))
		for i, r := range resps[2:] {
			if denied(t, r) != 0 {
				t.Fatalf("chunk %d denied in detect mode", i)
			}
		}
		if evs := securityEvents(t, &logs); len(evs) != 1 || evs[0]["stream_event"] != float64(1) {
			t.Errorf("events %v", evs)
		}
	})
	// Off: as before, the body isn't sent.
	t.Run("off", func(t *testing.T) {
		e := newEnvoy(t, newResponsePipeline(t, pipeline.ModeBlock, 256, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		resps := e.exchange(t, withModes(headers("GET", "/chat", true), 0, bp), respHeaders(200, false, "content-type", sse))
		if m := resps[1].GetModeOverride(); m.GetResponseBodyMode() != filterv3.ProcessingMode_NONE {
			t.Errorf("mode override %v, want NONE", m)
		}
	})
}

// A gRPC server stream: each message inspected, a leaking one ends the
// stream; the trailers end it otherwise.
func TestStreamedGRPCResponse(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeBlock), 64, &logs)
	clean := grpcFrame(protoString(1, "hello"))
	leak := grpcFrame(protoString(1, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
	resps := e.exchange(t, withModes(headers("POST", "/chat.Chat/Stream", true, "content-type", "application/grpc"), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL),
		respHeaders(200, false, "content-type", "application/grpc"),
		respBody(string(clean), false), respBody(string(leak), false))
	if denied(t, resps[2]) != 0 || chunkBody(string(clean), resps[2]) != string(clean) {
		t.Errorf("clean message: %v", resps[2])
	}
	if len(resps) != 4 || denied(t, resps[3]) == 0 {
		t.Fatalf("the leaking message wasn't denied: %v", resps)
	}
	resps = e.exchange(t, withModes(headers("POST", "/chat.Chat/Stream", true, "content-type", "application/grpc"), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL),
		respHeaders(200, false, "content-type", "application/grpc"), respBody(string(clean), false), respTrailers())
	if len(resps) != 4 || denied(t, resps[3]) != 0 {
		t.Errorf("trailers: %v", resps)
	}
}

func grpcFrame(msg []byte) []byte {
	return append([]byte{0, byte(len(msg) >> 24), byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

func protoString(field byte, s string) []byte {
	return append([]byte{field<<3 | 2, byte(len(s))}, s...)
}

func respTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{}}}
}

// leakStatus is a MySQL error as a gRPC status message: percent-encoded,
// as the gRPC spec sends grpc-message.
const leakStatus = "You%20have%20an%20error%20in%20your%20SQL%20syntax%3B%20check%20the%20manual%20that%20corresponds%20to%20your%20MySQL%20server%20version"

func respTrailersWith(kv ...string) *extprocv3.ProcessingRequest {
	var hs []*corev3.HeaderValue
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{Trailers: &corev3.HeaderMap{Headers: hs}}}}
}

// A gRPC call's status message (grpc-message) is the server's text too
// (#317): an error that leaks SQL, a stack trace. With streams inspected it
// is inspected as one more event, decoded: in a trailers-only answer (an
// error before any message), whose headers Envoy still holds, the leak is
// replaced by the engine's denial; in the trailers after the messages,
// which Envoy is told to send, it ends the stream before the client gets
// the status.
func TestGRPCStatusMessage(t *testing.T) {
	bp := filterv3.ProcessingMode_BUFFERED_PARTIAL
	call := func() *extprocv3.ProcessingRequest {
		return withModes(headers("POST", "/chat.Chat/Stream", true, "content-type", "application/grpc"), 0, bp)
	}
	t.Run("trailers-only", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeBlock), 64, &logs)
		resps := e.exchange(t, call(), respHeaders(200, true, "content-type", "application/grpc", "grpc-status", "13", "grpc-message", leakStatus))
		if len(resps) != 2 || denied(t, resps[1]) == 0 {
			t.Fatalf("a leaking status message wasn't denied: %v", resps)
		}
		if evs := securityEvents(t, &logs); len(evs) != 1 || evs[0]["phase"] != "response" || evs[0]["stream_event"] != float64(1) {
			t.Errorf("events %v", evs)
		}
		resps = e.exchange(t, call(), respHeaders(200, true, "content-type", "application/grpc", "grpc-status", "5", "grpc-message", "user%20not%20found"))
		if denied(t, resps[1]) != 0 {
			t.Errorf("a clean status message denied: %v", resps[1])
		}
	})
	t.Run("trailers", func(t *testing.T) {
		var logs bytes.Buffer
		e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeBlock), 64, &logs)
		clean := string(grpcFrame(protoString(1, "hello")))
		resps := e.exchange(t, call(), respHeaders(200, false, "content-type", "application/grpc"), respBody(clean, false),
			respTrailersWith("grpc-status", "13", "grpc-message", leakStatus))
		if m := resps[1].GetModeOverride(); m.GetResponseBodyMode() != filterv3.ProcessingMode_STREAMED || m.GetResponseTrailerMode() != filterv3.ProcessingMode_SEND {
			t.Fatalf("mode override %v, want the body streamed and the trailers sent", m)
		}
		if len(resps) != 4 || denied(t, resps[3]) == 0 {
			t.Fatalf("a leaking status message in the trailers wasn't denied: %v", resps)
		}
		if evs := securityEvents(t, &logs); len(evs) != 1 || evs[0]["stream_event"] != float64(2) {
			t.Errorf("events %v, want the status as event 2", evs)
		}
		resps = e.exchange(t, call(), respHeaders(200, false, "content-type", "application/grpc"), respBody(clean, false),
			respTrailersWith("grpc-status", "0"))
		if len(resps) != 4 || denied(t, resps[3]) != 0 {
			t.Errorf("clean trailers: %v", resps)
		}
	})
	// SSE has no trailers to ask for.
	t.Run("SSE", func(t *testing.T) {
		e := newEnvoy(t, newStreamPipeline(t, pipeline.ModeBlock), 64, &bytes.Buffer{})
		resps := e.exchange(t, withModes(headers("GET", "/chat", true), 0, bp), respHeaders(200, false, "content-type", "text/event-stream"))
		if m := resps[1].GetModeOverride(); m.GetResponseTrailerMode() == filterv3.ProcessingMode_SEND {
			t.Errorf("mode override %v: no trailers for SSE", m)
		}
	})
	// Without streams, as before: the status isn't read.
	t.Run("off", func(t *testing.T) {
		e := newEnvoy(t, newResponsePipeline(t, pipeline.ModeBlock, 256, pipeline.OversizeAuto), 64, &bytes.Buffer{})
		resps := e.exchange(t, call(), respHeaders(200, true, "content-type", "application/grpc", "grpc-status", "13", "grpc-message", leakStatus))
		if denied(t, resps[1]) != 0 {
			t.Errorf("status message inspected without streams: %v", resps[1])
		}
	})
}
