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
