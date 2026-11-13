// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/http"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// messageInspector inspects every call's messages one by one (#315): it
// denies a message whose text holds "deny", and one cut or unframed, as
// block mode's defaults do.
type messageInspector struct{ inspector }

func (m *messageInspector) GRPCStream(*request.Request) pipeline.GRPCStream { return m }

func (*messageInspector) Mode() pipeline.Mode { return pipeline.ModeBlock }

// deniesMessage is what messageInspector denies.
func deniesMessage(ev streams.Event) bool {
	return ev.Truncated || bytes.Contains(ev.Data, []byte("deny"))
}

func (*messageInspector) CheckGRPCMessage(_ context.Context, _ *request.Request, ev streams.Event, n int) pipeline.Verdict {
	if deniesMessage(ev) {
		return pipeline.Verdict{Action: pipeline.ActionDeny, Status: http.StatusForbidden, Reason: pipeline.ReasonRule, StreamEvent: n}
	}
	return pipeline.Verdict{StreamEvent: n}
}

// FuzzExtProcGRPCStream streams any body, cut into chunks anywhere, as a
// gRPC call whose messages are inspected one by one in block mode. What
// the answers let through, in order, is always whole gRPC messages of the
// body, each allowed, the body's own prefix: never a byte of a denied or
// unfinished message, nor anything after a denial; and no more than the
// limit and a prefix is held between chunks.
func FuzzExtProcGRPCStream(f *testing.F) {
	frame := func(s string) []byte {
		msg := append([]byte{0x0a, byte(len(s))}, s...)
		return append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(msg))), msg...)
	}
	f.Add(append(append(frame("hello"), frame("world")...), frame("deny me")...), uint16(3), uint16(11), true)
	f.Add([]byte(`{"q":"x"}`), uint16(2), uint16(4), false)
	f.Add(frame("a long message over the limit"), uint16(1), uint16(9), true)
	f.Fuzz(func(t *testing.T, body []byte, cut1, cut2 uint16, eos bool) {
		a, b := int(cut1)%(len(body)+1), int(cut2)%(len(body)+1)
		a, b = min(a, b), max(a, b)
		chunks := [][]byte{body[:a], body[a:b], body[b:]}
		in := []*extprocv3.ProcessingRequest{{
			Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("POST")}, {Key: ":path", RawValue: []byte("/chat.Chat/Talk")},
				{Key: ":authority", RawValue: []byte("grpc.example.com")}, {Key: ":scheme", RawValue: []byte("http")},
				{Key: "content-type", RawValue: []byte("application/grpc")},
			}}}},
			ProtocolConfig: &extprocv3.ProtocolConfiguration{RequestBodyMode: filterv3.ProcessingMode_BUFFERED_PARTIAL},
		}}
		for i, c := range chunks {
			in = append(in, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{Body: c, EndOfStream: eos && i == len(chunks)-1}}})
		}
		s, err := New(&messageInspector{}, Config{MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		stream := &fakeStream{in: in}
		if err := s.Process(stream); err != nil {
			t.Fatalf("stream failed: %v", err)
		}
		if stream.out[0].GetModeOverride().GetRequestBodyMode() != filterv3.ProcessingMode_STREAMED {
			t.Fatalf("headers answered %v", stream.out[0])
		}
		var out []byte
		denied := false
		for i, r := range stream.out[1:] {
			if r.GetImmediateResponse() != nil {
				if r.GetImmediateResponse().GetGrpcStatus() == nil {
					t.Fatalf("a denial without a gRPC status: %v", r)
				}
				denied = true
				break
			}
			if m := r.GetRequestBody().GetResponse().GetBodyMutation(); m != nil {
				out = append(out, m.GetBody()...)
			} else {
				out = append(out, chunks[i]...)
			}
		}
		if !bytes.HasPrefix(body, out) {
			t.Fatalf("let through %q, not a prefix of the body %q", out, body)
		}
		// Every message let through is whole and allowed, read as the
		// inspector reads it (the splitter's chunking is FuzzSSEEvents').
		msgs, ok := grpcwire.Messages(out, false)
		if !ok {
			t.Fatalf("let through %q: not whole gRPC messages", out)
		}
		split := streams.New(streams.GRPC, fuzzMaxBody, "")
		evs := append(split.Write(out), split.Close()...)
		if len(evs) != len(msgs) {
			t.Fatalf("let through %d messages, read as %d events", len(msgs), len(evs))
		}
		for i, ev := range evs {
			if msgs[i].Cut || len(msgs[i].Data) > fuzzMaxBody || deniesMessage(ev) {
				t.Fatalf("let through a message that should be denied: %q", msgs[i].Data)
			}
		}
		// What isn't let through is a message denied, or one not finished
		// when the stream ended: then there was a denial (eos), or it is
		// held (no eos), within the limit and a prefix.
		if rest := len(body) - len(out); rest > 0 && !denied && (eos || rest > fuzzMaxBody+grpcwire.FrameHeader) {
			t.Fatalf("%d bytes neither let through nor denied (eos %v): body %q", rest, eos, body)
		}
	})
}
