// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// onStreamHeaders answers the headers of a streamed response (Server-Sent
// Events, a gRPC server stream) whose policy inspects streams (#323,
// 0006 §2): the status and headers are inspected now, and the body event
// by event as it comes, Envoy told to stream it (mode_override: STREAMED,
// which the route's allow_mode_override permits; without it Envoy sends
// the body as its mode says, and it is split the same).
func (s *Server) onStreamHeaders(ctx context.Context, x *exchange) *extprocv3.ProcessingResponse {
	r := s.responseVerdict(ctx, x, phaseResponseHeaders)
	if r.GetImmediateResponse() != nil {
		return r
	}
	kind := pipeline.StreamKind(x.resp.Headers.Get("Content-Type"))
	x.split = streams.New(kind, x.ex.BodyLimit(), x.resp.Headers.Get("Grpc-Encoding"))
	x.holds = x.ex.HoldsEvents() && !x.observe
	if !x.observe {
		r.ModeOverride = &filterv3.ProcessingMode{ResponseBodyMode: filterv3.ProcessingMode_STREAMED}
	}
	return r
}

// onStreamChunk answers a chunk of a streamed response: it inspects the
// events the chunk completes. A denied one ends the stream with an
// immediate response, which Envoy, the headers already sent, turns into a
// reset: the client never gets that event. In block mode the bytes of the
// event in progress are held (the chunk's answer lets through only what
// precedes it), at most the event limit and a few bytes.
func (s *Server) onStreamChunk(ctx context.Context, x *exchange, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	chunk := b.GetBody()
	evs := x.split.Write(chunk)
	if b.GetEndOfStream() {
		evs = append(evs, x.split.Close()...)
	}
	if r := s.checkEvents(ctx, x, evs); r != nil {
		return r
	}
	if b.GetEndOfStream() {
		// Nothing is held at the end (Close returned the event in
		// progress): the stream is done.
		defer func() { x.split, x.held = nil, nil }()
	}
	if !x.holds || len(x.held) == 0 && x.split.Pending() == 0 {
		return allow(phaseResponseBody, nil)
	}
	x.held = append(x.held, chunk...)
	keep := int64(len(x.held)) - x.split.Pending()
	out := x.held[:keep]
	// A copy: out goes in the answer, sent after this returns.
	x.held = append([]byte(nil), x.held[keep:]...)
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
		ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
			BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: out}}}}}}
}

// endStream ends a streamed response at its trailers (gRPC's): an event
// the stream ended inside is inspected. Its held bytes, a message the
// stream cut, can't be let through in a trailers answer: they are dropped.
func (s *Server) endStream(ctx context.Context, x *exchange, p phase) *extprocv3.ProcessingResponse {
	if r := s.checkEvents(ctx, x, x.split.Close()); r != nil {
		return r
	}
	x.split, x.held = nil, nil
	return allow(p, nil)
}

// checkEvents inspects evs, the next events of x's stream, and returns the
// answer that ends the stream when one is denied.
func (s *Server) checkEvents(ctx context.Context, x *exchange, evs []streams.Event) *extprocv3.ProcessingResponse {
	for _, ev := range evs {
		x.events++
		v := x.ex.CheckEvent(ctx, x.req, x.resp, ev, x.events)
		if httpadapter.IsEvent(v) {
			httpadapter.LogEvent(ctx, s.logger, s.events, x.req, x.path, v)
		}
		if v.Action == pipeline.ActionDeny {
			x.split, x.held = nil, nil
			return s.denial(x.req, v.Status)
		}
	}
	return nil
}
