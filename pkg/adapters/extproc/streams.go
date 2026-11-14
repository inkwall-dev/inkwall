// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// eventStream is a body inspected event by event as Envoy streams it: a
// streamed response's (Server-Sent Events, a gRPC server stream, #323) or
// a gRPC call's request stream (#315). split splits it, n counts the
// events inspected, check inspects one, and held, when holds (block mode),
// are the bytes of the event in progress, not let through yet.
type eventStream struct {
	split *streams.Splitter
	n     int
	holds bool
	held  []byte
	check func(ctx context.Context, ev streams.Event, n int) pipeline.Verdict
}

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
	ex, req, resp := x.ex, x.req, x.resp
	x.respStream = &eventStream{
		split: streams.New(kind, ex.BodyLimit(), resp.Headers.Get("Grpc-Encoding")),
		holds: ex.HoldsEvents() && !x.observe,
		check: func(ctx context.Context, ev streams.Event, n int) pipeline.Verdict {
			return ex.CheckEvent(ctx, req, resp, ev, n)
		},
	}
	if !x.observe {
		r.ModeOverride = &filterv3.ProcessingMode{ResponseBodyMode: filterv3.ProcessingMode_STREAMED}
	}
	return r
}

// grpcStream returns how req's messages are inspected one by one, or nil
// when its policy reads the buffered body (or isn't one that can say).
func (s *Server) grpcStream(req *request.Request) pipeline.GRPCStream {
	if gi, ok := s.pipeline.(pipeline.GRPCStreamInspector); ok {
		return gi.GRPCStream(req)
	}
	return nil
}

// onGRPCStreamHeaders answers the headers of a gRPC call whose policy
// inspects its messages one by one (#315, 0006 §2): the call is decided on
// its headers now, and Envoy is told to stream the body (mode_override:
// STREAMED, which needs the route's allow_mode_override), so the call
// reaches the upstream at once and each message is inspected as it
// completes; a call never waits for its client's end, which a long client
// stream or a bidirectional call may never send. mode_override replaces
// the whole processing mode for the rest of the stream, so the response's
// stages are set as this request's policy needs them: sent when it
// inspects responses (with the route's body mode), off otherwise. In
// observability mode Envoy streams the body already, and nothing is held.
func (s *Server) onGRPCStreamHeaders(ctx context.Context, x *exchange, g pipeline.GRPCStream) *extprocv3.ProcessingResponse {
	r := s.verdict(ctx, x, phaseRequestHeaders)
	if r.GetImmediateResponse() != nil {
		return r
	}
	req := x.req
	x.reqStream = &eventStream{
		split: streams.New(streams.GRPC, x.limit, req.Headers.Get("Grpc-Encoding")),
		holds: g.Mode() == pipeline.ModeBlock && !x.observe,
		check: func(ctx context.Context, ev streams.Event, n int) pipeline.Verdict {
			return g.CheckGRPCMessage(ctx, req, ev, n)
		},
	}
	if !x.observe {
		mode := &filterv3.ProcessingMode{
			RequestHeaderMode:   filterv3.ProcessingMode_SEND,
			RequestBodyMode:     filterv3.ProcessingMode_STREAMED,
			RequestTrailerMode:  filterv3.ProcessingMode_SKIP,
			ResponseHeaderMode:  filterv3.ProcessingMode_SKIP,
			ResponseBodyMode:    filterv3.ProcessingMode_NONE,
			ResponseTrailerMode: filterv3.ProcessingMode_SKIP,
		}
		if x.ex != nil {
			mode.ResponseHeaderMode = filterv3.ProcessingMode_SEND
			mode.ResponseBodyMode = x.respMode
		}
		r.ModeOverride = mode
	}
	return r
}

// streamChunk answers b, a chunk of the stream *es, in phase p (a request
// or response body): it inspects the events the chunk completes. A denied
// one ends the stream with an immediate response: before the response
// started, the client gets it (a gRPC call its status, trailers-only);
// after, Envoy, the headers already sent, turns it into a reset. Either
// way that event never goes out. In block mode the bytes of the event in
// progress are held (the chunk's answer lets through only what precedes
// it), at most the event limit and a few bytes.
func (s *Server) streamChunk(ctx context.Context, x *exchange, es **eventStream, p phase, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	st := *es
	chunk := b.GetBody()
	evs := st.split.Write(chunk)
	if b.GetEndOfStream() {
		evs = append(evs, st.split.Close()...)
	}
	if r := s.checkEvents(ctx, x, es, evs); r != nil {
		return r
	}
	if b.GetEndOfStream() {
		// Nothing is held at the end (Close returned the event in
		// progress): the stream is done.
		defer func() { *es = nil }()
	}
	if !st.holds || len(st.held) == 0 && st.split.Pending() == 0 {
		return allow(p, nil)
	}
	st.held = append(st.held, chunk...)
	keep := int64(len(st.held)) - st.split.Pending()
	out := st.held[:keep]
	// A copy: out goes in the answer, sent after this returns.
	st.held = append([]byte(nil), st.held[keep:]...)
	common := &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: out}}}
	if p == phaseRequestBody {
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: common}}}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
		ResponseBody: &extprocv3.BodyResponse{Response: common}}}
}

// endStream ends the stream *es at its trailers: an event the stream
// ended inside is inspected. Its held bytes, a message the stream cut,
// can't be let through in a trailers answer: they are dropped.
func (s *Server) endStream(ctx context.Context, x *exchange, es **eventStream, p phase) *extprocv3.ProcessingResponse {
	if r := s.checkEvents(ctx, x, es, (*es).split.Close()); r != nil {
		return r
	}
	*es = nil
	return allow(p, nil)
}

// checkEvents inspects evs, the next events of the stream *es, and
// returns the answer that ends the stream when one is denied.
func (s *Server) checkEvents(ctx context.Context, x *exchange, es **eventStream, evs []streams.Event) *extprocv3.ProcessingResponse {
	st := *es
	for _, ev := range evs {
		st.n++
		v := st.check(ctx, ev, st.n)
		if httpadapter.IsEvent(v) {
			httpadapter.LogEvent(ctx, s.logger, s.events, x.req, x.path, v)
		}
		if v.Action == pipeline.ActionDeny {
			*es = nil
			return s.denial(x.req, v.Status)
		}
	}
	return nil
}
