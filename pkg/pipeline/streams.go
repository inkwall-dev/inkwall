// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// Streams reports whether streamed responses are inspected event by event
// (ResponseConfig.Streams).
func (e *Exchange) Streams() bool { return e.p.responses.Streams && e.p.responses.MaxBytes > 0 }

// HoldsEvents reports whether an adapter holds each event of a stream
// until it is inspected: in block mode, so a denied event never goes out.
// Detect mode forwards at once and inspects a copy.
func (e *Exchange) HoldsEvents() bool { return e.p.mode == ModeBlock }

// CheckEvent inspects one event of a streamed response (#323, 0006 §2):
// ev, the n-th event (from 1) of stream, the response to req, whose status
// and headers were inspected with CheckResponse. The event is inspected on
// its own, as a WebSocket message is: a fresh evaluation of a clean
// request with req's identity and path (so exclusions and events apply,
// but the request's score isn't added to every event), whose response has
// the stream's status and headers and the event's text as a plain-text
// body. A cut event (ev.Truncated) gets the oversize action. The Exchange
// may already be closed: only its policy is used.
func (e *Exchange) CheckEvent(ctx context.Context, req *request.Request, stream *request.Response, ev streams.Event, n int) Verdict {
	p := e.p
	start := time.Now()
	msg := messageRequest(req)
	v, x := p.evaluate(ctx, p.request(&msg, true))
	if x != nil {
		resp := &request.Response{Proto: stream.Proto, Status: stream.Status, Headers: eventHeaders(stream.Headers),
			Body: ev.Data, BodyTruncated: ev.Truncated}
		one := &Exchange{p: p, x: x, observe: e.observe}
		v = one.check(ctx, resp)
		one.Close()
	}
	// A clean request that its rules deny, or an evaluation refused:
	// its verdict is the event's.
	v.Duration = time.Since(start)
	v.Response = true
	v.StreamEvent = n
	v.Policy = p.policy
	if p.observer != nil {
		p.observer.ObserveVerdict(v)
	}
	if e.observe != nil {
		e.observe(v)
	}
	return v
}

// eventHeaders are the stream's headers, but for the body's type: the
// event's text is read as plain text, which the rules read whatever the
// stream's own type (SSE, gRPC).
func eventHeaders(h http.Header) http.Header {
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set("Content-Type", "text/plain")
	out.Del("Content-Encoding")
	out.Del("Content-Length")
	return out
}

// StreamKind is the kind of stream a response with this Content-Type is,
// split into events when Streams is on.
func StreamKind(contentType string) streams.Kind { return streams.KindOf(contentType) }
