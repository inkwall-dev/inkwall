// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// GRPCStream inspects the messages of one gRPC call's request stream one
// by one, as they come (#315, docs/design/0006 §2).
type GRPCStream interface {
	// CheckGRPCMessage inspects ev, the n-th message (from 1) of call,
	// whose headers were inspected (Check or CheckExchange) and let
	// through.
	CheckGRPCMessage(ctx context.Context, call *request.Request, ev streams.Event, n int) Verdict
	// Mode is the policy's mode: block mode holds each message until it is
	// inspected.
	Mode() Mode
}

// GRPCStreamInspector is an Inspector whose policies may inspect gRPC
// calls message by message, for the adapters that can stream a request
// body (ext_proc).
type GRPCStreamInspector interface {
	// GRPCStream returns how r's messages are inspected one by one, or nil
	// when they aren't: r isn't a gRPC call, or its policy inspects the
	// buffered body. r carries its headers only.
	GRPCStream(r *request.Request) GRPCStream
}

var _ GRPCStreamInspector = (*Pipeline)(nil)

// GRPCStream implements GRPCStreamInspector: r is a gRPC call (a POST
// whose one Content-Type is application/grpc or application/grpc+proto),
// the pipeline inspects messages one by one, and r's route is inspected
// with its body. gRPC-Web is left buffered: browsers don't stream a
// request, and its text form is base64.
func (p *Pipeline) GRPCStream(r *request.Request) GRPCStream {
	if !p.grpcPerMessage || r.Method != http.MethodPost || p.routes.Decide(r.RawURI) != router.InspectAll {
		return nil
	}
	ct := r.Headers.Values("Content-Type")
	if len(ct) != 1 || streams.KindOf(ct[0]) != streams.GRPC {
		return nil
	}
	return p
}

// CheckGRPCMessage implements GRPCStream. The message is inspected on its
// own, as a WebSocket message is (CheckWebSocketMessage): a fresh
// evaluation of a clean gRPC call with call's identity, path and content
// type, but not its query or other headers (inspected with the call; run
// again they would add the call's score to every message), whose form
// arguments are the message's text fields (request.Request.GRPCText), as
// grpcMessages names them in a buffered body. Each evaluation goes through
// admission control and the deadline, as a request does: a flood of
// messages is shed with the failure mode as a flood of requests is. A
// message cut at the body limit, or compressed in an encoding the engine
// can't read, gets the oversize action; a stream that isn't gRPC framing
// is denied whatever the oversize action, since under Allow it would pass
// uninspected (a JSON body labelled gRPC).
func (p *Pipeline) CheckGRPCMessage(ctx context.Context, call *request.Request, ev streams.Event, n int) Verdict {
	start := time.Now()
	var v Verdict
	switch {
	case p.ipListed(call) == ReasonIPAllow:
		v = Verdict{Action: ActionAllow, Reason: ReasonIPAllow}
	case p.routes.Decide(call.RawURI) != router.InspectAll:
		v = Verdict{Action: ActionAllow, Reason: ReasonSkipped}
	case ev.Unframed:
		v = p.enforce(Verdict{Reason: ReasonGRPC}, http.StatusForbidden)
	default:
		msg := grpcMessageRequest(call, ev)
		if ev.Truncated {
			v, _ = p.partly(ctx, &msg, false)
		} else {
			v, _ = p.evaluate(ctx, p.request(&msg, false))
		}
	}
	v.Duration = time.Since(start)
	v.StreamEvent = n
	v.Policy = p.policy
	if p.observer != nil {
		p.observer.ObserveVerdict(v)
	}
	return v
}

// grpcMessageRequest is the request a message of call is evaluated as.
func grpcMessageRequest(call *request.Request, ev streams.Event) request.Request {
	path, _, _ := strings.Cut(call.RawURI, "?")
	r := request.Request{
		ID:       call.ID,
		Proto:    call.Proto,
		Method:   http.MethodPost,
		Scheme:   call.Scheme,
		Host:     call.Host,
		RawURI:   path,
		Headers:  http.Header{"Content-Type": {call.Headers.Get("Content-Type")}, "Accept": {"*/*"}, "User-Agent": {"inkwall-grpc-message"}},
		PeerIP:   call.PeerIP,
		ClientIP: call.ClientIP,
		GRPC:     true,
	}
	if len(ev.Fields) > 0 {
		r.GRPCText = make([]request.Arg, len(ev.Fields))
		for i, f := range ev.Fields {
			r.GRPCText[i] = request.Arg{Name: f.Name, Value: f.Value}
		}
	}
	return r
}
