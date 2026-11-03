// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package extproc implements the ext_proc adapter used by Envoy's external
// processing filter (envoy.service.ext_proc.v3), and so by Envoy Gateway.
//
// Envoy opens one gRPC stream per HTTP request and sends the request
// headers, then the body if its processing mode asks for it. The adapter
// answers an allowed request with CONTINUE and a denied one with an
// immediate response carrying the verdict's status, or, for a gRPC call,
// its gRPC status (trailers-only). Later messages (the
// response headers and body, if the filter sends them) are answered with
// CONTINUE, unless the request's policy inspects responses.
//
// A policy that inspects responses keeps the request's evaluation for the
// response (pipeline.Exchange). Its status and headers are inspected, and
// its body when the rules read its media type and Envoy sends it in one
// message (response_body_mode BUFFERED or BUFFERED_PARTIAL): Envoy holds
// the response headers meanwhile, so a denied response is replaced by an
// immediate response. A response body the engine doesn't read (an image, a
// stream) is let through at the headers, and the answer asks Envoy, through
// mode_override, not to send or buffer it. A body Envoy cut, or doesn't send
// in one piece, has its prefix inspected and is handled as oversized
// (responses.onOversize). On a route whose response bodies are inspected,
// the request's Accept-Encoding is removed, so the upstream sends bodies
// the rules can read; gzip and deflate bodies are decoded all the same.
//
// The body is inspected when the policy asks for it and Envoy sends it in
// one message: request_body_mode BUFFERED or BUFFERED_PARTIAL. A body Envoy
// doesn't send that way (NONE, STREAMED, ...) goes uninspected, and is
// handled like a body over the policy's limit (body.onOversize). With
// BUFFERED_PARTIAL, a body Envoy cut at its buffer limit is handled the
// same way. Envoy sends a body without end_of_stream when it cut it, but
// also when trailers follow (HTTP/2), and then sends no trailers message:
// Envoy Gateway can't ask for them. Such a body counts as complete only
// when it is under the limit and as long as its Content-Length says: one
// without Content-Length may have been cut at a buffer the engine doesn't
// know, so it is handled as oversized.
//
// An upgrade (a WebSocket handshake: a GET with an Upgrade header) that
// declares no body is decided on its headers, and answered with
// CONTINUE_AND_REPLACE, so Envoy stops sending the stream: what follows
// its headers is the upgraded connection's data, not a body (#276).
//
// In observability mode (detect mode) Envoy doesn't wait for the answers,
// and the adapter sends none. The body comes in chunks there (STREAMED, the
// only mode Envoy allows, whatever protocol_config says): they are gathered
// up to the limit, and the stream is closed once the request is decided, or
// its response when that is inspected. A stream that ends first is decided
// on what came.
//
// The protocol the client spoke is Envoy's request.protocol attribute, if
// the filter sends it; HTTP/1.1 otherwise.
//
// The client address comes from X-Forwarded-For, which Envoy sets before
// the filter runs, through the trusted proxies. Envoy is the direct peer: a
// Unix-socket peer counts as loopback, 127.0.0.1.
package extproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// envelope bounds a ProcessingRequest beyond the body it carries: headers
// and attributes.
const envelope = 1 << 20

// Config configures a Server.
type Config struct {
	// MaxBodyBytes is how much of a request body is inspected. Zero
	// disables body inspection.
	MaxBodyBytes int64
	// ClientIP resolves the client address from X-Forwarded-For. Envoy is
	// the direct peer, so its address must be trusted. Nil trusts no
	// proxies.
	ClientIP *clientip.Resolver
	// Logger receives one security event per denied or logged request.
	// Nil uses slog.Default().
	Logger *slog.Logger
	// Events records each security event for the operator (nil: logged
	// only).
	Events *events.Recorder
}

// Server answers Envoy's external processing streams.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer

	pipeline pipeline.Inspector
	maxBody  int64
	clientIP *clientip.Resolver
	logger   *slog.Logger
	events   *events.Recorder
}

// New returns a Server that inspects requests with p.
func New(p pipeline.Inspector, cfg Config) (*Server, error) {
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("max body bytes %d must not be negative", cfg.MaxBodyBytes)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	resolver := cfg.ClientIP
	if resolver == nil {
		resolver = &clientip.Resolver{}
	}
	return &Server{pipeline: p, maxBody: cfg.MaxBodyBytes, clientIP: resolver, logger: logger, events: cfg.Events}, nil
}

// NewGRPCServer returns a gRPC server that serves s. It accepts messages
// as large as the body limit and the headers.
func (s *Server) NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {
	opts = append([]grpc.ServerOption{grpc.MaxRecvMsgSize(int(s.maxBody) + envelope)}, opts...)
	g := grpc.NewServer(opts...)
	extprocv3.RegisterExternalProcessorServer(g, s)
	return g
}

// exchange is the state of one stream, that is one HTTP request.
type exchange struct {
	peer     netip.Addr
	bodyMode filterv3.ProcessingMode_BodySendMode
	req      *request.Request
	path     string
	limit    int64
	// observe: Envoy runs in observability mode.
	observe bool
	// waiting: the headers were let into Envoy's buffer, and the verdict
	// waits for the body.
	waiting bool
	// gather: the body comes in chunks, gathered in streamed up to one
	// byte over the limit (observability mode).
	gather   bool
	streamed []byte
	// setID: the request ID was generated here, and is set on the request
	// Envoy forwards.
	setID bool
	// upgrade: the request is an upgrade (a WebSocket handshake) without
	// a body, answered on its headers.
	upgrade bool

	// The response, when the request's policy inspects it.
	respMode filterv3.ProcessingMode_BodySendMode
	// ex is the request's evaluation, kept for the response; nil when the
	// response isn't inspected.
	ex   *pipeline.Exchange
	resp *request.Response
	// respWaiting: the verdict waits for the response body, gathered in
	// respStreamed up to one byte over respLimit if respGather.
	respWaiting  bool
	respGather   bool
	respStreamed []byte
	respLimit    int64
	// respDone: the response was decided.
	respDone bool
	// pending are response messages that came, in observability mode,
	// before the request was decided (Envoy doesn't hold the request: the
	// upstream may answer before the client sent all of its body), handled
	// once it is; queued holds their body bytes, at most maxQueued, and
	// queueCut says some were dropped.
	pending  []*extprocv3.ProcessingRequest
	queued   int64
	queueCut bool
}

// done reports whether nothing more is needed in observability mode: the
// request was refused uninspected, or it was decided and so was its
// response, if inspected.
func (x *exchange) done() bool {
	return x.req == nil || !x.waiting && (x.ex == nil || x.respDone)
}

// Process handles the stream of one HTTP request.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	x := &exchange{peer: peerAddr(ctx)}
	// The response's evaluation, if kept, ends with the stream.
	defer func() { x.ex.Close() }()
	for first := true; ; first = false {
		msg, err := stream.Recv()
		if err != nil && x.observe && x.waiting {
			// Envoy sent no more of the body: decide on what came, even
			// though the stream is gone.
			x.setBody(x.streamed, false)
			s.verdict(context.WithoutCancel(ctx), x, phaseRequestBody)
			if s.replay(context.WithoutCancel(ctx), x) != nil {
				return err
			}
		}
		if err != nil && x.observe && x.respWaiting {
			x.setResponseBody(x.respStreamed, false)
			s.responseVerdict(context.WithoutCancel(ctx), x, phaseResponseBody)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Envoy describes its processing mode in the first message only.
		if first {
			x.bodyMode = msg.GetProtocolConfig().GetRequestBodyMode()
			x.respMode = msg.GetProtocolConfig().GetResponseBodyMode()
			x.observe = msg.GetObservabilityMode()
		}
		if x.observe && x.waiting && isResponse(msg) {
			x.queue(msg)
			continue
		}
		resp, err := s.handle(ctx, x, msg)
		if err == nil && x.observe && !x.waiting {
			err = s.replay(ctx, x)
		}
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelError, "invalid ext_proc stream", slog.Any("error", err))
			return status.Error(codes.InvalidArgument, err.Error())
		}
		// In observability mode Envoy doesn't wait, and ignores answers;
		// once the request is decided, and its response if inspected,
		// nothing more is needed.
		if x.observe {
			if x.done() {
				return nil
			}
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// handle answers one message of the stream.
func (s *Server) handle(ctx context.Context, x *exchange, msg *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch m := msg.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		if x.req != nil {
			return nil, errors.New("request headers sent twice")
		}
		return s.onHeaders(ctx, x, m.RequestHeaders, protocol(msg)), nil
	case *extprocv3.ProcessingRequest_RequestBody:
		if x.req == nil {
			return s.uninspectable(ctx, errors.New("request body before the request headers")), nil
		}
		if x.waiting && x.fillBody(m.RequestBody) {
			return s.verdict(ctx, x, phaseRequestBody), nil
		}
		return allow(phaseRequestBody, nil), nil
	case *extprocv3.ProcessingRequest_RequestTrailers:
		if x.req == nil {
			return s.uninspectable(ctx, errors.New("request trailers before the request headers")), nil
		}
		if x.waiting {
			// The body ended with the last body message, or was empty.
			x.fillBody(&extprocv3.HttpBody{EndOfStream: true})
			return s.verdict(ctx, x, phaseRequestTrailers), nil
		}
		return allow(phaseRequestTrailers, nil), nil
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		if r, err := s.onResponse(ctx, x, phaseResponseHeaders); r != nil || err != nil {
			if r.GetResponseHeaders() != nil && !m.ResponseHeaders.GetEndOfStream() && x.buffersResponses() {
				// A response that isn't inspected (its request's policy
				// doesn't, though the route sends responses): Envoy needn't
				// buffer its body, nor send it.
				r.ModeOverride = &filterv3.ProcessingMode{ResponseBodyMode: filterv3.ProcessingMode_NONE}
			}
			return r, err
		}
		return s.onResponseHeaders(ctx, x, m.ResponseHeaders), nil
	case *extprocv3.ProcessingRequest_ResponseBody:
		if r, err := s.onResponse(ctx, x, phaseResponseBody); r != nil || err != nil {
			return r, err
		}
		if x.respWaiting && x.fillResponse(m.ResponseBody) {
			return s.responseVerdict(ctx, x, phaseResponseBody), nil
		}
		return allow(phaseResponseBody, nil), nil
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		// The response was decided on its headers and body, unless no body
		// came: it ends here.
		if r, err := s.onResponse(ctx, x, phaseResponseTrailers); r != nil || err != nil {
			return r, err
		}
		if x.respWaiting {
			x.fillResponse(&extprocv3.HttpBody{EndOfStream: true})
			return s.responseVerdict(ctx, x, phaseResponseTrailers), nil
		}
		return allow(phaseResponseTrailers, nil), nil
	default:
		return nil, fmt.Errorf("unsupported message %T", m)
	}
}

// onHeaders inspects the request now, or waits for its body.
func (s *Server) onHeaders(ctx context.Context, x *exchange, h *extprocv3.HttpHeaders, proto string) *extprocv3.ProcessingResponse {
	req, path, err := s.toRequest(h, x.peer, proto)
	if err != nil {
		return s.uninspectable(ctx, err)
	}
	x.req, x.path = req, path
	x.setID = !strings.EqualFold(req.ID, req.Headers.Get("X-Request-Id"))
	if h.GetEndOfStream() {
		return s.verdict(ctx, x, phaseRequestHeaders)
	}
	if bodilessUpgrade(req) {
		// Envoy sends an upgrade's headers without end_of_stream: what
		// follows them is the upgraded connection's data (WebSocket
		// frames), which the client sends only once the upgrade is
		// answered. Waiting for it as a body would hold the handshake
		// until Envoy's idle timeout (#276). The request is decided on its
		// headers, and Envoy is told to stop sending its stream.
		x.upgrade = true
		return s.verdict(ctx, x, phaseRequestHeaders)
	}
	if x.limit = s.pipeline.BodyLimit(req, s.maxBody); x.limit > 0 {
		switch {
		case x.bodyMode == filterv3.ProcessingMode_BUFFERED, x.bodyMode == filterv3.ProcessingMode_BUFFERED_PARTIAL:
			// Envoy holds the headers until the body is answered.
			x.waiting = true
			return allow(phaseRequestHeaders, nil)
		case x.observe:
			// Envoy forwards the request meanwhile: nothing is held.
			x.waiting, x.gather = true, true
			return allow(phaseRequestHeaders, nil)
		default:
			// Envoy won't send the body in one piece, so it goes
			// uninspected, as an oversized body does.
			req.BodyTruncated = true
		}
	}
	return s.verdict(ctx, x, phaseRequestHeaders)
}

// fillBody adds a body message, up to the limit. It reports whether the
// verdict can be given: always, but for a gathered body that is neither
// complete nor over the limit yet.
func (x *exchange) fillBody(b *extprocv3.HttpBody) bool {
	body := b.GetBody()
	if x.gather {
		// One byte over the limit tells an oversized body.
		room := max(x.limit+1-int64(len(x.streamed)), 0)
		x.streamed = append(x.streamed, body[:min(int64(len(body)), room)]...)
		body = x.streamed
		if !b.GetEndOfStream() && int64(len(body)) <= x.limit {
			return false
		}
	}
	// BUFFERED sends the whole body, trailers or not.
	x.setBody(body, b.GetEndOfStream() || x.bodyMode == filterv3.ProcessingMode_BUFFERED)
	return true
}

// setBody sets the request's body, up to the limit. A body without
// end_of_stream (eos) was cut, or trailers follow: it is complete only when
// it is under the limit and has its full Content-Length.
func (x *exchange) setBody(body []byte, eos bool) {
	x.waiting = false
	n := int64(len(body))
	complete := eos || n < x.limit && n == x.contentLength()
	if complete && x.req.Headers.Get("Content-Length") == "" && x.req.Headers.Get("Transfer-Encoding") == "" {
		// HTTP/2 clients may omit Content-Length; as in SnapshotHeaders,
		// rules must not see a body without either header.
		x.req.Headers.Set("Content-Length", strconv.Itoa(len(body)))
	}
	x.req.Body = body[:min(n, x.limit)]
	x.req.BodyTruncated = n > x.limit || !complete
}

// contentLength returns the request's Content-Length, or -1 without a
// valid one.
func (x *exchange) contentLength() int64 {
	length, err := strconv.ParseInt(x.req.Headers.Get("Content-Length"), 10, 64)
	if err != nil || length < 0 {
		return -1
	}
	return length
}

// onResponse checks that a response message comes after the request was
// decided. It returns nil, nil when the message is to be handled; a
// response stage the request's policy doesn't inspect is continued.
func (s *Server) onResponse(ctx context.Context, x *exchange, p phase) (*extprocv3.ProcessingResponse, error) {
	if x.waiting {
		return nil, errors.New("response before the request body")
	}
	if x.req == nil {
		return s.uninspectable(ctx, errors.New("response before the request headers")), nil
	}
	if x.ex == nil {
		return allow(p, nil), nil
	}
	return nil, nil
}

// maxQueued is the most of a response body queued before its request is
// decided: the largest responses.maxBytes (policy.MaxBodyBytes).
const maxQueued = 10 << 20

func isResponse(m *extprocv3.ProcessingRequest) bool {
	return m.GetResponseHeaders() != nil || m.GetResponseBody() != nil || m.GetResponseTrailers() != nil
}

// queue keeps a response message until the request is decided. Past
// maxQueued body bytes the rest is dropped, end of stream with it, so the
// response is decided at the stream's end on the prefix, as truncated.
func (x *exchange) queue(m *extprocv3.ProcessingRequest) {
	if x.queueCut {
		return
	}
	if b := m.GetResponseBody(); b != nil {
		if room := maxQueued - x.queued; int64(len(b.GetBody())) > room {
			x.queueCut = true
			m = &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{Body: b.GetBody()[:room]}}}
		}
		x.queued += int64(len(m.GetResponseBody().GetBody()))
	}
	x.pending = append(x.pending, m)
}

// replay handles the response messages queued while the request was
// undecided; in observability mode, so their answers go nowhere.
func (s *Server) replay(ctx context.Context, x *exchange) error {
	pending := x.pending
	x.pending, x.queued = nil, 0
	for _, m := range pending {
		if _, err := s.handle(ctx, x, m); err != nil {
			return err
		}
	}
	return nil
}

// onResponseHeaders inspects the response now, or waits for its body.
func (s *Server) onResponseHeaders(ctx context.Context, x *exchange, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	if x.resp != nil {
		// Response headers sent twice: the response was decided on the
		// first.
		return allow(phaseResponseHeaders, nil)
	}
	x.resp = toResponse(h, x.req.Proto)
	eos := h.GetEndOfStream()
	buffered := x.buffersResponses()
	if !eos && x.ex.WantsBody(x.resp.Headers.Get("Content-Type")) {
		x.respLimit = x.ex.BodyLimit()
		switch {
		case x.observe:
			// Envoy streams the body, whatever protocol_config says.
			x.respWaiting, x.respGather = true, true
			return allow(phaseResponseHeaders, nil)
		case buffered:
			// Envoy holds the response headers until the body is
			// answered.
			x.respWaiting = true
			return allow(phaseResponseHeaders, nil)
		default:
			// Envoy won't send the body in one piece: it goes
			// uninspected.
			x.resp.BodyUninspected = true
		}
	}
	r := s.responseVerdict(ctx, x, phaseResponseHeaders)
	if !eos && buffered && r.GetImmediateResponse() == nil {
		// A body the rules don't read: Envoy needn't buffer it, nor send
		// it (when the filter allows mode_override).
		r.ModeOverride = &filterv3.ProcessingMode{ResponseBodyMode: filterv3.ProcessingMode_NONE}
	}
	return r
}

// buffersResponses reports whether Envoy holds response bodies for the
// engine (BUFFERED or BUFFERED_PARTIAL).
func (x *exchange) buffersResponses() bool {
	return x.respMode == filterv3.ProcessingMode_BUFFERED || x.respMode == filterv3.ProcessingMode_BUFFERED_PARTIAL
}

// fillResponse adds a response body message, as fillBody does for the
// request.
func (x *exchange) fillResponse(b *extprocv3.HttpBody) bool {
	body := b.GetBody()
	if x.respGather {
		room := max(x.respLimit+1-int64(len(x.respStreamed)), 0)
		x.respStreamed = append(x.respStreamed, body[:min(int64(len(body)), room)]...)
		body = x.respStreamed
		if !b.GetEndOfStream() && int64(len(body)) <= x.respLimit {
			return false
		}
	}
	x.setResponseBody(body, b.GetEndOfStream() || x.respMode == filterv3.ProcessingMode_BUFFERED)
	return true
}

// setResponseBody sets the response's body, up to the limit. A body
// without end_of_stream (eos) was cut, or trailers follow: it is complete
// only when it is under the limit and has its full Content-Length. Unlike a
// request's, the prefix of a longer one is inspected.
func (x *exchange) setResponseBody(body []byte, eos bool) {
	x.respWaiting = false
	n := int64(len(body))
	length, err := strconv.ParseInt(x.resp.Headers.Get("Content-Length"), 10, 64)
	complete := eos || n < x.respLimit && err == nil && n == length
	x.resp.Body = body[:min(n, x.respLimit)]
	x.resp.BodyTruncated = n > x.respLimit || !complete
}

// responseVerdict inspects the response and answers it in phase p: a
// denied response is replaced.
func (s *Server) responseVerdict(ctx context.Context, x *exchange, p phase) *extprocv3.ProcessingResponse {
	x.respDone = true
	v := x.ex.CheckResponse(ctx, x.resp)
	x.ex.Close()
	x.resp.Body, x.respStreamed = nil, nil
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, s.logger, s.events, x.req, x.path, v)
	}
	if v.Action == pipeline.ActionDeny {
		return denial(x.req, v.Status)
	}
	return allow(p, nil)
}

// denial denies req's stream with status: a gRPC call with a gRPC status.
func denial(req *request.Request, status int) *extprocv3.ProcessingResponse {
	if g := httpadapter.GRPCOf(req.Headers); g != httpadapter.NotGRPC {
		return denyGRPC(g, status, req.ID)
	}
	return deny(status, req.ID)
}

// toResponse reads the response's status and headers. Envoy validated
// them: a missing or odd :status is inspected as 0, and a header name that
// isn't a token is left out.
func toResponse(h *extprocv3.HttpHeaders, proto string) *request.Response {
	fields := h.GetHeaders().GetHeaders()
	resp := &request.Response{Proto: proto, Headers: make(http.Header, len(fields))}
	for _, f := range fields {
		name := f.GetKey()
		value := f.GetValue()
		if raw := f.GetRawValue(); len(raw) > 0 {
			value = string(raw)
		}
		if name == ":status" {
			if code, err := strconv.Atoi(value); err == nil && code >= 100 && code <= 999 {
				resp.Status = code
			}
			continue
		}
		if !httpadapter.IsToken(name) {
			continue
		}
		resp.Headers.Add(name, value)
	}
	return resp
}

// verdict inspects the request and answers it in phase p. When the
// request's policy inspects responses, its evaluation is kept for the
// response, and, if response bodies are inspected, the request's
// Accept-Encoding is removed.
func (s *Server) verdict(ctx context.Context, x *exchange, p phase) *extprocv3.ProcessingResponse {
	var v pipeline.Verdict
	// An upgraded stream has no response to inspect: its data passes
	// untouched once the handshake is allowed.
	if ei, ok := s.pipeline.(pipeline.ExchangeInspector); ok && !x.upgrade {
		v, x.ex = ei.CheckExchange(ctx, x.req)
	} else {
		v = s.pipeline.Check(ctx, x.req)
	}
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, s.logger, s.events, x.req, x.path, v)
	}
	if v.Action == pipeline.ActionDeny {
		return denial(x.req, v.Status)
	}
	m := &extprocv3.HeaderMutation{}
	if x.setID {
		m.SetHeaders = []*corev3.HeaderValueOption{header("x-request-id", x.req.ID)}
	}
	if x.ex != nil {
		// The request body is no longer needed.
		x.req.Body, x.streamed = nil, nil
		if x.ex.BodyLimit() > 0 {
			m.RemoveHeaders = []string{"accept-encoding"}
		}
	}
	if len(m.SetHeaders) == 0 && len(m.RemoveHeaders) == 0 {
		m = nil
	}
	resp := allow(p, m)
	if x.upgrade {
		// CONTINUE_AND_REPLACE without a body mutation: Envoy continues the
		// request now and sends nothing more of it, whatever its body
		// mode; the upgraded connection's data passes untouched.
		resp.GetRequestHeaders().GetResponse().Status = extprocv3.CommonResponse_CONTINUE_AND_REPLACE
	}
	return resp
}

// bodilessUpgrade reports whether r is a GET asking to upgrade the
// connection (a WebSocket handshake) that declares no body: no
// Transfer-Encoding and no Content-Length but 0. One that declares a body
// waits for it, as any request does.
func bodilessUpgrade(r *request.Request) bool {
	if r.Method != http.MethodGet || len(r.Headers.Values("Upgrade")) == 0 || len(r.Headers.Values("Transfer-Encoding")) > 0 {
		return false
	}
	switch cl := r.Headers.Values("Content-Length"); len(cl) {
	case 0:
		return true
	case 1:
		return strings.TrimSpace(cl[0]) == "0"
	default:
		return false
	}
}

// uninspectable refuses a request the engine can't inspect: only a
// misconfigured proxy sends one, and it is not let through.
func (s *Server) uninspectable(ctx context.Context, err error) *extprocv3.ProcessingResponse {
	s.logger.LogAttrs(ctx, slog.LevelError, "invalid ext_proc request", slog.Any("error", err))
	return deny(http.StatusBadRequest, httpadapter.NewRequestID())
}

// toRequest reconstructs the client's request from its headers and
// protocol. It also returns the decoded path for logging.
func (s *Server) toRequest(h *extprocv3.HttpHeaders, peer netip.Addr, proto string) (*request.Request, string, error) {
	fields := h.GetHeaders().GetHeaders()
	headers := make(http.Header, len(fields))
	var method, rawURI, authority, scheme string
	pseudo := map[string]*string{":method": &method, ":path": &rawURI, ":authority": &authority, ":scheme": &scheme}
	for _, f := range fields {
		name := f.GetKey()
		value := f.GetValue()
		if raw := f.GetRawValue(); len(raw) > 0 {
			value = string(raw)
		}
		if strings.HasPrefix(name, ":") {
			dst, ok := pseudo[name]
			if !ok {
				continue // :protocol and the like say nothing the rules read
			}
			if *dst != "" {
				return nil, "", fmt.Errorf("several values for %s", name)
			}
			if value == "" {
				return nil, "", fmt.Errorf("empty %s", name)
			}
			*dst = value
			continue
		}
		if !httpadapter.IsToken(name) {
			return nil, "", fmt.Errorf("invalid header name %q", name)
		}
		// The authority travels in its own field, as in request.Request.
		if strings.EqualFold(name, "Host") {
			continue
		}
		headers.Add(name, value)
	}
	if !httpadapter.IsToken(method) {
		return nil, "", fmt.Errorf("invalid :method %q", method)
	}
	path, err := httpadapter.URIPath(rawURI)
	if err != nil {
		return nil, "", fmt.Errorf(":path: %w", err)
	}
	// Envoy forwards the authority it received; inspect only one that is a
	// valid Host, as the reverse proxy does.
	if !httpguts.ValidHostHeader(authority) {
		return nil, "", fmt.Errorf("invalid :authority %q", authority)
	}
	switch strings.ToLower(scheme) {
	case "", "http":
		scheme = "http"
	case "https":
		scheme = "https"
	default:
		return nil, "", fmt.Errorf("invalid :scheme %q", scheme)
	}
	// Clients send "Content-Length: 0" for an empty POST, PUT or PATCH, but
	// HTTP/2 clients may not. Without it, rule 920180 (POST without
	// Content-Length) scores every empty POST.
	if h.GetEndOfStream() && headers.Get("Content-Length") == "" && headers.Get("Transfer-Encoding") == "" &&
		(method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
		headers.Set("Content-Length", "0")
	}
	id := httpadapter.RequestID(headers.Get("X-Request-Id"))
	if id == "" {
		id = httpadapter.NewRequestID()
	}
	return &request.Request{
		ID:       id,
		Proto:    proto,
		Method:   method,
		Scheme:   scheme,
		Host:     authority,
		RawURI:   rawURI,
		Headers:  headers,
		PeerIP:   peer,
		ClientIP: s.clientIP.Resolve(peer, headers),
	}, path, nil
}

// protocolAttr is the Envoy attribute naming the client's protocol:
// HTTP/1.0, HTTP/1.1, HTTP/2 or HTTP/3.
const protocolAttr = "request.protocol"

// protocol returns the protocol the client spoke, from the attributes
// Envoy sends with the request headers (keyed by the filter's name), or
// HTTP/1.1 when it sends none.
func protocol(msg *extprocv3.ProcessingRequest) string {
	for _, attrs := range msg.GetAttributes() {
		if p := attrs.GetFields()[protocolAttr].GetStringValue(); strings.HasPrefix(p, "HTTP/") {
			return p
		}
	}
	return "HTTP/1.1"
}

// loopback is the address of a Unix-socket peer: a process on the same
// host, like a loopback one.
var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// peerAddr returns the address of the stream's peer, Envoy.
func peerAddr(ctx context.Context) netip.Addr {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return netip.Addr{}
	}
	switch a := p.Addr.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.UnixAddr:
		return loopback
	}
	return netip.Addr{}
}

// phase is the message a response answers.
type phase int

const (
	phaseRequestHeaders phase = iota
	phaseRequestBody
	phaseRequestTrailers
	phaseResponseHeaders
	phaseResponseBody
	phaseResponseTrailers
)

// allow continues phase p, with m, if set, applied to the request Envoy
// forwards (request phases only).
func allow(p phase, m *extprocv3.HeaderMutation) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{HeaderMutation: m}
	switch p {
	case phaseRequestHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: common}}}
	case phaseRequestBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: common}}}
	case phaseRequestTrailers:
		// A trailers response mutates the trailers, not the headers.
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}
	case phaseResponseHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{}}}
	case phaseResponseBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{}}}
	default:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{}}}
	}
}

// deny answers with status and the same plain-text body as the other
// adapters.
func deny(code int, id string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			// #nosec G115 -- an HTTP status
			Status: &typev3.HttpStatus{Code: typev3.StatusCode(code)},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				header("content-type", "text/plain; charset=utf-8"),
				header("x-content-type-options", "nosniff"),
				header("x-request-id", id),
			}},
			Body:    []byte(http.StatusText(code) + "\n"),
			Details: "inkwall_denied",
		},
	}}
}

// denyGRPC answers a denied gRPC call in the trailers-only form: the gRPC
// status in the headers, and no body.
//
// For gRPC, Envoy answers a local reply as a gRPC call itself: HTTP 200,
// content-type application/grpc, grpc_status (or a status from the HTTP
// one) as grpc-status, and the body, if any, as grpc-message. So there is
// no body, which would replace the grpc-message, and the HTTP status stays
// the verdict's, for a client Envoy doesn't take for gRPC (one over
// HTTP/1.1). Envoy takes no gRPC-Web request for gRPC, so a gRPC-Web
// denial is answered with HTTP 200 here, as the gRPC-Web spec says.
func denyGRPC(g httpadapter.GRPCProtocol, code int, id string) *extprocv3.ProcessingResponse {
	httpStatus := code
	if g != httpadapter.GRPC {
		httpStatus = http.StatusOK
	}
	grpcStatus := httpadapter.GRPCCode(code)
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			// #nosec G115 -- an HTTP status
			Status: &typev3.HttpStatus{Code: typev3.StatusCode(httpStatus)},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				header("content-type", g.ContentType()),
				header("grpc-status", strconv.Itoa(int(grpcStatus))),
				header("grpc-message", httpadapter.GRPCMessage(code, id)),
				header("x-content-type-options", "nosniff"),
				header("x-request-id", id),
			}},
			GrpcStatus: &extprocv3.GrpcStatus{Status: uint32(grpcStatus)},
			Details:    "inkwall_denied",
		},
	}}
}

func header(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: name, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}
