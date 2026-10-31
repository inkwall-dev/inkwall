// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package extproc implements the ext_proc adapter used by Envoy's external
// processing filter (envoy.service.ext_proc.v3), and so by Envoy Gateway.
//
// Envoy opens one gRPC stream per HTTP request and sends the request
// headers, then the body if its processing mode asks for it. The adapter
// answers an allowed request with CONTINUE and a denied one with an
// immediate response carrying the verdict's status. Later messages (the
// response headers and body, if the filter sends them) are answered with
// CONTINUE.
//
// The body is inspected when the policy asks for it and Envoy sends it in
// one message: request_body_mode BUFFERED or BUFFERED_PARTIAL. A body Envoy
// doesn't send that way (NONE, STREAMED, ...) goes uninspected, and is
// handled like a body over the policy's limit (body.onOversize). With
// BUFFERED_PARTIAL, a body Envoy cut at its buffer limit is handled the
// same way.
//
// In observability mode (detect mode) Envoy doesn't wait for the answers,
// and the adapter sends none. The body comes in chunks there (STREAMED, the
// only mode Envoy allows, whatever protocol_config says): they are gathered
// up to the limit, and the stream is closed once the request is decided. A
// stream that ends first is decided on what came.
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
}

// Process handles the stream of one HTTP request.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	x := &exchange{peer: peerAddr(ctx)}
	for first := true; ; first = false {
		msg, err := stream.Recv()
		if err != nil && x.observe && x.waiting {
			// Envoy sent no more of the body: decide on what came, even
			// though the stream is gone.
			x.req.Body, x.req.BodyTruncated = x.streamed, true
			s.verdict(context.WithoutCancel(ctx), x, phaseRequestBody)
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
			x.observe = msg.GetObservabilityMode()
		}
		resp, err := s.handle(ctx, x, msg)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelError, "invalid ext_proc stream", slog.Any("error", err))
			return status.Error(codes.InvalidArgument, err.Error())
		}
		// In observability mode Envoy doesn't wait, and ignores answers;
		// once the request is decided, nothing more is needed.
		if x.observe {
			if x.req == nil || !x.waiting {
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
		return allow(phaseRequestBody, ""), nil
	case *extprocv3.ProcessingRequest_RequestTrailers:
		if x.req == nil {
			return s.uninspectable(ctx, errors.New("request trailers before the request headers")), nil
		}
		if x.waiting {
			// The body ended with the last body message, or was empty.
			x.fillBody(&extprocv3.HttpBody{EndOfStream: true})
			return s.verdict(ctx, x, phaseRequestTrailers), nil
		}
		return allow(phaseRequestTrailers, ""), nil
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return s.onResponse(ctx, x, phaseResponseHeaders)
	case *extprocv3.ProcessingRequest_ResponseBody:
		return s.onResponse(ctx, x, phaseResponseBody)
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return s.onResponse(ctx, x, phaseResponseTrailers)
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
	if x.limit = s.pipeline.BodyLimit(req, s.maxBody); x.limit > 0 {
		switch {
		case x.bodyMode == filterv3.ProcessingMode_BUFFERED, x.bodyMode == filterv3.ProcessingMode_BUFFERED_PARTIAL:
			// Envoy holds the headers until the body is answered.
			x.waiting = true
			return allow(phaseRequestHeaders, "")
		case x.observe:
			// Envoy forwards the request meanwhile: nothing is held.
			x.waiting, x.gather = true, true
			return allow(phaseRequestHeaders, "")
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
	x.waiting = false
	// BUFFERED sends the whole body (trailers may follow); BUFFERED_PARTIAL
	// sends it without end_of_stream when it was cut at the buffer limit.
	complete := b.GetEndOfStream() || x.bodyMode == filterv3.ProcessingMode_BUFFERED
	if complete && x.req.Headers.Get("Content-Length") == "" && x.req.Headers.Get("Transfer-Encoding") == "" {
		// HTTP/2 clients may omit Content-Length; as in SnapshotHeaders,
		// rules must not see a body without either header.
		x.req.Headers.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if int64(len(body)) > x.limit {
		x.req.Body = body[:x.limit]
		x.req.BodyTruncated = true
		return true
	}
	x.req.Body = body
	x.req.BodyTruncated = !complete
	return true
}

// onResponse continues the response stages: the request was decided
// already.
func (s *Server) onResponse(ctx context.Context, x *exchange, p phase) (*extprocv3.ProcessingResponse, error) {
	if x.waiting {
		return nil, errors.New("response before the request body")
	}
	if x.req == nil {
		return s.uninspectable(ctx, errors.New("response before the request headers")), nil
	}
	return allow(p, ""), nil
}

// verdict inspects the request and answers it in phase p.
func (s *Server) verdict(ctx context.Context, x *exchange, p phase) *extprocv3.ProcessingResponse {
	v := s.pipeline.Check(ctx, x.req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, s.logger, s.events, x.req, x.path, v)
	}
	if v.Action == pipeline.ActionDeny {
		return deny(v.Status, x.req.ID)
	}
	if x.setID {
		return allow(p, x.req.ID)
	}
	return allow(p, "")
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

// allow continues phase p. A non-empty id is set as X-Request-Id on the
// request Envoy forwards.
func allow(p phase, id string) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{}
	if id != "" {
		common.HeaderMutation = &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{header("x-request-id", id)}}
	}
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

func header(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: name, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}
