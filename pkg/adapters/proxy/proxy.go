// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package proxy implements Inkwall's standalone mode: an HTTP reverse proxy
// that inspects each request and forwards allowed ones to an upstream.
//
// It is used in front of services without a supported ingress, and it is the
// reference adapter: every other adapter must reach the same verdict for the
// same request.
package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// Config configures a Handler.
type Config struct {
	// Upstream is the service that allowed requests are forwarded to.
	Upstream *url.URL
	// MaxBodyBytes is how much of a request body is inspected. The rest is
	// streamed to the upstream uninspected. Zero disables body inspection.
	MaxBodyBytes int64
	// ClientIP resolves the client address behind trusted proxies. Nil
	// trusts no proxies.
	ClientIP *clientip.Resolver
	// Logger receives one security event per denied or logged request.
	// Nil uses slog.Default().
	Logger *slog.Logger
	// JSONDenials answers a denied client that accepts application/json
	// with a JSON body (httpadapter.DenialBody); off: text.
	JSONDenials bool
	// Metrics counts the requests the proxy can't read, and its
	// WebSockets (nil: none).
	Metrics *telemetry.Metrics
	// Events records each security event for the operator (nil: logged
	// only).
	Events *events.Recorder
	// WebSocketMessages inspects the messages of the WebSockets it
	// forwards (websocket.go), each up to MaxBodyBytes. It needs a policy
	// from flags (a *pipeline.Pipeline).
	WebSocketMessages pipeline.WebSocketMessages
	// WebSocketIdleTimeout closes a WebSocket with 1001 (going away) when
	// no bytes pass either way for this long (0: never).
	WebSocketIdleTimeout time.Duration
	// BodyReadTimeout bounds reading the part of a request body that is
	// inspected, from when the engine starts reading it: a client that
	// stalls in it gets 408. The rest streams to the upstream under the
	// server's own limits (0: none but the server's).
	BodyReadTimeout time.Duration
	// ReadTimeout is the server's limit to read a whole request
	// (http.Server.ReadTimeout), set again once BodyReadTimeout's part is
	// read (0: none).
	ReadTimeout time.Duration
}

// Handler is an inspecting reverse proxy.
type Handler struct {
	pipeline pipeline.Inspector
	proxy    *httputil.ReverseProxy
	maxBody  int64
	clientIP *clientip.Resolver
	logger   *slog.Logger
	events   *events.Recorder
	messages pipeline.WebSocketMessages
	metrics  *telemetry.Metrics
	// jsonDenials: Config.JSONDenials.
	jsonDenials bool
	wsIdle      time.Duration
	bodyTimeout time.Duration
	readTimeout time.Duration
	// live are the open WebSockets (longlived.go).
	live liveConns
}

// New returns a Handler that inspects requests with p.
func New(p pipeline.Inspector, cfg Config) (*Handler, error) {
	if cfg.Upstream == nil || cfg.Upstream.Scheme == "" || cfg.Upstream.Host == "" {
		return nil, errors.New("upstream must be an absolute URL")
	}
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
	upstream := cfg.Upstream
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			// Forward what was inspected: the client's Host and the query
			// exactly as received. SetURL replaces the Host, and Rewrite mode
			// drops query pairs containing ';' or a malformed '%'.
			pr.Out.Host = pr.In.Host
			pr.Out.URL.RawQuery = joinQuery(upstream.RawQuery, pr.In.URL.RawQuery)
			setForwarded(pr, resolver)
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	if cfg.WebSocketMessages != pipeline.MessagesOff {
		if _, ok := p.(messageInspector); !ok {
			return nil, errors.New("WebSocket message inspection needs a policy from flags")
		}
		if cfg.MaxBodyBytes <= 0 {
			return nil, errors.New("WebSocket message inspection needs a body limit")
		}
	}
	if cfg.WebSocketIdleTimeout < 0 || cfg.BodyReadTimeout < 0 {
		return nil, errors.New("timeouts must not be negative")
	}
	return &Handler{pipeline: p, proxy: rp, maxBody: cfg.MaxBodyBytes, clientIP: resolver, logger: logger, events: cfg.Events,
		messages: cfg.WebSocketMessages, metrics: cfg.Metrics, jsonDenials: cfg.JSONDenials,
		wsIdle: cfg.WebSocketIdleTimeout, bodyTimeout: cfg.BodyReadTimeout, readTimeout: cfg.ReadTimeout}, nil
}

// ServeHTTP inspects r, then denies it or forwards it to the upstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// A raw '#' is not valid in a request target (RFC 9112), and clients
	// never send fragments. Coraza stops reading the URI at '#' while the
	// upstream still parses what follows, so parameters after it would
	// reach the application uninspected.
	if strings.ContainsRune(r.RequestURI, '#') {
		h.metrics.AdapterError(telemetry.ErrInvalidRequest)
		httpadapter.WriteDenial(w, http.StatusBadRequest, httpadapter.NewRequestID(), r.Header, h.jsonDenials)
		return
	}
	// Only the origin form ("/path?query"). For an absolute-form target
	// ("http://host/path"), Go takes the Host from the URL without checking
	// it, and the client forwarding the request sends another one (punycode,
	// or none if it is invalid): the engine would choose the policy by a Host
	// the upstream never sees. The asterisk form would be forwarded as "/*".
	if r.RequestURI != "" && !strings.HasPrefix(r.RequestURI, "/") {
		h.metrics.AdapterError(telemetry.ErrInvalidRequest)
		httpadapter.WriteDenial(w, http.StatusBadRequest, httpadapter.NewRequestID(), r.Header, h.jsonDenials)
		return
	}
	// Forward only a Host the client sends as it is: what was inspected.
	if !httpguts.ValidHostHeader(r.Host) {
		h.metrics.AdapterError(telemetry.ErrInvalidRequest)
		httpadapter.WriteDenial(w, http.StatusBadRequest, httpadapter.NewRequestID(), r.Header, h.jsonDenials)
		return
	}
	req, err := h.readRequest(r, w, start)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// The client stalled in the part of its body that is inspected.
		h.metrics.AdapterError(telemetry.ErrInvalidRequest)
		w.Header().Set("Connection", "close")
		httpadapter.WriteDenial(w, http.StatusRequestTimeout, httpadapter.NewRequestID(), r.Header, h.jsonDenials)
		return
	}
	if err != nil {
		h.metrics.AdapterError(telemetry.ErrInvalidRequest)
		httpadapter.WriteDenial(w, http.StatusBadRequest, httpadapter.NewRequestID(), r.Header, h.jsonDenials)
		return
	}

	v := h.pipeline.Check(r.Context(), req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(r.Context(), h.logger, h.events, req, r.URL.Path, v)
	}
	if v.Action == pipeline.ActionDeny {
		// As a gRPC server answers a failed call: HTTP 200, trailers-only.
		if g := httpadapter.GRPCOf(req.Headers); g != httpadapter.NotGRPC {
			httpadapter.WriteGRPCDenial(w, g, http.StatusOK, v.Status, req.ID)
			return
		}
		httpadapter.WriteDenial(w, v.Status, req.ID, req.Headers, h.jsonDenials)
		return
	}
	if h.messages != pipeline.MessagesOff && v.Reason != pipeline.ReasonSkipped &&
		httpguts.HeaderValuesContainsToken(r.Header.Values("Upgrade"), "websocket") {
		// No extension, so no compressed messages (permessage-deflate):
		// a frame with an RSV bit is then an error.
		r.Header.Del("Sec-Websocket-Extensions")
		w = &liveWriter{ResponseWriter: &inspectingWriter{ResponseWriter: w, h: h, ctx: r.Context(), req: req, path: r.URL.Path, mi: h.pipeline.(messageInspector)}, h: h}
	} else if httpguts.HeaderValuesContainsToken(r.Header.Values("Upgrade"), "websocket") {
		w = &liveWriter{ResponseWriter: &countingWriter{ResponseWriter: w, metrics: h.metrics}, h: h}
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) toRequest(r *http.Request) (*request.Request, error) {
	return h.readRequest(r, nil, time.Time{})
}

// readRequest reads r for the pipeline; w, the request's start, is for
// BodyReadTimeout (nil: none).
func (h *Handler) readRequest(r *http.Request, w http.ResponseWriter, start time.Time) (*request.Request, error) {
	peer := httpadapter.PeerAddr(r.RemoteAddr)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	rawURI := r.RequestURI
	if rawURI == "" {
		rawURI = r.URL.RequestURI()
	}
	id := httpadapter.RequestID(r.Header.Get("X-Request-Id"))
	if id == "" {
		// Generate one so events can always be correlated; the upstream
		// receives it as X-Request-Id.
		id = httpadapter.NewRequestID()
		r.Header.Set("X-Request-Id", id)
	}
	req := &request.Request{
		ID:       id,
		Proto:    r.Proto,
		Method:   r.Method,
		Scheme:   scheme,
		Host:     r.Host,
		RawURI:   rawURI,
		Headers:  forwardedHeaders(r),
		PeerIP:   peer,
		ClientIP: h.clientIP.Resolve(peer, r.Header),
	}

	if r.Body == nil || r.Body == http.NoBody {
		return req, nil
	}
	if limit := h.pipeline.BodyLimit(req, h.maxBody); limit > 0 {
		var rc *http.ResponseController
		if h.bodyTimeout > 0 && w != nil {
			// Only the inspected part; then the server's whole-request
			// limit again, from the request's start. Unsupported
			// (HTTP/2): the server's limits alone.
			rc = http.NewResponseController(w)
			if rc.SetReadDeadline(time.Now().Add(h.bodyTimeout)) != nil {
				rc = nil
			}
		}
		prefix, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if rc != nil && err == nil {
			var after time.Time
			if h.readTimeout > 0 {
				after = start.Add(h.readTimeout)
			}
			_ = rc.SetReadDeadline(after)
		}
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		// Hand the upstream the full body: the inspected prefix followed by
		// whatever was not read.
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(prefix), r.Body), Closer: r.Body}
		if int64(len(prefix)) > limit {
			req.Body = prefix[:limit]
			req.BodyTruncated = true
		} else {
			req.Body = prefix
		}
	}
	return req, nil
}

// forwardedHeaders returns the request's headers as ReverseProxy forwards
// them, to inspect what the upstream gets: without the headers the
// Connection header names (hop-by-hop, RFC 9110 7.6.1), which it drops.
// Otherwise "Connection: Content-Type" would show the engine a media type
// the upstream never sees, such as a gRPC one whose messages aren't
// inspected, for a body the upstream then reads as it reads one without a
// media type (Rack: as a form). Connection and Upgrade (kept for an
// upgrade) and the framing headers, which Go sets itself, stay.
func forwardedHeaders(r *http.Request) http.Header {
	h := httpadapter.SnapshotHeaders(r)
	for _, v := range r.Header.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			switch name = http.CanonicalHeaderKey(textproto.TrimString(name)); name {
			case "", "Connection", "Upgrade", "Content-Length", "Transfer-Encoding":
			default:
				h.Del(name)
			}
		}
	}
	return h
}

// setForwarded sets X-Forwarded-For, -Proto and -Host on the outbound
// request. Rewrite mode removes the incoming values first. From a trusted
// proxy they are kept and the proxy's address is appended, so the upstream
// still sees the real client and the original scheme; from anyone else they
// are rebuilt from the connection, so clients cannot spoof them.
func setForwarded(pr *httputil.ProxyRequest, resolver *clientip.Resolver) {
	peer := httpadapter.PeerAddr(pr.In.RemoteAddr)
	if !resolver.Trusts(peer) {
		pr.SetXForwarded()
		return
	}
	in := pr.In.Header
	xff := strings.Join(in.Values("X-Forwarded-For"), ", ")
	if peer.IsValid() {
		if xff != "" {
			xff += ", "
		}
		xff += peer.String()
	}
	if xff != "" {
		pr.Out.Header.Set("X-Forwarded-For", xff)
	}
	proto := in.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
		if pr.In.TLS != nil {
			proto = "https"
		}
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	host := in.Get("X-Forwarded-Host")
	if host == "" {
		host = pr.In.Host
	}
	pr.Out.Header.Set("X-Forwarded-Host", host)
}

func joinQuery(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "&" + b
	}
}

type readCloser struct {
	io.Reader
	io.Closer
}
