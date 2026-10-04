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
	"net/netip"
	"net/url"
	"strconv"

	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
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
}

// Handler is an inspecting reverse proxy.
type Handler struct {
	pipeline *pipeline.Pipeline
	proxy    *httputil.ReverseProxy
	maxBody  int64
	clientIP *clientip.Resolver
	logger   *slog.Logger
}

// New returns a Handler that inspects requests with p.
func New(p *pipeline.Pipeline, cfg Config) (*Handler, error) {
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
			pr.SetXForwarded()
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	return &Handler{pipeline: p, proxy: rp, maxBody: cfg.MaxBodyBytes, clientIP: resolver, logger: logger}, nil
}

// ServeHTTP inspects r, then denies it or forwards it to the upstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := h.toRequest(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	v := h.pipeline.Check(r.Context(), req)
	// Log blocks and detections, and every request that went uninspected
	// unexpectedly (timeout, error, overload). Client cancellations and
	// routes configured to skip inspection are not events.
	if v.Action != pipeline.ActionAllow ||
		(v.Reason != pipeline.ReasonNone && v.Reason != pipeline.ReasonCanceled && v.Reason != pipeline.ReasonSkipped) {
		h.logEvent(r, req, v)
	}
	if v.Action == pipeline.ActionDeny {
		http.Error(w, http.StatusText(v.Status), v.Status)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) toRequest(r *http.Request) (*request.Request, error) {
	peer := peerAddr(r.RemoteAddr)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	rawURI := r.RequestURI
	if rawURI == "" {
		rawURI = r.URL.RequestURI()
	}
	req := &request.Request{
		ID:       requestID(r.Header.Get("X-Request-Id")),
		Proto:    r.Proto,
		Method:   r.Method,
		Scheme:   scheme,
		Host:     r.Host,
		RawURI:   rawURI,
		Headers:  snapshotHeaders(r),
		PeerIP:   peer,
		ClientIP: h.clientIP.Resolve(peer, r.Header),
	}

	if h.maxBody > 0 && r.Body != nil && r.Body != http.NoBody {
		prefix, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		// Hand the upstream the full body: the inspected prefix followed by
		// whatever was not read.
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(prefix), r.Body), Closer: r.Body}
		if int64(len(prefix)) > h.maxBody {
			req.Body = prefix[:h.maxBody]
			req.BodyTruncated = true
		} else {
			req.Body = prefix
		}
	}
	return req, nil
}

func (h *Handler) logEvent(r *http.Request, req *request.Request, v pipeline.Verdict) {
	h.logger.LogAttrs(r.Context(), slog.LevelWarn, "security event",
		slog.String("action", v.Action.String()),
		slog.String("reason", v.Reason.String()),
		slog.Int("status", v.Status),
		slog.Int("interrupting_rule_id", v.InterruptingRuleID),
		slog.Any("rule_ids", v.RuleIDs),
		slog.String("client_ip", addrString(req.ClientIP)),
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", r.URL.Path),
		slog.String("request_id", req.ID),
		slog.Duration("inspection_time", v.Duration),
	)
}

// snapshotHeaders returns a private copy of r's headers for inspection, with
// Transfer-Encoding and Content-Length restored.
//
// The copy matters because an evaluation that times out keeps running after
// the handler has returned, and must not read the live request. Copying costs
// about 0.3µs, well under 0.1% of an evaluation.
//
// net/http moves Transfer-Encoding out of the header map, and Content-Length
// can be absent (HTTP/2) even when the length is known. Without them, rules see
// a POST with neither header and raise a false positive.
func snapshotHeaders(r *http.Request) http.Header {
	h := r.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	if len(r.TransferEncoding) > 0 && h.Get("Transfer-Encoding") == "" {
		h["Transfer-Encoding"] = r.TransferEncoding
	}
	if r.ContentLength > 0 && h.Get("Content-Length") == "" {
		h.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	return h
}

// maxRequestIDLen bounds client-supplied request IDs.
const maxRequestIDLen = 128

// requestID returns id if it is a safe correlation ID (at most 128 of
// [A-Za-z0-9._:-]), and "" otherwise so that one is generated. The value is
// client-controlled and ends up in logs and events.
func requestID(id string) string {
	if id == "" || len(id) > maxRequestIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '-':
		default:
			return ""
		}
	}
	return id
}

type readCloser struct {
	io.Reader
	io.Closer
}

func peerAddr(remoteAddr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
