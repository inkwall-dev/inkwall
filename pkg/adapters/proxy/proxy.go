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
	"net/url"
	"strings"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
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
			// Forward what was inspected: the client's Host and the query
			// exactly as received. SetURL replaces the Host, and Rewrite mode
			// drops query pairs containing ';' or a malformed '%'.
			pr.Out.Host = pr.In.Host
			pr.Out.URL.RawQuery = joinQuery(upstream.RawQuery, pr.In.URL.RawQuery)
			setForwarded(pr, resolver)
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	return &Handler{pipeline: p, proxy: rp, maxBody: cfg.MaxBodyBytes, clientIP: resolver, logger: logger}, nil
}

// ServeHTTP inspects r, then denies it or forwards it to the upstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A raw '#' is not valid in a request target (RFC 9112), and clients
	// never send fragments. Coraza stops reading the URI at '#' while the
	// upstream still parses what follows, so parameters after it would
	// reach the application uninspected.
	if strings.ContainsRune(r.RequestURI, '#') {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	req, err := h.toRequest(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	v := h.pipeline.Check(r.Context(), req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(r.Context(), h.logger, req, r.URL.Path, v)
	}
	if v.Action == pipeline.ActionDeny {
		http.Error(w, http.StatusText(v.Status), v.Status)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) toRequest(r *http.Request) (*request.Request, error) {
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
		Headers:  httpadapter.SnapshotHeaders(r),
		PeerIP:   peer,
		ClientIP: h.clientIP.Resolve(peer, r.Header),
	}

	if h.maxBody > 0 && r.Body != nil && r.Body != http.NoBody && h.pipeline.InspectsBody(rawURI) {
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
