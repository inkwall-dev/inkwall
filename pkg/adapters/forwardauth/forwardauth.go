// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package forwardauth implements the forward-auth adapter used by Traefik's
// ForwardAuth middleware.
//
// For every client request the proxy sends a subrequest to Path. The original
// method, URI and host arrive in X-Forwarded-* headers, the client's other
// headers are copied, and the body is included when the proxy is configured
// to forward it. A 2xx answer lets the request through; the proxy returns any
// other answer to the client as is.
//
// The proxy must overwrite client-supplied X-Forwarded-* headers. In Traefik
// that is trustForwardHeader: false. With true, Traefik keeps a client's own
// X-Forwarded-Uri, and the engine would inspect a URI chosen by the attacker
// while the real one is forwarded.
//
// The proxy must also forward the body (Traefik: forwardBody: true with a
// maxBodySize above the engine's limit). Otherwise bodies reach the
// application uninspected.
package forwardauth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Path is where the proxy sends its subrequests.
const Path = "/v1/forward-auth"

// Headers the proxy adds to describe the original request. They are not part
// of that request, so they are removed before inspection.
var synthesized = []string{
	"X-Forwarded-Method",
	"X-Forwarded-Uri",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
}

// Config configures a Handler.
type Config struct {
	// MaxBodyBytes is how much of a forwarded body is inspected. Zero
	// disables body inspection.
	MaxBodyBytes int64
	// ClientIP resolves the client address from X-Forwarded-For. The proxy
	// is the direct peer, so its address must be trusted. Nil trusts no
	// proxies.
	ClientIP *clientip.Resolver
	// Logger receives one security event per denied or logged request.
	// Nil uses slog.Default().
	Logger *slog.Logger
}

// Handler answers forward-auth subrequests.
type Handler struct {
	pipeline *pipeline.Pipeline
	maxBody  int64
	clientIP *clientip.Resolver
	logger   *slog.Logger
}

// New returns a Handler that inspects requests with p.
func New(p *pipeline.Pipeline, cfg Config) (*Handler, error) {
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
	return &Handler{pipeline: p, maxBody: cfg.MaxBodyBytes, clientIP: resolver, logger: logger}, nil
}

// ServeHTTP inspects the request described by r and answers 200 to allow it,
// or the verdict's status to deny it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	req, path, err := h.toRequest(r)
	if err != nil {
		// Only a misconfigured proxy sends this; the request can't be
		// inspected, so it is not let through.
		h.logger.LogAttrs(r.Context(), slog.LevelError, "invalid forward-auth request", slog.Any("error", err))
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	v := h.pipeline.Check(r.Context(), req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(r.Context(), h.logger, req, path, v)
	}
	if v.Action == pipeline.ActionDeny {
		http.Error(w, http.StatusText(v.Status), v.Status)
		return
	}
	// The proxy copies headers listed in its authResponseHeaders onto the
	// request it forwards, so the upstream can receive the request ID.
	w.Header().Set("X-Request-Id", req.ID)
	w.WriteHeader(http.StatusOK)
}

// toRequest reconstructs the client's request. It also returns the decoded
// path for logging.
func (h *Handler) toRequest(r *http.Request) (*request.Request, string, error) {
	method, err := single(r.Header, "X-Forwarded-Method")
	if err != nil {
		return nil, "", err
	}
	if !httpadapter.IsToken(method) {
		return nil, "", fmt.Errorf("invalid X-Forwarded-Method %q", method)
	}
	rawURI, err := single(r.Header, "X-Forwarded-Uri")
	if err != nil {
		return nil, "", err
	}
	path, err := httpadapter.URIPath(rawURI)
	if err != nil {
		return nil, "", fmt.Errorf("X-Forwarded-Uri: %w", err)
	}
	host, err := optional(r.Header, "X-Forwarded-Host")
	if err != nil {
		return nil, "", err
	}
	scheme := "http"
	if proto, _ := optional(r.Header, "X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		scheme = "https"
	}

	headers := httpadapter.SnapshotHeaders(r)
	for _, name := range synthesized {
		headers.Del(name)
	}
	// Traefik sends no Content-Length when the forwarded body is empty, while
	// clients send "Content-Length: 0" for an empty POST, PUT or PATCH.
	// Without it, rule 920180 (POST without Content-Length) scores every
	// empty POST.
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 && headers.Get("Content-Length") == "" &&
		(method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
		headers.Set("Content-Length", "0")
	}
	id := httpadapter.RequestID(headers.Get("X-Request-Id"))
	if id == "" {
		id = httpadapter.NewRequestID()
	}
	peer := httpadapter.PeerAddr(r.RemoteAddr)
	req := &request.Request{
		ID:       id,
		Proto:    r.Proto,
		Method:   method,
		Scheme:   scheme,
		Host:     host,
		RawURI:   rawURI,
		Headers:  headers,
		PeerIP:   peer,
		ClientIP: h.clientIP.Resolve(peer, r.Header),
	}

	if h.maxBody > 0 && r.Body != nil && r.Body != http.NoBody && h.pipeline.InspectsBody(rawURI) {
		prefix, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
		if err != nil {
			return nil, "", fmt.Errorf("read body: %w", err)
		}
		if int64(len(prefix)) > h.maxBody {
			req.Body = prefix[:h.maxBody]
			req.BodyTruncated = true
		} else {
			req.Body = prefix
		}
	}
	return req, path, nil
}

// single returns the only value of a required header. Several values mean
// something other than the proxy set it, so the request is rejected rather
// than guessing which one the proxy acted on.
func single(h http.Header, name string) (string, error) {
	switch vs := h.Values(name); len(vs) {
	case 0:
		return "", fmt.Errorf("missing %s", name)
	case 1:
		if vs[0] == "" {
			return "", fmt.Errorf("empty %s", name)
		}
		return vs[0], nil
	default:
		return "", fmt.Errorf("%d values for %s", len(vs), name)
	}
}

func optional(h http.Header, name string) (string, error) {
	if vs := h.Values(name); len(vs) > 1 {
		return "", fmt.Errorf("%d values for %s", len(vs), name)
	}
	return h.Get(name), nil
}
