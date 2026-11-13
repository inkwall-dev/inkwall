// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// DefaultMaxHeldResponseBytes bounds the response bodies the proxy holds
// at once for inspection (Config.MaxHeldResponseBytes).
const DefaultMaxHeldResponseBytes = 64 << 20

// exchangeKey keys the request's exchange in its context, from ServeHTTP
// to the response (inspectResponse).
type exchangeKey struct{}

// exchange is a request let through whose response is inspected.
type exchange struct {
	ex   *pipeline.Exchange
	req  *request.Request
	path string
}

// deniedResponse is the error inspectResponse returns for a response it
// replaces: ReverseProxy then calls proxyError, which writes the denial.
type deniedResponse struct {
	status int
	x      *exchange
}

func (d *deniedResponse) Error() string { return fmt.Sprintf("response denied with %d", d.status) }

// inspectResponse is ReverseProxy's ModifyResponse: it runs before any of
// the response is written to the client. For a request whose policy
// inspects responses, it reads up to the body limit of a body the rules
// read, holding it under the proxy's bound on held bodies, inspects the
// response, and forwards it with the body read put back in front of the
// rest, or replaces it (an error, written by proxyError). Bodies the rules
// don't read (images, streams) aren't held.
func (h *Handler) inspectResponse(res *http.Response) error {
	x, _ := res.Request.Context().Value(exchangeKey{}).(*exchange)
	if x == nil {
		return nil
	}
	ctx := res.Request.Context()
	if res.StatusCode == http.StatusSwitchingProtocols {
		// An upgrade: what follows is the upgraded connection's.
		x.ex.Close()
		return nil
	}
	resp := &request.Response{Proto: x.req.Proto, Status: res.StatusCode, Headers: res.Header.Clone()}
	if res.Body != nil && res.Body != http.NoBody && x.ex.WantsBody(res.Header.Get("Content-Type")) {
		limit := x.ex.BodyLimit()
		// One byte over the limit tells a longer body.
		weight := min(limit+1, h.heldMax)
		if !h.held.TryAcquire(weight) {
			return h.decideResponse(ctx, x, x.ex.Refused())
		}
		prefix, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
		n := int64(len(prefix))
		resp.Body = prefix[:min(n, limit)]
		// A read error cut the body: what was read is inspected, and the
		// client gets the same error after it.
		resp.BodyTruncated = n > limit || err != nil
		res.Body = &heldBody{Reader: io.MultiReader(bytes.NewReader(prefix), res.Body), body: res.Body,
			release: func() { h.held.Release(weight) }}
	}
	return h.decideResponse(ctx, x, x.ex.CheckResponse(ctx, resp))
}

// decideResponse logs v, the response's verdict, and returns the error
// that replaces the response when v denies it.
func (h *Handler) decideResponse(ctx context.Context, x *exchange, v pipeline.Verdict) error {
	x.ex.Close()
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, h.logger, h.events, x.req, x.path, v)
	}
	if v.Action == pipeline.ActionDeny {
		return &deniedResponse{status: v.Status, x: x}
	}
	return nil
}

// proxyError is ReverseProxy's ErrorHandler: a denied response gets the
// denial, as a denied request does; any other error, ReverseProxy's own
// answer (logged, 502).
func (h *Handler) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var d *deniedResponse
	if errors.As(err, &d) {
		if g := httpadapter.GRPCOf(d.x.req.Headers); g != httpadapter.NotGRPC {
			httpadapter.WriteGRPCDenial(w, g, http.StatusOK, d.status, d.x.req.ID)
			return
		}
		httpadapter.WriteDenial(w, d.status, d.x.req.ID, d.x.req.Headers, h.jsonDenials)
		return
	}
	h.proxy.ErrorLog.Printf("http: proxy error: %v", err)
	w.WriteHeader(http.StatusBadGateway)
}

// heldBody is a response body whose prefix was read for inspection: it
// reads the prefix again, then the rest, and gives back its share of the
// held bytes when closed (ReverseProxy closes it once the response is
// copied, or replaced).
type heldBody struct {
	io.Reader
	body    io.Closer
	release func()
	once    sync.Once
}

func (b *heldBody) Close() error {
	b.once.Do(b.release)
	return b.body.Close()
}

// newHeld returns the bound on held response bodies.
func newHeld(max int64) (*semaphore.Weighted, int64) {
	if max <= 0 {
		max = DefaultMaxHeldResponseBytes
	}
	return semaphore.NewWeighted(max), max
}
