// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// Exchange is a request's inspection kept for its response, for a policy
// that inspects responses. CheckResponse inspects the response once; Close
// releases the evaluation, and may be called from any goroutine, also
// while CheckResponse runs or after it timed out.
type Exchange struct {
	p *Pipeline

	mu sync.Mutex
	x  rules.Exchange
	// busy: an evaluation of the response is running on x; closed: Close
	// was called, and the evaluation closes x when it finishes.
	busy, closed, used bool

	observe func(Verdict)
}

// OnVerdict sets a function told about the response's verdict (a policy's
// counter).
func (e *Exchange) OnVerdict(observe func(Verdict)) {
	e.observe = observe
}

// FailureMode is the request's failure mode, resolved for the pipeline's
// mode: what an adapter that loses the exchange before the response (the
// SPOE agent's table) does with that response.
func (e *Exchange) FailureMode() FailureMode { return e.p.failure }

// BodyLimit is how much of the response body is inspected: 0 for none.
func (e *Exchange) BodyLimit() int64 { return e.p.responses.MaxBytes }

// WantsBody reports whether a response body with this Content-Type is
// inspected: a body limit is set and the rules read its media type
// (rules.ResponseBodyTypes). Others, such as images and streams (Server-Sent
// Events, gRPC), pass without their body inspected and without being
// counted as oversized.
func (e *Exchange) WantsBody(contentType string) bool {
	return e.BodyLimit() > 0 && InspectedResponseType(contentType)
}

// InspectedResponseType reports whether the rules read a response body
// with this Content-Type.
func InspectedResponseType(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return slices.Contains(rules.ResponseBodyTypes, media)
}

// CheckResponse inspects resp, the response to the exchange's request, with
// its body cut at BodyLimit by the adapter (a longer one is BodyTruncated).
// It returns within the pipeline's timeout, under its admission limit,
// with its failure mode. A body that is truncated or uninspected gets the
// oversize action once the rules found nothing: OversizeDeny replaces the
// response in block mode with 502 Bad Gateway. In block mode, a deny
// replaces the response with the verdict's status.
func (e *Exchange) CheckResponse(ctx context.Context, resp *request.Response) Verdict {
	start := time.Now()
	v := e.check(ctx, resp)
	v.Duration = time.Since(start)
	v.Response = true
	v.Policy = e.p.policy
	if e.p.observer != nil {
		e.p.observer.ObserveVerdict(v)
	}
	if e.observe != nil {
		e.observe(v)
	}
	return v
}

// Refused is the verdict of a response the adapter can't hold for
// inspection (the bodies it holds are at their bound): the failure mode,
// as for an evaluation refused a slot (ReasonOverload), reported as a
// response's verdict. The exchange is spent.
func (e *Exchange) Refused() Verdict {
	e.mu.Lock()
	e.used = true
	e.mu.Unlock()
	v := e.p.failed(ReasonOverload)
	v.Response = true
	v.Policy = e.p.policy
	if e.p.observer != nil {
		e.p.observer.ObserveVerdict(v)
	}
	if e.observe != nil {
		e.observe(v)
	}
	return v
}

func (e *Exchange) check(ctx context.Context, resp *request.Response) Verdict {
	p := e.p
	e.mu.Lock()
	x := e.x
	if e.closed || e.used || x == nil {
		e.mu.Unlock()
		return p.failed(ReasonError)
	}
	e.used = true
	e.mu.Unlock()

	resp = decodeBody(resp, p.responses.MaxBytes)
	v, _ := p.evaluate(ctx, func(ctx context.Context) outcome {
		// busy only once the evaluation runs: refused a slot, it never
		// does, and Close releases x itself.
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return outcome{err: errors.New("exchange closed")}
		}
		e.busy = true
		e.mu.Unlock()
		defer e.release()
		res, err := x.EvaluateResponse(ctx, resp)
		return outcome{res: res, err: err}
	})
	if v.Reason != ReasonNone || !resp.BodyTruncated && !resp.BodyUninspected {
		return v
	}
	// The rules found nothing in what they read, but part of the body, or
	// all of it, went uninspected.
	v.Reason = ReasonOversize
	if p.responses.Oversize == OversizeDeny {
		return p.enforce(v, http.StatusBadGateway)
	}
	return v
}

// release ends the evaluation of the response, and closes it if Close was
// called meanwhile.
func (e *Exchange) release() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.busy = false
	if e.closed && e.x != nil {
		e.x.Close()
		e.x = nil
	}
}

// Close releases the evaluation: now, or when the running evaluation of the
// response finishes.
func (e *Exchange) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if !e.busy && e.x != nil {
		e.x.Close()
		e.x = nil
	}
}

// decodeBody returns resp with its body decoded, up to limit, when it came
// gzip- or deflate-encoded, and without the Content-Encoding header the
// rules would skip it for (CRS skips encoded bodies). A body in another
// encoding is not inspected (BodyUninspected). A body that doesn't decode
// to its end, as one cut by the proxy, keeps the prefix that did, marked
// truncated.
func decodeBody(resp *request.Response, limit int64) *request.Response {
	encoding := strings.ToLower(strings.TrimSpace(resp.Headers.Get("Content-Encoding")))
	if len(resp.Body) == 0 || encoding == "" || encoding == "identity" {
		return resp
	}
	out := *resp
	out.Headers = resp.Headers.Clone()
	out.Headers.Del("Content-Encoding")
	out.Headers.Del("Content-Length")
	var r io.Reader
	var err error
	switch encoding {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(resp.Body))
	case "deflate":
		// HTTP's deflate is zlib; some servers send raw DEFLATE.
		if r, err = zlib.NewReader(bytes.NewReader(resp.Body)); err != nil {
			r, err = flate.NewReader(bytes.NewReader(resp.Body)), nil
		}
	default:
		err = errors.New("unsupported encoding")
	}
	if err != nil {
		out.Body, out.BodyUninspected = nil, true
		return &out
	}
	// One byte over the limit tells a longer body.
	decoded, err := io.ReadAll(io.LimitReader(r, limit+1))
	out.Body = decoded[:min(int64(len(decoded)), limit)]
	out.BodyTruncated = resp.BodyTruncated || int64(len(decoded)) > limit || err != nil
	if len(out.Body) == 0 && err != nil {
		out.Body, out.BodyTruncated, out.BodyUninspected = nil, false, true
	}
	return &out
}
