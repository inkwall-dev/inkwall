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
	"net/http"
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

	policy  string
	observe func(Verdict)

	// others are the exchanges of the request's other policies
	// (JoinExchanges), which inspect the response too.
	others []*Exchange
}

// JoinExchanges returns one Exchange for the exchanges of a request
// inspected by several policies: the response is inspected by each, each
// to its own body limit, and gets the strictest verdict. nil for none.
func JoinExchanges(xs []*Exchange) *Exchange {
	if len(xs) == 0 {
		return nil
	}
	x := xs[0]
	x.others = append(x.others, xs[1:]...)
	return x
}

// OnVerdict sets the policy the response's verdict names, and a function
// told about that verdict (a policy's counter).
func (e *Exchange) OnVerdict(policy string, observe func(Verdict)) {
	e.policy, e.observe = policy, observe
}

// BodyLimit is how much of the response body is inspected: 0 for none.
func (e *Exchange) BodyLimit() int64 {
	limit := e.p.responses.MaxBytes
	for _, o := range e.others {
		limit = max(limit, o.p.responses.MaxBytes)
	}
	return limit
}

// WantsBody reports whether a response body with this Content-Type
// (ResponseContentType of the headers) is inspected: a body limit is set
// and the rules read its media type (rules.ResponseBodyType). Others, such
// as images and streams (Server-Sent Events, gRPC), pass without their
// body inspected and without being counted as oversized.
func (e *Exchange) WantsBody(contentType string) bool {
	return e.BodyLimit() > 0 && InspectedResponseType(contentType)
}

// InspectedResponseType reports whether the rules read a response body
// with this Content-Type: rules.ResponseBodyType, so also one with a
// structured syntax suffix (+json, +xml), one a strict parser rejects, or
// none.
func InspectedResponseType(contentType string) bool {
	return rules.ResponseBodyType(contentType) != ""
}

// ResponseContentType is the Content-Type of a response with headers h,
// as WantsBody takes it: its values joined with ",", so a header sent
// twice, which isn't one type, reads as text.
func ResponseContentType(h http.Header) string {
	return strings.Join(h.Values("Content-Type"), ",")
}

// partial reports whether resp is a part of its body (206 Partial Content,
// or a multipart/byteranges body) of a type the rules read: a part can't
// be inspected as the whole, as a leak cut across parts would pass.
// Adapters remove a request's Range and If-Range for this when responses
// are inspected; an upstream that answers with a part anyway has the body
// counted as uninspected.
func partial(resp *request.Response) bool {
	ct := ResponseContentType(resp.Headers)
	media, _, _ := strings.Cut(ct, ";")
	if strings.EqualFold(strings.TrimSpace(media), "multipart/byteranges") {
		return true
	}
	return resp.Status == http.StatusPartialContent && InspectedResponseType(ct)
}

// CheckResponse inspects resp, the response to the exchange's request, with
// its body cut at BodyLimit by the adapter (a longer one is BodyTruncated).
// It returns within the pipeline's timeout, under its admission limit,
// with its failure mode. A body that is truncated or uninspected gets the
// oversize action once the rules found nothing: OversizeDeny replaces the
// response in block mode with 502 Bad Gateway. In block mode, a deny
// replaces the response with the verdict's status.
func (e *Exchange) CheckResponse(ctx context.Context, resp *request.Response) Verdict {
	v := e.checkResponse(ctx, cut(resp, e.p.responses.MaxBytes))
	for _, o := range e.others {
		if v.Action == ActionDeny {
			break
		}
		if ov := o.checkResponse(ctx, cut(resp, o.p.responses.MaxBytes)); Stricter(ov, v) {
			v = ov
		}
	}
	return v
}

// cut returns resp with its body cut at limit, as the adapter would have
// read it for that limit.
func cut(resp *request.Response, limit int64) *request.Response {
	if int64(len(resp.Body)) <= limit {
		return resp
	}
	out := *resp
	out.Body, out.BodyTruncated = resp.Body[:limit], true
	return &out
}

func (e *Exchange) checkResponse(ctx context.Context, resp *request.Response) Verdict {
	start := time.Now()
	v := e.check(ctx, resp)
	v.Duration = time.Since(start)
	v.Response = true
	v.Policy = e.policy
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

	if p.responses.MaxBytes > 0 && partial(resp) {
		out := *resp
		out.Body, out.BodyTruncated, out.BodyUninspected = nil, false, true
		resp = &out
	}
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
	for _, o := range e.others {
		o.Close()
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
// rules would skip it for (CRS skips encoded bodies). Every
// Content-Encoding value counts, as a client decodes the list of all: a
// body in another encoding, or in more than one, is not inspected
// (BodyUninspected). A body that doesn't decode to its end, as one cut by
// the proxy, keeps the prefix that did, marked truncated.
func decodeBody(resp *request.Response, limit int64) *request.Response {
	var codings []string
	for _, v := range resp.Headers.Values("Content-Encoding") {
		for c := range strings.SplitSeq(v, ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" && c != "identity" {
				codings = append(codings, c)
			}
		}
	}
	if len(resp.Body) == 0 || len(codings) == 0 {
		return resp
	}
	encoding := codings[0]
	if len(codings) > 1 {
		encoding = "several"
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
