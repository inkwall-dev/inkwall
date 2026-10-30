// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// fuzzInspector records the requests it is asked to check, and allows them.
type fuzzInspector struct {
	mu  sync.Mutex
	got []*request.Request
}

func (i *fuzzInspector) Check(_ context.Context, r *request.Request) pipeline.Verdict {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.got = append(i.got, r)
	return pipeline.Verdict{}
}

func (*fuzzInspector) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

func (i *fuzzInspector) requests() []*request.Request {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.got
}

// received is a request as a server read it.
type received struct {
	requestURI, path, rawQuery, host, requestID string
	body                                        []byte
}

// recorder is a server handler that records the requests it reads.
type recorder struct {
	mu  sync.Mutex
	got []received
	// next, if set, serves the request after it is recorded.
	next atomic.Pointer[http.Handler]
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	in := received{r.RequestURI, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("X-Request-Id"), nil}
	if next := rec.next.Load(); next != nil {
		rec.mu.Lock()
		rec.got = append(rec.got, in)
		rec.mu.Unlock()
		(*next).ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	in.body = body
	rec.mu.Lock()
	rec.got = append(rec.got, in)
	rec.mu.Unlock()
}

func (rec *recorder) take() []received {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.got
	rec.got = nil
	return got
}

const fuzzMaxBody = 16

// FuzzProxy sends the first HTTP/1.x request of arbitrary bytes to the
// proxy through net/http's server. A request is either refused with 400
// before inspection, or inspected with an origin-form target and a valid
// Host. Whatever reaches the upstream was inspected first, as the upstream receives it: the same path and query,
// the same Host, the same request ID, and a body of which the inspected part
// is a prefix; the upstream gets the whole body.
func FuzzProxy(f *testing.F) {
	up := &recorder{}
	upstream := httptest.NewServer(up)
	f.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		f.Fatal(err)
	}
	front := &recorder{}
	srv := httptest.NewServer(front)
	f.Cleanup(srv.Close)

	f.Fuzz(func(t *testing.T, raw []byte) {
		// The first request, and its body as the server reads it.
		br := bufio.NewReader(bytes.NewReader(raw))
		r, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		first := raw[:len(raw)-br.Buffered()]

		insp := &fuzzInspector{}
		h, err := New(insp, Config{Upstream: target, MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		var handler http.Handler = h
		front.next.Store(&handler)
		front.take()
		up.take()
		status := send(t, srv.Listener.Addr().String(), first)

		served := front.take()
		inspected := insp.requests()
		fwd := up.take()
		if len(served) > 1 || len(inspected) > len(served) || len(fwd) > len(inspected) {
			t.Fatalf("served %d, inspected %d, forwarded %d", len(served), len(inspected), len(fwd))
		}
		if len(inspected) == 0 {
			// Refused before inspection: a fragment, a target not in
			// origin form (absolute or asterisk), an invalid Host.
			if len(served) > 0 && status != http.StatusBadRequest {
				t.Fatalf("%q answered %d uninspected, want 400", served[0].requestURI, status)
			}
			return
		}
		req := inspected[0]
		if req.RawURI != served[0].requestURI || !strings.HasPrefix(req.RawURI, "/") || strings.ContainsRune(req.RawURI, '#') {
			t.Errorf("inspected URI %q, received %q", req.RawURI, served[0].requestURI)
		}
		if !httpguts.ValidHostHeader(req.Host) {
			t.Errorf("inspected invalid Host %q", req.Host)
		}
		if len(req.Body) > fuzzMaxBody || !bytes.HasPrefix(body, req.Body) || req.BodyTruncated != (len(body) > fuzzMaxBody) {
			t.Errorf("inspected body %q (truncated %v) of %q, limit %d", req.Body, req.BodyTruncated, body, fuzzMaxBody)
		}
		if len(fwd) == 0 {
			return
		}
		out := fwd[0]
		u, err := url.ParseRequestURI(req.RawURI)
		if err != nil {
			t.Fatalf("forwarded a request whose inspected URI %q doesn't parse: %v", req.RawURI, err)
		}
		if out.path != u.Path || out.rawQuery != u.RawQuery {
			t.Errorf("inspected path %q query %q, forwarded path %q query %q", u.Path, u.RawQuery, out.path, out.rawQuery)
		}
		// Without a Host (HTTP/1.0), the upstream gets its own.
		if out.host != req.Host && (req.Host != "" || out.host != target.Host) {
			t.Errorf("inspected Host %q, forwarded %q", req.Host, out.host)
		}
		if out.requestID != req.ID {
			t.Errorf("inspected request ID %q, forwarded %q", req.ID, out.requestID)
		}
		if !bytes.Equal(out.body, body) {
			t.Errorf("forwarded body %q, received %q", out.body, body)
		}
	})
}

// send writes raw, one request, to a new connection to addr and returns the
// answer's status. The connection stays open until then: net/http cancels a request
// whose client has gone, which would let the forwarded request outlive the
// test.
func send(t *testing.T, addr string, raw []byte) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}
