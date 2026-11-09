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

// take returns the requests checked since the last take.
func (i *fuzzInspector) take() []*request.Request {
	i.mu.Lock()
	defer i.mu.Unlock()
	got := i.got
	i.got = nil
	return got
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
	p := newFuzzProxy(f)
	f.Fuzz(p.check)
}

// fuzzProxy is one Handler, as the engine runs one, behind a recording
// front server and in front of a recording upstream. The Handler and its
// transport are shared by every input: a Handler per input would leave its
// transport's idle connection to the upstream open (IdleConnTimeout), and
// tens of thousands of them, with their goroutines and buffers, stall the
// fuzz workers until an answer misses send's deadline.
type fuzzProxy struct {
	insp      *fuzzInspector
	front, up *recorder
	target    *url.URL
	addr      string
	// upConns counts the connections the upstream accepted.
	upConns atomic.Int64
}

func newFuzzProxy(tb testing.TB) *fuzzProxy {
	tb.Helper()
	p := &fuzzProxy{insp: &fuzzInspector{}, front: &recorder{}, up: &recorder{}}
	upstream := httptest.NewUnstartedServer(p.up)
	upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			p.upConns.Add(1)
		}
	}
	upstream.Start()
	tb.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		tb.Fatal(err)
	}
	p.target = target
	h, err := New(p.insp, Config{Upstream: target, MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(h.proxy.Transport.(*http.Transport).CloseIdleConnections)
	var handler http.Handler = h
	p.front.next.Store(&handler)
	srv := httptest.NewServer(p.front)
	tb.Cleanup(srv.Close)
	p.addr = srv.Listener.Addr().String()
	return p
}

// check sends the first request of raw through the proxy and checks what
// was inspected and forwarded.
func (p *fuzzProxy) check(t *testing.T, raw []byte) {
	front, up, insp, target := p.front, p.up, p.insp, p.target
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

	front.take()
	insp.take()
	up.take()
	status := send(t, p.addr, first)

	served := front.take()
	inspected := insp.take()
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

// FuzzProxy's inputs share the proxy and its upstream connections: with a
// proxy per input, each left an idle connection to the upstream open, and a
// few minutes of fuzzing stalled on them.
func TestFuzzProxyReusesUpstreamConnections(t *testing.T) {
	p := newFuzzProxy(t)
	const n = 100
	for range n {
		p.check(t, []byte("POST /a?b=c HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"))
	}
	if got := p.upConns.Load(); got == 0 || got > n/10 {
		t.Errorf("the upstream accepted %d connections for %d requests, want one or a few reused", got, n)
	}
}
