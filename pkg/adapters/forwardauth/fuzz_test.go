// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// inspector records the requests it is asked to check, and allows them.
type inspector struct{ got []*request.Request }

func (i *inspector) Check(_ context.Context, r *request.Request) pipeline.Verdict {
	i.got = append(i.got, r)
	return pipeline.Verdict{}
}

func (*inspector) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

const fuzzMaxBody = 16

// FuzzForwardAuth sends subrequests with arbitrary X-Forwarded-* headers,
// an extra header (which may repeat one of them, as a client would with
// trustForwardHeader: true) and a body. The engine either rejects the
// subrequest uninspected, or inspects exactly the method and URI the proxy
// forwarded, without the headers the proxy added, and at most the body
// limit of the body it sent.
func FuzzForwardAuth(f *testing.F) {
	f.Fuzz(func(t *testing.T, method, uri, host, proto, name, value string, body []byte) {
		h := http.Header{}
		h.Set("X-Forwarded-Method", method)
		h.Set("X-Forwarded-Uri", uri)
		h.Set("X-Forwarded-Host", host)
		h.Set("X-Forwarded-Proto", proto)
		h.Set("X-Forwarded-Port", "443")
		h.Add(name, value)
		r := &http.Request{
			Method:        http.MethodGet,
			URL:           &url.URL{Path: Path},
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        h,
			Host:          "127.0.0.1:9001",
			RemoteAddr:    "10.0.0.1:41000",
			RequestURI:    Path,
			ContentLength: int64(len(body)),
			Body:          io.NopCloser(bytes.NewReader(body)),
		}
		if len(body) == 0 {
			r.Body = http.NoBody
		}
		insp := &inspector{}
		handler, err := New(insp, Config{MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if len(insp.got) == 0 {
			if w.Code != http.StatusBadRequest {
				t.Fatalf("uninspected subrequest answered %d, want 400", w.Code)
			}
			return
		}
		if len(insp.got) > 1 {
			t.Fatalf("inspected %d times", len(insp.got))
		}
		if w.Code != http.StatusOK {
			t.Errorf("allowed subrequest answered %d", w.Code)
		}
		req := insp.got[0]
		for _, s := range []string{"X-Forwarded-Method", "X-Forwarded-Uri", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if n := len(h.Values(s)); n != 1 {
				t.Errorf("inspected a subrequest with %d values of %s", n, s)
			}
		}
		if req.RawURI != h.Get("X-Forwarded-Uri") || req.Method != h.Get("X-Forwarded-Method") || req.Host != h.Get("X-Forwarded-Host") {
			t.Errorf("inspected %s %q (host %q), the proxy forwarded %s %q (host %q)",
				req.Method, req.RawURI, req.Host, h.Get("X-Forwarded-Method"), h.Get("X-Forwarded-Uri"), h.Get("X-Forwarded-Host"))
		}
		if !httpadapter.IsToken(req.Method) {
			t.Errorf("inspected method %q is not a token", req.Method)
		}
		if req.RawURI != "*" && (!strings.HasPrefix(req.RawURI, "/") || strings.ContainsRune(req.RawURI, '#')) {
			t.Errorf("inspected URI %q is not in origin form without a fragment", req.RawURI)
		}
		if want := strings.EqualFold(h.Get("X-Forwarded-Proto"), "https"); (req.Scheme == "https") != want || (req.Scheme != "https" && req.Scheme != "http") {
			t.Errorf("scheme %q from X-Forwarded-Proto %q", req.Scheme, h.Get("X-Forwarded-Proto"))
		}
		for _, s := range synthesized {
			if _, ok := req.Headers[s]; ok {
				t.Errorf("inspected headers include %s, added by the proxy", s)
			}
		}
		if len(req.Body) > fuzzMaxBody || !bytes.HasPrefix(body, req.Body) || req.BodyTruncated != (len(body) > fuzzMaxBody) {
			t.Errorf("inspected body %q (truncated %v) of %q, limit %d", req.Body, req.BodyTruncated, body, fuzzMaxBody)
		}
		if id := w.Header().Get("X-Request-Id"); id != req.ID || httpadapter.RequestID(id) != id {
			t.Errorf("X-Request-Id %q, inspected request ID %q", id, req.ID)
		}
	})
}
