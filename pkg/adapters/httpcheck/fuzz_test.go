// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpcheck

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// fuzzInspector records the requests it is asked to check, and allows them.
type fuzzInspector struct{ got []*request.Request }

func (i *fuzzInspector) Check(_ context.Context, r *request.Request) pipeline.Verdict {
	i.got = append(i.got, r)
	return pipeline.Verdict{}
}

func (*fuzzInspector) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

const fuzzMaxBody = 16

// FuzzCheck posts arbitrary bytes as a CheckRequest, in protobuf or JSON.
// The engine either rejects them uninspected with a 4xx, or inspects exactly
// the request they describe (method, URI, authority, headers but Host,
// addresses, at most the body limit of the body) and answers a CheckResponse
// for it in the same encoding.
func FuzzCheck(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte, isJSON bool) {
		contentType := ContentTypeProtobuf
		if isJSON {
			contentType = ContentTypeJSON
		}
		r := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", contentType)
		insp := &fuzzInspector{}
		h, err := New(insp, Config{MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if len(insp.got) == 0 {
			if w.Code < 400 || w.Code >= 500 {
				t.Fatalf("uninspected check answered %d, want a 4xx", w.Code)
			}
			return
		}
		if len(insp.got) > 1 || w.Code != http.StatusOK {
			t.Fatalf("inspected %d times, answered %d", len(insp.got), w.Code)
		}
		var in enginev1.CheckRequest
		if isJSON {
			err = protojson.Unmarshal(raw, &in)
		} else {
			err = proto.Unmarshal(raw, &in)
		}
		if err != nil {
			t.Fatalf("inspected a check that doesn't decode: %v", err)
		}
		req := insp.got[0]
		if req.Method != in.GetMethod() || !httpadapter.IsToken(req.Method) {
			t.Errorf("inspected method %q, sent %q", req.Method, in.GetMethod())
		}
		if req.RawURI != in.GetRawUri() || (req.RawURI != "*" && (!strings.HasPrefix(req.RawURI, "/") || strings.ContainsRune(req.RawURI, '#'))) {
			t.Errorf("inspected URI %q, sent %q", req.RawURI, in.GetRawUri())
		}
		if req.Host != in.GetAuthority() || (req.Scheme != "http" && req.Scheme != "https") {
			t.Errorf("inspected %s://%s, sent %q %q", req.Scheme, req.Host, in.GetScheme(), in.GetAuthority())
		}
		if _, ok := req.Headers["Host"]; ok {
			t.Errorf("Host is in the inspected headers")
		}
		sent := 0
		for _, hf := range in.GetHeaders() {
			if !strings.EqualFold(hf.GetName(), "Host") {
				sent++
			}
		}
		got := 0
		for _, vs := range req.Headers {
			got += len(vs)
		}
		if got != sent {
			t.Errorf("inspected %d header values, sent %d", got, sent)
		}
		client := req.PeerIP
		if in.GetClientIp() != "" {
			client = netip.MustParseAddr(in.GetClientIp()).Unmap()
		}
		if req.ClientIP != client {
			t.Errorf("inspected client %v, sent %q (peer %q)", req.ClientIP, in.GetClientIp(), in.GetPeerIp())
		}
		body := in.GetBody()
		truncated := len(body) > fuzzMaxBody || in.GetBodyTruncated()
		if len(req.Body) > fuzzMaxBody || !bytes.HasPrefix(body, req.Body) || req.BodyTruncated != truncated {
			t.Errorf("inspected body %q (truncated %v) of %q, limit %d", req.Body, req.BodyTruncated, body, fuzzMaxBody)
		}

		var out enginev1.CheckResponse
		if isJSON {
			err = protojson.Unmarshal(w.Body.Bytes(), &out)
		} else {
			err = proto.Unmarshal(w.Body.Bytes(), &out)
		}
		if err != nil || w.Header().Get("Content-Type") != contentType {
			t.Fatalf("response %q (%s): %v", w.Body.Bytes(), w.Header().Get("Content-Type"), err)
		}
		if out.GetRequestId() != req.ID || httpadapter.RequestID(req.ID) != req.ID {
			t.Errorf("response request ID %q, inspected %q", out.GetRequestId(), req.ID)
		}
	})
}
