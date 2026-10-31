// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
)

// fakeStream feeds Process the messages Envoy sends for one request, and
// stops after an immediate response, as Envoy does.
type fakeStream struct {
	grpc.ServerStream
	in  []*extprocv3.ProcessingRequest
	out []*extprocv3.ProcessingResponse
}

func (*fakeStream) Context() context.Context { return context.Background() }

func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(f.in) == 0 || (len(f.out) > 0 && f.out[len(f.out)-1].GetImmediateResponse() != nil) {
		return nil, io.EOF
	}
	m := f.in[0]
	f.in = f.in[1:]
	return m, nil
}

func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.out = append(f.out, r)
	return nil
}

const fuzzMaxBody = 16

// FuzzExtProc sends request headers with arbitrary pseudo-headers, an extra
// header (which may repeat one of them) and, unless the headers end the
// request, a body, in any body send mode. The engine either refuses the
// request uninspected with 400, or inspects exactly the method, path and
// authority Envoy sent, without pseudo-headers, and at most the body limit
// of the body; a body Envoy doesn't send whole is marked truncated, never
// taken as complete.
func FuzzExtProc(f *testing.F) {
	f.Fuzz(func(t *testing.T, method, path, authority, scheme, name, value string, body []byte, eos, bodyEOS bool, mode uint8) {
		bodyMode := filterv3.ProcessingMode_BodySendMode(mode % 6)
		hs := []*corev3.HeaderValue{
			{Key: ":method", RawValue: []byte(method)},
			{Key: ":path", RawValue: []byte(path)},
			{Key: ":authority", RawValue: []byte(authority)},
			{Key: ":scheme", RawValue: []byte(scheme)},
			{Key: name, RawValue: []byte(value)},
		}
		in := []*extprocv3.ProcessingRequest{{
			Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
				Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: eos,
			}},
			ProtocolConfig: &extprocv3.ProtocolConfiguration{RequestBodyMode: bodyMode},
		}}
		if !eos {
			in = append(in, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{Body: body, EndOfStream: bodyEOS},
			}})
		}
		insp := &inspector{}
		s, err := New(insp, Config{MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		stream := &fakeStream{in: in}
		if err := s.Process(stream); err != nil {
			t.Fatalf("stream failed: %v", err)
		}

		if len(insp.got) == 0 {
			if len(stream.out) != 1 || denied(t, stream.out[0]) != 400 {
				t.Fatalf("uninspected request answered %v, want 400 alone", stream.out)
			}
			return
		}
		if len(insp.got) > 1 {
			t.Fatalf("inspected %d times", len(insp.got))
		}
		for _, r := range stream.out {
			if r.GetImmediateResponse() != nil {
				t.Fatalf("allowed request answered %v", r)
			}
		}
		req := insp.got[0]
		if req.Method != method || req.RawURI != path || req.Host != authority {
			t.Errorf("inspected %s %q (host %q), Envoy sent %s %q (host %q)", req.Method, req.RawURI, req.Host, method, path, authority)
		}
		if strings.HasPrefix(name, ":") && (name == ":method" || name == ":path" || name == ":authority" || name == ":scheme") {
			t.Errorf("inspected a request with two %s", name)
		}
		if !httpadapter.IsToken(req.Method) {
			t.Errorf("inspected method %q is not a token", req.Method)
		}
		if req.RawURI != "*" && (!strings.HasPrefix(req.RawURI, "/") || strings.ContainsRune(req.RawURI, '#')) {
			t.Errorf("inspected URI %q is not in origin form without a fragment", req.RawURI)
		}
		if req.Scheme != "http" && req.Scheme != "https" {
			t.Errorf("scheme %q", req.Scheme)
		}
		for h := range req.Headers {
			if strings.HasPrefix(h, ":") || strings.EqualFold(h, "Host") {
				t.Errorf("inspected headers include %s", h)
			}
		}
		if len(req.Body) > fuzzMaxBody || !bytes.HasPrefix(body, req.Body) {
			t.Errorf("inspected body %q of %q, limit %d", req.Body, body, fuzzMaxBody)
		}
		buffered := bodyMode == filterv3.ProcessingMode_BUFFERED || bodyMode == filterv3.ProcessingMode_BUFFERED_PARTIAL
		var truncated bool
		switch {
		case eos:
		case !buffered:
			truncated = true
		default:
			truncated = len(body) > fuzzMaxBody || (!bodyEOS && bodyMode == filterv3.ProcessingMode_BUFFERED_PARTIAL)
		}
		if req.BodyTruncated != truncated {
			t.Errorf("body %q truncated %v, want %v (mode %v, end of stream %v)", req.Body, req.BodyTruncated, truncated, bodyMode, bodyEOS)
		}
		if httpadapter.RequestID(req.ID) != req.ID || req.ID == "" {
			t.Errorf("request ID %q", req.ID)
		}
	})
}
