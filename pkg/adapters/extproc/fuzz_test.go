// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
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
// taken as complete — unless, sent without end of stream (trailers follow),
// it is under the limit and exactly its Content-Length long.
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
		case bodyEOS || bodyMode == filterv3.ProcessingMode_BUFFERED:
			truncated = len(body) > fuzzMaxBody
		default:
			// BUFFERED_PARTIAL without end of stream: complete only under
			// the limit and with its whole Content-Length.
			length, err := strconv.ParseInt(req.Headers.Get("Content-Length"), 10, 64)
			truncated = len(body) >= fuzzMaxBody || err != nil || length != int64(len(body))
		}
		if req.BodyTruncated != truncated {
			t.Errorf("body %q truncated %v, want %v (mode %v, end of stream %v)", req.Body, req.BodyTruncated, truncated, bodyMode, bodyEOS)
		}
		if httpadapter.RequestID(req.ID) != req.ID || req.ID == "" {
			t.Errorf("request ID %q", req.ID)
		}
	})
}

// responseRecorder is a rules evaluator that allows requests and records
// the responses it is given, denying those whose body says "DENY".
type responseRecorder struct{ got []*request.Response }

func (*responseRecorder) Evaluate(context.Context, *request.Request) (rules.Result, error) {
	return rules.Result{}, nil
}

func (r *responseRecorder) EvaluateExchange(context.Context, *request.Request) (rules.Result, rules.Exchange, error) {
	return rules.Result{}, &recordedExchange{r: r}, nil
}

type recordedExchange struct{ r *responseRecorder }

func (x *recordedExchange) EvaluateResponse(_ context.Context, resp *request.Response) (rules.Result, error) {
	x.r.got = append(x.r.got, resp)
	return rules.Result{Interrupted: bytes.Contains(resp.Body, []byte("DENY")), Status: 403}, nil
}

func (*recordedExchange) Close() {}

const fuzzMaxResponse = 16

// FuzzExtProcResponse sends a request, then response headers with an
// arbitrary :status and an extra header, and, unless the headers end the
// response, a body in one or two chunks, in any body send mode, observed or
// not, and maybe trailers. The response is inspected exactly once, after
// the request, whatever Envoy sends or leaves out; its body
// only when its media type is one the rules read, at most the limit and a
// prefix of what Envoy sent, marked truncated unless it is complete; and
// only an answer to the last message replaces it.
func FuzzExtProcResponse(f *testing.F) {
	f.Add("200", "content-type", "text/html", []byte("<p>hi</p>"), false, true, uint8(2), false, 3, false)
	f.Add("500", "content-type", "application/json", []byte(`{"e":"DENY"}`), false, false, uint8(5), true, 0, true)
	f.Add("204", "x", "y", []byte{}, true, true, uint8(0), false, 0, false)
	f.Add("200", "content-encoding", "gzip", []byte("\x1f\x8b\x08"), false, false, uint8(2), false, -1, true)
	f.Fuzz(func(t *testing.T, status, name, value string, body []byte, eos, bodyEOS bool, mode uint8, observe bool, split int, trailers bool) {
		respMode := filterv3.ProcessingMode_BodySendMode(mode % 6)
		first := &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
				Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
					{Key: ":method", RawValue: []byte("GET")},
					{Key: ":path", RawValue: []byte("/")},
					{Key: ":authority", RawValue: []byte("shop.example.com")},
				}}, EndOfStream: true,
			}},
			ProtocolConfig:    &extprocv3.ProtocolConfiguration{ResponseBodyMode: respMode},
			ObservabilityMode: observe,
		}
		hs := []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte(status)},
			{Key: "content-type", RawValue: []byte("text/plain")},
			{Key: name, RawValue: []byte(value)},
		}
		in := []*extprocv3.ProcessingRequest{first, {Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: eos},
		}}}
		var sent []byte
		if !eos {
			chunks := [][]byte{body}
			if split > 0 && split < len(body) {
				chunks = [][]byte{body[:split], body[split:]}
			}
			if split < 0 && trailers {
				chunks = nil // no body message: the trailers end the response
			}
			for i, c := range chunks {
				sent = append(sent, c...)
				in = append(in, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
					ResponseBody: &extprocv3.HttpBody{Body: c, EndOfStream: bodyEOS && !trailers && i == len(chunks)-1},
				}})
			}
			if trailers {
				in = append(in, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
					ResponseTrailers: &extprocv3.HttpTrailers{},
				}})
			}
		}
		rec := &responseRecorder{}
		p := pipeline.New(rec, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
			Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: fuzzMaxResponse, Oversize: pipeline.OversizeAllow}})
		s, err := New(p, Config{MaxBodyBytes: fuzzMaxBody, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		stream := &fakeStream{in: in}
		if err := s.Process(stream); err != nil {
			t.Fatalf("stream failed: %v", err)
		}
		if observe && len(stream.out) > 0 {
			t.Fatalf("answered %d messages in observability mode", len(stream.out))
		}
		if len(rec.got) != 1 {
			t.Fatalf("response inspected %d times, want once", len(rec.got))
		}
		for i, r := range stream.out {
			if r.GetImmediateResponse() != nil && i != len(stream.out)-1 {
				t.Fatalf("answers after an immediate response: %v", stream.out)
			}
		}
		if !observe && stream.out[len(stream.out)-1].GetImmediateResponse() == nil && len(stream.out) != len(in) {
			t.Fatalf("%d answers to %d messages", len(stream.out), len(in))
		}
		resp := rec.got[0]
		for h := range resp.Headers {
			if strings.HasPrefix(h, ":") || !httpadapter.IsToken(h) {
				t.Errorf("inspected response header %q", h)
			}
		}
		if code, err := strconv.Atoi(status); err == nil && code >= 100 && code <= 999 && resp.Status != code {
			t.Errorf("status %d, Envoy sent %q", resp.Status, status)
		}
		ct := resp.Headers.Get("Content-Type")
		if resp.Body != nil && !pipeline.InspectedResponseType(ct) {
			t.Errorf("inspected a %q body", ct)
		}
		if len(resp.Body) > fuzzMaxResponse {
			t.Errorf("inspected %d bytes, limit %d", len(resp.Body), fuzzMaxResponse)
		}
		encoded := resp.Headers.Get("Content-Encoding") != "" || strings.EqualFold(name, "content-encoding")
		if !encoded && !bytes.HasPrefix(sent, resp.Body) {
			t.Errorf("inspected %q, Envoy sent %q", resp.Body, sent)
		}
		if !encoded && resp.Body != nil && !resp.BodyTruncated {
			// Complete: the whole body, with end of stream (or BUFFERED,
			// or its whole Content-Length).
			if len(resp.Body) != len(sent) {
				t.Errorf("body %q of %q not marked truncated", resp.Body, sent)
			}
		}
	})
}
