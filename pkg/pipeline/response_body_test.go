// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqlErrorPage = `<html><body><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p></body></html>`

func leak() *request.Response {
	return &request.Response{Status: 500, Proto: "HTTP/1.1", Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte(sqlErrorPage)}
}

// responsePipeline inspects responses with the Core Rule Set, oversized
// ones denied.
func responsePipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{ResponseBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 1 << 20, Oversize: pipeline.OversizeDeny}})
}

// checkResponse inspects resp as the response to a benign GET, its body
// given when the adapters read it (WantsBody).
func checkResponse(t *testing.T, p *pipeline.Pipeline, resp *request.Response) pipeline.Verdict {
	t.Helper()
	req := &request.Request{Proto: "HTTP/1.1", Method: http.MethodGet, Scheme: "https", Host: "shop.example.com",
		RawURI: "/products?id=42", ClientIP: netip.MustParseAddr("198.51.100.7"),
		Headers: http.Header{"User-Agent": {"Mozilla/5.0"}, "Accept": {"*/*"}}}
	v, x := p.CheckExchange(context.Background(), req)
	if v.Action != pipeline.ActionAllow || x == nil {
		t.Fatalf("request: %s/%s %v", v.Action, v.Reason, v.RuleIDs)
	}
	defer x.Close()
	if !x.WantsBody(pipeline.ResponseContentType(resp.Headers)) {
		resp.Body = nil
	}
	return x.CheckResponse(context.Background(), resp)
}

// A response leaking a SQL error is denied whatever Content-Type a browser
// would read it as: one with a structured syntax suffix, a script, CSV, a
// parameter a strict parser rejects, no type, or two.
func TestResponseContentTypesInspected(t *testing.T) {
	p := responsePipeline(t)
	for _, ct := range [][]string{
		{"text/html"}, {"text/html; charset=utf-8"}, {"Text/HTML"}, {" text/html "},
		{"application/vnd.api+json"}, {"application/hal+json"}, {"application/ld+json"}, {"application/problem+xml"},
		{"image/svg+xml"}, {"application/javascript"}, {"text/javascript"}, {"application/xhtml+xml"}, {"text/csv"},
		{"text/html; charset"}, {"text/html;;charset=utf-8"}, {"text/html; charset="}, {"html"}, {"text/html,"},
		nil, {""}, {"image/png", "text/html"},
	} {
		h := http.Header{}
		if ct != nil {
			h["Content-Type"] = ct
		}
		v := checkResponse(t, p, &request.Response{Status: 500, Proto: "HTTP/1.1", Headers: h, Body: []byte(sqlErrorPage)})
		if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule {
			t.Errorf("Content-Type %q: %s/%s, want denied by the rules", ct, v.Action, v.Reason)
		}
	}
	// Types the rules don't read pass without their body: images, and
	// streams, which are split into events instead.
	for _, ct := range []string{"image/png", "application/octet-stream", "text/event-stream", "application/grpc+json", "application/connect+json"} {
		v := checkResponse(t, p, &request.Response{Status: 200, Proto: "HTTP/1.1", Headers: http.Header{"Content-Type": {ct}}, Body: []byte(sqlErrorPage)})
		if v.Action != pipeline.ActionAllow || v.Reason != pipeline.ReasonNone {
			t.Errorf("Content-Type %q: %s/%s, want allowed", ct, v.Action, v.Reason)
		}
	}
}

// A part of a body (206, multipart/byteranges) can't be inspected as the
// whole: a leak cut across ranges would pass. Its body counts as
// uninspected, so the oversize action applies.
func TestResponseRangesUninspected(t *testing.T) {
	p := responsePipeline(t)
	whole := checkResponse(t, p, leak())
	if whole.Action != pipeline.ActionDeny {
		t.Fatalf("whole page: %s/%s", whole.Action, whole.Reason)
	}
	multipart := "--b\r\nContent-Type: text/html\r\nContent-Range: bytes 0-90/180\r\n\r\n" + sqlErrorPage[:91] +
		"\r\n--b\r\nContent-Type: text/html\r\nContent-Range: bytes 91-179/180\r\n\r\n" + sqlErrorPage[91:] + "\r\n--b--\r\n"
	v := checkResponse(t, p, &request.Response{Status: http.StatusPartialContent, Proto: "HTTP/1.1",
		Headers: http.Header{"Content-Type": {"multipart/byteranges; boundary=b"}}, Body: []byte(multipart)})
	if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonOversize || v.Status != http.StatusBadGateway {
		t.Errorf("multipart/byteranges: %s/%s %d, want denied as oversized with 502", v.Action, v.Reason, v.Status)
	}
	for i := 0; i < len(sqlErrorPage); i += 24 {
		part := sqlErrorPage[i:min(i+24, len(sqlErrorPage))]
		v := checkResponse(t, p, &request.Response{Status: http.StatusPartialContent, Proto: "HTTP/1.1",
			Headers: http.Header{"Content-Type": {"text/html"}, "Content-Range": {"bytes ..."}}, Body: []byte(part)})
		if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonOversize {
			t.Errorf("206, bytes %d+: %s/%s, want denied as oversized", i, v.Action, v.Reason)
		}
	}
	// A range of an image passes, as the image does.
	v = checkResponse(t, p, &request.Response{Status: http.StatusPartialContent, Proto: "HTTP/1.1",
		Headers: http.Header{"Content-Type": {"video/mp4"}}, Body: []byte("....")})
	if v.Action != pipeline.ActionAllow {
		t.Errorf("206 video/mp4: %s/%s, want allowed", v.Action, v.Reason)
	}
}

// Every Content-Encoding counts, as a client decodes the list of all:
// identity then gzip is gzip; two codings aren't decoded, so the body is
// uninspected.
func TestResponseContentEncodingList(t *testing.T) {
	p := responsePipeline(t)
	gz := func(b []byte) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(b)
		_ = w.Close()
		return buf.Bytes()
	}
	for _, tc := range []struct {
		encoding []string
		body     []byte
		reason   pipeline.Reason
	}{
		{[]string{"identity", "gzip"}, gz([]byte(sqlErrorPage)), pipeline.ReasonRule},
		{[]string{"identity, gzip"}, gz([]byte(sqlErrorPage)), pipeline.ReasonRule},
		{[]string{"GZIP"}, gz([]byte(sqlErrorPage)), pipeline.ReasonRule},
		{[]string{"identity", "identity"}, []byte(sqlErrorPage), pipeline.ReasonRule},
		{[]string{"gzip", "gzip"}, gz(gz([]byte(sqlErrorPage))), pipeline.ReasonOversize},
		{[]string{"gzip", "br"}, []byte("..."), pipeline.ReasonOversize},
	} {
		v := checkResponse(t, p, &request.Response{Status: 500, Proto: "HTTP/1.1",
			Headers: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": tc.encoding}, Body: tc.body})
		if v.Action != pipeline.ActionDeny || v.Reason != tc.reason {
			t.Errorf("Content-Encoding %q: %s/%s, want denied (%s)", tc.encoding, v.Action, v.Reason, tc.reason)
		}
	}
}
