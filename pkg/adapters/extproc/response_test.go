// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqlError = "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax</body></html>"

// newResponsePipeline returns a CRS pipeline that inspects responses, with
// a response body limit of limit.
func newResponsePipeline(t testing.TB, mode pipeline.Mode, limit int64, oversize pipeline.OversizeAction) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{ResponseBodyLimit: int(limit)})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: limit, Oversize: oversize}})
}

// withModes sets the request and response body modes Envoy sends in its
// first message.
func withModes(m *extprocv3.ProcessingRequest, req, resp filterv3.ProcessingMode_BodySendMode) *extprocv3.ProcessingRequest {
	m.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: req, ResponseBodyMode: resp}
	return m
}

func respHeaders(status int, eos bool, kv ...string) *extprocv3.ProcessingRequest {
	hs := []*corev3.HeaderValue{{Key: ":status", RawValue: []byte(strconv.Itoa(status))}}
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: eos},
	}}
}

func respBody(b string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte(b), EndOfStream: eos},
	}}
}

// securityEvents returns the security events logged, one JSON object per line.
func securityEvents(t testing.TB, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var evs []map[string]any
	for line := range strings.Lines(logs.String()) {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if ev["msg"] == "security event" {
			evs = append(evs, ev)
		}
	}
	return evs
}

func gzipString(t testing.TB, s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = io.WriteString(w, s)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestResponse(t *testing.T) {
	const html, png, sse = "text/html; charset=utf-8", "image/png", "text/event-stream"
	bp := filterv3.ProcessingMode_BUFFERED_PARTIAL
	tests := []struct {
		name     string
		mode     pipeline.Mode
		oversize pipeline.OversizeAction
		respMode filterv3.ProcessingMode_BodySendMode
		msgs     []*extprocv3.ProcessingRequest // after the request headers
		status   int                            // the immediate response's status, 0 for none
		event    string                         // the response event's reason, "" for none
		override bool                           // the response headers' answer asks for no body
	}{
		{name: "clean", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", html), respBody("<p>hello</p>", true)}},
		{name: "sql error blocked", mode: pipeline.ModeBlock, respMode: bp,
			msgs:   []*extprocv3.ProcessingRequest{respHeaders(500, false, "content-type", html), respBody(sqlError, true)},
			status: 403, event: "rule"},
		{name: "sql error detected", mode: pipeline.ModeDetect, respMode: bp,
			msgs:  []*extprocv3.ProcessingRequest{respHeaders(500, false, "content-type", html), respBody(sqlError, true)},
			event: "rule"},
		{name: "gzip sql error blocked", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{
				respHeaders(500, false, "content-type", html, "content-encoding", "gzip"), respBody(gzipString(t, sqlError), true)},
			status: 403, event: "rule"},
		// An image's body isn't read: decided on the headers, and Envoy is
		// told not to send it.
		{name: "image", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", png)}, override: true},
		{name: "server-sent events", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", sse)}, override: true},
		{name: "no body", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{respHeaders(204, true)}},
		// Over the limit (256 bytes): the prefix is inspected, and the
		// rest gets onOversize.
		{name: "sql error in the prefix", mode: pipeline.ModeBlock, oversize: pipeline.OversizeAllow, respMode: bp,
			msgs:   []*extprocv3.ProcessingRequest{respHeaders(500, false, "content-type", html), respBody(sqlError+strings.Repeat("x", 300), true)},
			status: 403, event: "rule"},
		{name: "oversized, allowed", mode: pipeline.ModeBlock, oversize: pipeline.OversizeAllow, respMode: bp,
			msgs:  []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", html), respBody(strings.Repeat("x", 300), true)},
			event: "oversize"},
		{name: "oversized, denied", mode: pipeline.ModeBlock, respMode: bp,
			msgs:   []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", html), respBody(strings.Repeat("x", 300), true)},
			status: 502, event: "oversize"},
		// Cut at Envoy's buffer: neither end of stream nor its length.
		{name: "cut", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{
				respHeaders(200, false, "content-type", html, "content-length", "1000"), respBody("<p>hello</p>", false)},
			status: 502, event: "oversize"},
		// Trailers follow a body of its full length: complete.
		{name: "trailers", mode: pipeline.ModeBlock, respMode: bp,
			msgs: []*extprocv3.ProcessingRequest{
				respHeaders(200, false, "content-type", html, "content-length", "12"), respBody("<p>hello</p>", false)}},
		// Envoy doesn't send the body in one piece.
		{name: "streamed", mode: pipeline.ModeBlock, respMode: filterv3.ProcessingMode_STREAMED,
			msgs:   []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", html)},
			status: 502, event: "oversize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, newResponsePipeline(t, tt.mode, 256, tt.oversize), 64, &logs)
			msgs := append([]*extprocv3.ProcessingRequest{withModes(headers("GET", "/", true, "accept-encoding", "gzip"), 0, tt.respMode)}, tt.msgs...)
			resps := e.exchange(t, msgs...)
			last := resps[len(resps)-1]
			if got := denied(t, last); got != tt.status {
				t.Fatalf("status %d, want %d: %v", got, tt.status, last)
			}
			if tt.status == 0 && len(resps) != len(msgs) {
				t.Fatalf("%d answers to %d messages", len(resps), len(msgs))
			}
			// The request's answer removes Accept-Encoding.
			if rm := resps[0].GetRequestHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders(); !slices.Equal(rm, []string{"accept-encoding"}) {
				t.Errorf("request headers removed %v, want accept-encoding", rm)
			}
			override := resps[1].GetModeOverride().GetResponseBodyMode() == filterv3.ProcessingMode_NONE && resps[1].GetModeOverride() != nil
			if override != tt.override {
				t.Errorf("mode override %v, want %v", resps[1].GetModeOverride(), tt.override)
			}
			evs := securityEvents(t, &logs)
			got := ""
			if len(evs) > 0 {
				ev := evs[len(evs)-1]
				if ev["phase"] != "response" {
					t.Errorf("event %v, want a response event", ev)
				}
				got, _ = ev["reason"].(string)
			}
			if got != tt.event {
				t.Errorf("event reason %q, want %q: %s", got, tt.event, logs.String())
			}
		})
	}
}

// Without response inspection, responses are continued as before, and the
// request's Accept-Encoding is kept.
func TestResponseNotInspected(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &logs)
	resps := e.exchange(t,
		withModes(headers("GET", "/", true, "accept-encoding", "gzip"), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL),
		respHeaders(500, false, "content-type", "text/html"), respBody(sqlError, true))
	if len(resps) != 3 {
		t.Fatalf("%d answers", len(resps))
	}
	if m := resps[0].GetRequestHeaders().GetResponse().GetHeaderMutation(); m != nil {
		t.Errorf("request headers mutated: %v", m)
	}
	// Envoy sends the response because the route asks for it (another
	// policy on it inspects responses, or Envoy's config does): it is told
	// not to buffer or send the body of one that isn't inspected.
	if resps[1].GetModeOverride().GetResponseBodyMode() != filterv3.ProcessingMode_NONE || resps[1].GetModeOverride() == nil || denied(t, resps[2]) != 0 {
		t.Errorf("response answered %v, %v", resps[1], resps[2])
	}
	// Without a body, or not buffered, there is nothing to override.
	resps = e.exchange(t,
		withModes(headers("GET", "/", true), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL), respHeaders(204, true))
	if resps[1].GetModeOverride() != nil {
		t.Errorf("no body: mode override %v", resps[1].GetModeOverride())
	}
	resps = e.exchange(t,
		withModes(headers("GET", "/", true), 0, filterv3.ProcessingMode_NONE), respHeaders(200, false))
	if resps[1].GetModeOverride() != nil {
		t.Errorf("body mode NONE: mode override %v", resps[1].GetModeOverride())
	}
	if logs.Len() != 0 {
		t.Errorf("logged %s", logs.String())
	}
}

// A request denied has no response to inspect; one held for its body gets
// the response inspection once decided.
func TestResponseAfterBody(t *testing.T) {
	e := newEnvoy(t, newResponsePipeline(t, pipeline.ModeBlock, 256, pipeline.OversizeAuto), 64, io.Discard)
	resps := e.exchange(t,
		withModes(headers("POST", "/login", false, "content-type", "application/x-www-form-urlencoded"),
			filterv3.ProcessingMode_BUFFERED, filterv3.ProcessingMode_BUFFERED),
		body("user=alice", true),
		respHeaders(500, false, "content-type", "text/html"), respBody(sqlError, true))
	if len(resps) != 4 || denied(t, resps[3]) != 403 {
		t.Fatalf("answers %v, want the response denied", resps)
	}
	// The request body's answer removes Accept-Encoding: Envoy held the
	// headers.
	if rm := resps[1].GetRequestBody().GetResponse().GetHeaderMutation().GetRemoveHeaders(); len(rm) != 1 {
		t.Errorf("request body answer removed %v", rm)
	}
}

// In observability mode the response is gathered from its chunks and
// decided, and then the stream is closed.
func TestResponseObservabilityMode(t *testing.T) {
	tests := []struct {
		name  string
		msgs  []*extprocv3.ProcessingRequest
		event string
	}{
		{"clean", []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", "text/html"), respBody("<p>he", false), respBody("llo</p>", true)}, ""},
		{"sql error in chunks", []*extprocv3.ProcessingRequest{
			respHeaders(500, false, "content-type", "text/html"), respBody(sqlError[:60], false), respBody(sqlError[60:], true)}, "rule"},
		// The stream ends first: decided on what came.
		{"cut short", []*extprocv3.ProcessingRequest{
			respHeaders(500, false, "content-type", "text/html", "content-length", "500"), respBody(sqlError, false)}, "rule"},
		{"image", []*extprocv3.ProcessingRequest{respHeaders(200, false, "content-type", "image/png"), respBody("PNG", true)}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, newResponsePipeline(t, pipeline.ModeDetect, 256, pipeline.OversizeAuto), 64, &logs)
			e.observe(t, append([]*extprocv3.ProcessingRequest{headers("GET", "/", true)}, tt.msgs...)...)
			got := ""
			if evs := securityEvents(t, &logs); len(evs) > 0 {
				got, _ = evs[0]["reason"].(string)
			}
			if got != tt.event {
				t.Errorf("event %q, want %q: %s", got, tt.event, logs.String())
			}
		})
	}
}

// Trailers that come before any body message (a body Envoy sent none of)
// still get the response inspected, once, in buffered and observability
// modes.
func TestResponseTrailersOnly(t *testing.T) {
	trailers := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{}}}
	for _, observe := range []bool{false, true} {
		rec := &responseRecorder{}
		p := pipeline.New(rec, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
			Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 64, Oversize: pipeline.OversizeAllow}})
		e := newEnvoy(t, p, 64, io.Discard)
		first := withModes(headers("GET", "/", true), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL)
		msgs := []*extprocv3.ProcessingRequest{first, respHeaders(200, false, "content-type", "text/html"), trailers}
		if observe {
			first.ObservabilityMode = true
			e.observe(t, msgs...)
		} else if resps := e.exchange(t, msgs...); len(resps) != 3 {
			t.Fatalf("%d answers", len(resps))
		}
		if len(rec.got) != 1 {
			t.Errorf("observe %v: response inspected %d times, want once", observe, len(rec.got))
		}
	}
}
