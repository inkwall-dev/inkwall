// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func newPipeline(t testing.TB, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	return newPipelineOversize(t, mode, pipeline.OversizeAuto)
}

// newPipelineOversize returns a pipeline that handles oversized bodies
// with oversize.
func newPipelineOversize(t testing.TB, mode pipeline.Mode, oversize pipeline.OversizeAction) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// A generous deadline: these tests are not about it, and CRS under the
	// race detector on a loaded machine can take longer than a real one.
	return pipeline.New(eval, pipeline.Config{Mode: mode, Oversize: oversize, Timeout: 10 * time.Second})
}

// envoy is a fake Envoy: a client of the Server over an in-memory
// connection, or over a listener the test chooses.
type envoy struct {
	client extprocv3.ExternalProcessorClient
}

// startServer serves s on ln and returns an Envoy connected through dial.
func startServer(t testing.TB, s *Server, ln net.Listener, dial func(context.Context, string) (net.Conn, error)) *envoy {
	t.Helper()
	g := s.NewGRPCServer()
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///envoy",
		grpc.WithContextDialer(dial), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &envoy{client: extprocv3.NewExternalProcessorClient(conn)}
}

func newEnvoy(t testing.TB, p pipeline.Inspector, maxBody int64, logs io.Writer) *envoy {
	t.Helper()
	s, err := New(p, Config{MaxBodyBytes: maxBody, Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	return startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })
}

// exchange sends msgs on one stream, as Envoy does for one request,
// waiting for each answer, and returns the answers. It stops at an
// immediate response, after which Envoy sends nothing more.
func (e *envoy) exchange(t testing.TB, msgs ...*extprocv3.ProcessingRequest) []*extprocv3.ProcessingResponse {
	t.Helper()
	resps, err := e.try(msgs...)
	if err != nil {
		t.Fatal(err)
	}
	return resps
}

func (e *envoy) try(msgs ...*extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := e.client.Process(ctx)
	if err != nil {
		return nil, err
	}
	var resps []*extprocv3.ProcessingResponse
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			return resps, err
		}
		resp, err := stream.Recv()
		if err != nil {
			return resps, err
		}
		resps = append(resps, resp)
		if resp.GetImmediateResponse() != nil {
			break
		}
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		return resps, err
	}
	return resps, nil
}

// headers is the request_headers message Envoy sends: pseudo-headers
// first, then name/value pairs.
func headers(method, path string, eos bool, kv ...string) *extprocv3.ProcessingRequest {
	hs := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":path", RawValue: []byte(path)},
		{Key: ":authority", RawValue: []byte("shop.example.com")},
		{Key: ":scheme", RawValue: []byte("https")},
		{Key: "user-agent", RawValue: []byte("Mozilla/5.0 inkwall-test")},
		{Key: "accept", RawValue: []byte("text/html")},
		{Key: "x-request-id", RawValue: []byte("envoy-id-1")},
	}
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: eos},
	}}
}

// withMode sets the protocol configuration Envoy sends in its first message.
func withMode(m *extprocv3.ProcessingRequest, mode filterv3.ProcessingMode_BodySendMode) *extprocv3.ProcessingRequest {
	m.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: mode}
	return m
}

func body(b string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(b), EndOfStream: eos},
	}}
}

func responseHeaders() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
	}}
}

// denied returns the status of an immediate response, 0 for a continue.
func denied(t testing.TB, r *extprocv3.ProcessingResponse) int {
	t.Helper()
	if ir := r.GetImmediateResponse(); ir != nil {
		return int(ir.GetStatus().GetCode())
	}
	return 0
}

// continued checks that r continues the stage it answers, unchanged but
// for the headers it sets, which it returns.
func continued(t testing.TB, r *extprocv3.ProcessingResponse) map[string]string {
	t.Helper()
	var common *extprocv3.CommonResponse
	switch m := r.GetResponse().(type) {
	case *extprocv3.ProcessingResponse_RequestHeaders:
		common = m.RequestHeaders.GetResponse()
	case *extprocv3.ProcessingResponse_RequestBody:
		common = m.RequestBody.GetResponse()
	case *extprocv3.ProcessingResponse_ResponseHeaders:
		common = m.ResponseHeaders.GetResponse()
	default:
		t.Fatalf("answer %v, want a continue", r)
	}
	if common.GetStatus() != extprocv3.CommonResponse_CONTINUE || common.GetBodyMutation() != nil {
		t.Fatalf("answer %v, want a plain continue", r)
	}
	set := map[string]string{}
	for _, h := range common.GetHeaderMutation().GetSetHeaders() {
		set[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	return set
}

func TestBlockMode(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &logs)

	resps := e.exchange(t, headers("GET", "/products?id=42", true), responseHeaders())
	if len(resps) != 2 {
		t.Fatalf("%d answers, want 2", len(resps))
	}
	if set := continued(t, resps[0]); len(set) != 0 {
		t.Errorf("benign request: headers set %v, want none (Envoy's request ID is kept)", set)
	}
	continued(t, resps[1])
	if logs.Len() != 0 {
		t.Errorf("benign request logged: %s", logs.String())
	}

	resps = e.exchange(t, headers("GET", "/products?id=1'%20OR%20'1'='1", true))
	ir := resps[0].GetImmediateResponse()
	if denied(t, resps[0]) != 403 || string(ir.GetBody()) != "Forbidden\n" {
		t.Fatalf("SQL injection: %v, want 403 Forbidden", resps[0])
	}
	var id string
	for _, h := range ir.GetHeaders().GetSetHeaders() {
		if h.GetHeader().GetKey() == "x-request-id" {
			id = string(h.GetHeader().GetRawValue())
		}
	}
	if id != "envoy-id-1" {
		t.Errorf("denial's x-request-id %q, want Envoy's", id)
	}
	var ev map[string]any
	if err := json.Unmarshal(logs.Bytes(), &ev); err != nil {
		t.Fatalf("security event: %v (%s)", err, logs.String())
	}
	if ev["msg"] != "security event" || ev["action"] != "deny" || ev["request_id"] != "envoy-id-1" ||
		ev["host"] != "shop.example.com" || ev["path"] != "/products" {
		t.Errorf("security event %v", ev)
	}
}

func TestDetectMode(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, newPipeline(t, pipeline.ModeDetect), 64<<10, &logs)
	resps := e.exchange(t, headers("GET", "/?q=<script>alert(1)</script>", true))
	continued(t, resps[0])
	if !strings.Contains(logs.String(), `"action":"log"`) {
		t.Errorf("detected attack not logged: %s", logs.String())
	}
}

func TestBody(t *testing.T) {
	const (
		attack = "user=admin'%20OR%201=1--&password=x"
		benign = "user=alice&password=hunter2xx"
	)
	// The limit is 64 bytes. Envoy sends a body without end_of_stream when
	// it cut it at its buffer limit, or when trailers follow (and then no
	// trailers message).
	tests := []struct {
		name     string
		mode     pipeline.Mode
		oversize pipeline.OversizeAction
		bodyMod  filterv3.ProcessingMode_BodySendMode
		length   string // Content-Length: "" for the body's, "-" for none
		body     string
		eos      bool
		want     int // status of the denial; 0 allows
	}{
		{"buffered benign", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED, "", benign, true, 0},
		{"buffered attack", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED, "", attack, true, 403},
		{"buffered, trailers follow", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED, "", attack, false, 403},
		{"partial attack", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "", attack, true, 403},
		{"partial attack, trailers", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "", attack, false, 403},
		{"partial attack, trailers, onOversize allow", pipeline.ModeBlock, pipeline.OversizeAllow, filterv3.ProcessingMode_BUFFERED_PARTIAL, "", attack, false, 403},
		{"partial benign, trailers", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "", benign, false, 0},
		// Without Content-Length, the body may have been cut at a buffer
		// smaller than the limit: handled as oversized.
		{"partial attack, trailers, no content-length", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "-", attack, false, 413},
		{"partial benign, trailers, no content-length", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "-", benign, false, 413},
		// Cut at Envoy's buffer limit: the rest goes uninspected.
		{"partial, cut at the limit", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "-", strings.Repeat("a=b&", 16), false, 413},
		{"partial, cut over the limit", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "-", strings.Repeat("a=b&", 20), false, 413},
		{"partial, cut, onOversize allow", pipeline.ModeBlock, pipeline.OversizeAllow, filterv3.ProcessingMode_BUFFERED_PARTIAL, "-", strings.Repeat("a=b&", 20), false, 0},
		// Cut at a smaller buffer (the Gateway's own ClientTrafficPolicy).
		{"partial, short of its content-length", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "100", benign, false, 413},
		{"partial, short of its content-length, detect", pipeline.ModeDetect, 0, filterv3.ProcessingMode_BUFFERED_PARTIAL, "100", benign, false, 0},
		{"over the limit", pipeline.ModeBlock, 0, filterv3.ProcessingMode_BUFFERED, "", strings.Repeat("a=b&", 20), true, 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnvoy(t, newPipelineOversize(t, tt.mode, tt.oversize), 64, io.Discard)
			kv := []string{"content-type", "application/x-www-form-urlencoded"}
			switch tt.length {
			case "":
				kv = append(kv, "content-length", strconv.Itoa(len(tt.body)))
			case "-":
			default:
				kv = append(kv, "content-length", tt.length)
			}
			resps := e.exchange(t, withMode(headers("POST", "/login", false, kv...), tt.bodyMod), body(tt.body, tt.eos))
			if len(resps) != 2 {
				t.Fatalf("answers %v: the verdict must wait for the body", resps)
			}
			continued(t, resps[0])
			if got := denied(t, resps[1]); got != tt.want {
				t.Fatalf("status %d, want %d (%v)", got, tt.want, resps[1])
			}
			if tt.want == 0 {
				continued(t, resps[1])
			}
		})
	}
}

// TestBodyNotSent: a body Envoy doesn't send in one message can't be
// inspected, and is handled as an oversized one.
func TestBodyNotSent(t *testing.T) {
	for _, mode := range []filterv3.ProcessingMode_BodySendMode{filterv3.ProcessingMode_NONE, filterv3.ProcessingMode_STREAMED} {
		var logs bytes.Buffer
		e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &logs)
		resps := e.exchange(t, withMode(headers("POST", "/login", false, "content-length", "10"), mode))
		if got := denied(t, resps[0]); got != 413 {
			t.Errorf("%v: status %d, want 413", mode, got)
		}
	}
	// No protocol configuration (Envoy before 1.33) says the same.
	e := newEnvoy(t, newPipeline(t, pipeline.ModeDetect), 64<<10, io.Discard)
	continued(t, e.exchange(t, headers("POST", "/login", false, "content-length", "10"))[0])
}

// TestBodySkipped: when the route's body isn't inspected, the verdict
// comes with the headers and the body is let through.
func TestBodySkipped(t *testing.T) {
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 0, io.Discard)
	resps := e.exchange(t, withMode(headers("POST", "/login", false, "content-type", "application/x-www-form-urlencoded", "content-length", "11"),
		filterv3.ProcessingMode_BUFFERED),
		body("q=<script>x", true))
	continued(t, resps[0])
	continued(t, resps[1])
}

// inspector records the requests it is asked to check, and allows them.
type inspector struct{ got []*request.Request }

func (i *inspector) Check(_ context.Context, r *request.Request) pipeline.Verdict {
	i.got = append(i.got, r)
	return pipeline.Verdict{}
}

func (*inspector) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

func TestRequest(t *testing.T) {
	insp := &inspector{}
	e := newEnvoy(t, insp, 1<<10, io.Discard)
	e.exchange(t, withMode(headers("POST", "/a%20b?x=1", false, "cookie", "a=1", "cookie", "b=2", "host", "evil.example"),
		filterv3.ProcessingMode_BUFFERED), body("x=1", true))
	if len(insp.got) != 1 {
		t.Fatalf("inspected %d times", len(insp.got))
	}
	r := insp.got[0]
	if r.Method != "POST" || r.RawURI != "/a%20b?x=1" || r.Host != "shop.example.com" || r.Scheme != "https" {
		t.Errorf("inspected %s %s %s %s", r.Method, r.Scheme, r.Host, r.RawURI)
	}
	if string(r.Body) != "x=1" || r.BodyTruncated {
		t.Errorf("body %q truncated %v", r.Body, r.BodyTruncated)
	}
	if got := r.Headers.Values("Cookie"); len(got) != 2 {
		t.Errorf("cookies %v", got)
	}
	// HTTP/2 clients may send no Content-Length; Envoy sent the whole body.
	if r.Headers.Get("Content-Length") != "3" || r.Headers.Get("Host") != "" || r.Headers.Get(":path") != "" {
		t.Errorf("headers %v", r.Headers)
	}
	if r.ID != "envoy-id-1" {
		t.Errorf("request ID %q", r.ID)
	}

	insp.got = nil
	e.exchange(t, headers("POST", "/", true))
	if cl := insp.got[0].Headers.Get("Content-Length"); cl != "0" {
		t.Errorf("empty POST: Content-Length %q, want 0", cl)
	}
}

// TestProtocol: the protocol is Envoy's request.protocol attribute.
func TestProtocol(t *testing.T) {
	for attr, want := range map[string]string{"HTTP/2": "HTTP/2", "HTTP/1.0": "HTTP/1.0", "": "HTTP/1.1", "bogus": "HTTP/1.1"} {
		insp := &inspector{}
		e := newEnvoy(t, insp, 0, io.Discard)
		m := headers("GET", "/", true)
		if attr != "" {
			m.Attributes = map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
				"request.protocol": structpb.NewStringValue(attr)}}}
		}
		e.exchange(t, m)
		if got := insp.got[0].Proto; got != want {
			t.Errorf("attribute %q: protocol %q, want %q", attr, got, want)
		}
	}
}

// TestRequestID: a request without a usable ID gets one, set on the
// request Envoy forwards.
func TestRequestID(t *testing.T) {
	insp := &inspector{}
	e := newEnvoy(t, insp, 0, io.Discard)
	for _, id := range []string{"", "bad id"} {
		h := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", Value: "GET"}, {Key: ":path", Value: "/"}, {Key: ":authority", Value: "a"},
				{Key: "x-request-id", Value: id},
			}}, EndOfStream: true,
		}}}
		insp.got = nil
		set := continued(t, e.exchange(t, h)[0])
		if id := insp.got[0].ID; set["x-request-id"] != id || len(id) != 16 {
			t.Errorf("request ID %q, set %v", id, set)
		}
	}
}

func TestInvalid(t *testing.T) {
	ok := func(k, v string) *corev3.HeaderValue { return &corev3.HeaderValue{Key: k, RawValue: []byte(v)} }
	base := func(drop string, extra ...*corev3.HeaderValue) *extprocv3.ProcessingRequest {
		var hs []*corev3.HeaderValue
		for _, h := range []*corev3.HeaderValue{ok(":method", "GET"), ok(":path", "/"), ok(":authority", "shop.example.com"), ok(":scheme", "http")} {
			if h.GetKey() != drop {
				hs = append(hs, h)
			}
		}
		return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: append(hs, extra...)}, EndOfStream: true}}}
	}
	tests := map[string][]*extprocv3.ProcessingRequest{
		"absolute :path":  {base(":path", ok(":path", "http://evil.example/x"))},
		"fragment":        {base(":path", ok(":path", "/a#?id=1'--"))},
		"no :path":        {base(":path")},
		"two :path":       {base("", ok(":path", "/b"))},
		"no :method":      {base(":method")},
		"bad :method":     {base(":method", ok(":method", "G T"))},
		"bad :authority":  {base(":authority", ok(":authority", "a b"))},
		"bad :scheme":     {base(":scheme", ok(":scheme", "ftp"))},
		"bad header name": {base("", ok("a b", "c"))},
		"body first":      {body("x", true)},
		"response first":  {responseHeaders()},
		"two :authority":  {base("", ok(":authority", "x"))},
	}
	for name, msgs := range tests {
		t.Run(name, func(t *testing.T) {
			insp := &inspector{}
			e := newEnvoy(t, insp, 1<<10, io.Discard)
			resps := e.exchange(t, msgs...)
			if len(insp.got) != 0 || denied(t, resps[0]) != 400 {
				t.Errorf("answer %v after %d inspections, want 400 uninspected", resps[0], len(insp.got))
			}
		})
	}

	// A broken stream is closed.
	e := newEnvoy(t, &inspector{}, 1<<10, io.Discard)
	_, err := e.try(headers("GET", "/", true), headers("GET", "/", true))
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("headers twice: %v, want InvalidArgument", err)
	}
	_, err = e.try(&extprocv3.ProcessingRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty message: %v, want InvalidArgument", err)
	}
}

// observe sends msgs in observability mode: Envoy doesn't wait for
// answers.
func (e *envoy) observe(t testing.TB, msgs ...*extprocv3.ProcessingRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := e.client.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	msgs[0].ObservabilityMode = true
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			break // the engine closed the stream once it had decided
		}
	}
	_ = stream.CloseSend()
	if r, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("answered %v, %v in observability mode", r, err)
	}
}

// TestObservabilityMode: Envoy doesn't wait, so nothing is answered, but
// the request is inspected, its STREAMED body too.
func TestObservabilityMode(t *testing.T) {
	form := []string{"content-type", "application/x-www-form-urlencoded"}
	streamed := func(m *extprocv3.ProcessingRequest) *extprocv3.ProcessingRequest {
		return withMode(m, filterv3.ProcessingMode_STREAMED)
	}
	trailers := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{}}}
	tests := []struct {
		name string
		msgs []*extprocv3.ProcessingRequest
		want string // the event's reason; "" for none
	}{
		{"headers", []*extprocv3.ProcessingRequest{headers("GET", "/?q=<script>alert(1)</script>", true)}, "rule"},
		{"benign body", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, form...)), body("user=alice&", false), body("password=x", true)}, ""},
		// The attack is split across chunks.
		{"body attack", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, form...)), body("user=admin'%20OR", false), body("%201=1--", true)}, "rule"},
		// Trailers follow: Envoy sends no last chunk, and no trailers
		// message unless asked for them.
		{"body attack, trailers", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, append(form, "content-length", "24")...)), body("user=admin'%20OR", false), body("%201=1--", false)}, "rule"},
		{"benign body, trailers", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, append(form, "content-length", "21")...)), body("user=alice&", false), body("password=x", false)}, ""},
		// Without Content-Length, maybe cut short.
		{"body attack, trailers, no content-length", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, form...)), body("user=admin'%20OR", false), body("%201=1--", false)}, "oversize"},
		{"body attack, trailers message", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, form...)), body("user=admin'%20OR", false), body("%201=1--", false), trailers}, "rule"},
		// Envoy may not say STREAMED: in observability mode the body comes
		// in chunks anyway.
		{"body attack, no protocol_config", []*extprocv3.ProcessingRequest{
			headers("POST", "/login", false, form...), body("user=admin'%20OR", false), body("%201=1--", true)}, "rule"},
		// The stream ends before the body does: decided on what came.
		{"cut short", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, append(form, "content-length", "40")...)), body("user=alice", false)}, "oversize"},
		// Over the limit (64 bytes): the rest goes uninspected.
		{"oversized body", []*extprocv3.ProcessingRequest{
			streamed(headers("POST", "/login", false, form...)), body(strings.Repeat("a=b&", 10), false), body(strings.Repeat("a=b&", 10), false),
			body("<script>alert(1)</script>", true)}, "oversize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, &logs)
			e.observe(t, tt.msgs...)
			got := ""
			if strings.Contains(logs.String(), `"security event"`) {
				var ev struct{ Reason string }
				if err := json.Unmarshal(logs.Bytes(), &ev); err != nil {
					t.Fatal(err)
				}
				got = ev.Reason
			}
			if got != tt.want {
				t.Errorf("event reason %q, want %q: %s", got, tt.want, logs.String())
			}
		})
	}
}

// TestObservabilityModeClose: once the request is decided, the engine
// closes the stream: Envoy needs send nothing more.
func TestObservabilityModeClose(t *testing.T) {
	e := newEnvoy(t, newPipeline(t, pipeline.ModeBlock), 64, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := e.client.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := withMode(headers("POST", "/login", false, "content-type", "application/x-www-form-urlencoded"), filterv3.ProcessingMode_STREAMED)
	m.ObservabilityMode = true
	for _, m := range []*extprocv3.ProcessingRequest{m, body("a=b&", false), body("c=d", true)} {
		if err := stream.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	// No CloseSend: the engine ends the stream itself.
	if r, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, %v; want the stream closed", r, err)
	}
}

// TestNoPolicy: without a policy for the route the request passes, and is
// no security event.
func TestNoPolicy(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvoy(t, &policy.Holder{}, 64<<10, &logs)
	continued(t, e.exchange(t, headers("GET", "/?q=<script>alert(1)</script>", true))[0])
	if logs.Len() != 0 {
		t.Errorf("logged: %s", logs.String())
	}
}

// TestClientIP: Envoy, on the Unix socket, is a loopback peer; its
// X-Forwarded-For counts only when loopback is trusted.
func TestClientIP(t *testing.T) {
	for _, tt := range []struct {
		trusted []string
		want    string
	}{
		{[]string{"127.0.0.1/32", "::1/128"}, "203.0.113.7"},
		{nil, "127.0.0.1"},
	} {
		resolver, err := clientip.NewResolver(tt.trusted)
		if err != nil {
			t.Fatal(err)
		}
		insp := &inspector{}
		s, err := New(insp, Config{ClientIP: resolver, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(t.TempDir(), "extproc.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		})
		// Envoy appends its own peer to what the client sent.
		e.exchange(t, headers("GET", "/", true, "x-forwarded-for", "198.51.100.1, 203.0.113.7"))
		r := insp.got[0]
		if r.ClientIP != netip.MustParseAddr(tt.want) || r.PeerIP != loopback {
			t.Errorf("trusted %v: client %v peer %v, want client %s", tt.trusted, r.ClientIP, r.PeerIP, tt.want)
		}
	}
}

func TestNew(t *testing.T) {
	if _, err := New(&inspector{}, Config{MaxBodyBytes: -1}); err == nil {
		t.Fatal("negative body limit accepted")
	}
}
