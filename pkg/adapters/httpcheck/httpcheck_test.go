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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func newPipeline(t *testing.T, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// A generous timeout keeps the race detector from tripping the deadline.
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 500 * time.Millisecond})
}

func newHandler(t *testing.T, p *pipeline.Pipeline, maxBody int64, logs *bytes.Buffer) *Handler {
	t.Helper()
	h, err := New(p, Config{MaxBodyBytes: maxBody, Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// checkRequest describes a browser-like client request.
func checkRequest(method, uri, contentType, body string) *enginev1.CheckRequest {
	in := &enginev1.CheckRequest{
		Method:    method,
		Scheme:    "https",
		Authority: "shop.example.com",
		RawUri:    uri,
		ClientIp:  "203.0.113.7",
		PeerIp:    "192.0.2.10",
		Headers: []*enginev1.Header{
			{Name: "User-Agent", Value: "Mozilla/5.0 inkwall-test"},
			{Name: "Accept", Value: "text/html"},
		},
	}
	if body != "" {
		in.Body = []byte(body)
		in.Headers = append(in.Headers,
			&enginev1.Header{Name: "Content-Type", Value: contentType},
			&enginev1.Header{Name: "Content-Length", Value: strconv.Itoa(len(body))},
		)
	}
	return in
}

// send posts in to h as protobuf and decodes the answer.
func send(t *testing.T, h http.Handler, in *enginev1.CheckRequest) *enginev1.CheckResponse {
	t.Helper()
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", ContentTypeProtobuf)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("check: got %d (%s), want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if ct := w.Header().Get("Content-Type"); ct != ContentTypeProtobuf {
		t.Fatalf("response content type %q, want %s", ct, ContentTypeProtobuf)
	}
	var out enginev1.CheckResponse
	if err := proto.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestBlockMode(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &logs)

	out := send(t, h, checkRequest("GET", "/products?id=42", "", ""))
	if out.GetAction() != enginev1.Action_ACTION_ALLOW || out.GetReason() != enginev1.Reason_REASON_NONE {
		t.Fatalf("benign request: got %v/%v, want allow/none", out.GetAction(), out.GetReason())
	}
	if out.GetRequestId() == "" || out.GetInspectionTime().AsDuration() <= 0 {
		t.Fatalf("missing request ID or inspection time: %v", out)
	}

	out = send(t, h, checkRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""))
	if out.GetAction() != enginev1.Action_ACTION_DENY || out.GetStatus() != http.StatusForbidden ||
		out.GetReason() != enginev1.Reason_REASON_RULE {
		t.Fatalf("sqli in the URI: got %v/%d/%v, want deny/403/rule", out.GetAction(), out.GetStatus(), out.GetReason())
	}
	if out.GetInterruptingRuleId() == 0 || !slices.Contains(out.GetRuleIds(), 942100) {
		t.Fatalf("sqli: rule IDs %v (interrupting %d), want 942100 among them", out.GetRuleIds(), out.GetInterruptingRuleId())
	}

	out = send(t, h, checkRequest("POST", "/comments", "application/x-www-form-urlencoded", "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"))
	if out.GetAction() != enginev1.Action_ACTION_DENY {
		t.Fatalf("xss in the body: got %v, want deny", out.GetAction())
	}
	if !strings.Contains(logs.String(), `"action":"deny"`) || !strings.Contains(logs.String(), `"path":"/products"`) ||
		!strings.Contains(logs.String(), `"client_ip":"203.0.113.7"`) {
		t.Fatalf("deny event missing or incomplete:\n%s", logs.String())
	}
}

func TestDetectModeLogs(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, newPipeline(t, pipeline.ModeDetect), 64<<10, &logs)
	out := send(t, h, checkRequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", "", ""))
	if out.GetAction() != enginev1.Action_ACTION_LOG || out.GetStatus() != 0 {
		t.Fatalf("detect mode: got %v/%d, want log/0", out.GetAction(), out.GetStatus())
	}
	if !strings.Contains(logs.String(), `"action":"log"`) {
		t.Fatalf("detect event missing:\n%s", logs.String())
	}
}

func TestJSONEncoding(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &logs)
	// What a Lua client writes by hand: snake_case names, base64 body.
	body := `{"request_id":"lua-1","method":"GET","raw_uri":"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",` +
		`"authority":"shop.example.com","client_ip":"203.0.113.7",` +
		`"headers":[{"name":"User-Agent","value":"Mozilla/5.0"},{"name":"Accept","value":"*/*"}]}`
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d (%s), want 200", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != ContentTypeJSON {
		t.Fatalf("response content type %q, want %s", ct, ContentTypeJSON)
	}
	for _, want := range []string{`"action":"ACTION_DENY"`, `"status":403`, `"request_id":"lua-1"`, `"reason":"REASON_RULE"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("response %s lacks %s", w.Body.String(), want)
		}
	}
	var out enginev1.CheckResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
}

// recorder captures the request the evaluator saw.
type recorder struct{ got *request.Request }

func (r *recorder) Evaluate(_ context.Context, req *request.Request) (rules.Result, error) {
	r.got = req
	return rules.Result{}, nil
}

func TestConvertsTheRequest(t *testing.T) {
	rec := &recorder{}
	p := pipeline.New(rec, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: time.Second})
	var logs bytes.Buffer
	h := newHandler(t, p, 16, &logs)

	in := checkRequest("POST", "/a%2Fb?x=1", "text/plain", "0123456789")
	in.RequestId = "abc-123"
	in.Protocol = "HTTP/2.0"
	in.Headers = append(in.Headers,
		&enginev1.Header{Name: "Host", Value: "evil.example.com"},
		&enginev1.Header{Name: "X-Legacy", Value: "ignored", RawValue: []byte{'c', 'a', 'f', 0xe9}},
	)
	out := send(t, h, in)

	got := rec.got
	if got == nil {
		t.Fatal("evaluator not called")
	}
	if got.ID != "abc-123" || out.GetRequestId() != "abc-123" {
		t.Errorf("request ID: evaluator %q, response %q, want abc-123", got.ID, out.GetRequestId())
	}
	if got.Method != "POST" || got.Scheme != "https" || got.Host != "shop.example.com" ||
		got.RawURI != "/a%2Fb?x=1" || got.Proto != "HTTP/2.0" {
		t.Errorf("request line: %+v", got)
	}
	if got.ClientIP != netip.MustParseAddr("203.0.113.7") || got.PeerIP != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("addresses: client %v, peer %v", got.ClientIP, got.PeerIP)
	}
	if got.Headers.Get("Host") != "" {
		t.Error("a Host header must not override the authority")
	}
	if got.Headers.Get("X-Legacy") != "caf\xe9" {
		t.Errorf("raw_value not preferred: %q", got.Headers.Get("X-Legacy"))
	}
	if string(got.Body) != "0123456789" || got.BodyTruncated {
		t.Errorf("body %q truncated=%v, want the whole body", got.Body, got.BodyTruncated)
	}
}

func TestTruncatedBodies(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, newPipeline(t, pipeline.ModeBlock), 8, &logs)

	// Longer than the engine's limit.
	out := send(t, h, checkRequest("POST", "/upload", "text/plain", "0123456789"))
	if out.GetReason() != enginev1.Reason_REASON_OVERSIZE || out.GetStatus() != http.StatusRequestEntityTooLarge {
		t.Errorf("body over the limit: got %v/%d, want oversize/413", out.GetReason(), out.GetStatus())
	}
	// Already truncated by the proxy.
	in := checkRequest("POST", "/upload", "text/plain", "0123")
	in.BodyTruncated = true
	out = send(t, h, in)
	if out.GetReason() != enginev1.Reason_REASON_OVERSIZE || out.GetStatus() != http.StatusRequestEntityTooLarge {
		t.Errorf("body truncated by the proxy: got %v/%d, want oversize/413", out.GetReason(), out.GetStatus())
	}
}

func TestClientIPDefaultsToPeer(t *testing.T) {
	rec := &recorder{}
	p := pipeline.New(rec, pipeline.Config{Timeout: time.Second})
	var logs bytes.Buffer
	in := checkRequest("GET", "/", "", "")
	in.ClientIp = ""
	send(t, newHandler(t, p, 0, &logs), in)
	if rec.got.ClientIP != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("client IP %v, want the peer", rec.got.ClientIP)
	}
}

func TestBodyInspectionDisabled(t *testing.T) {
	rec := &recorder{}
	p := pipeline.New(rec, pipeline.Config{Timeout: time.Second})
	var logs bytes.Buffer
	in := checkRequest("POST", "/", "text/plain", "hello")
	in.BodyTruncated = true
	send(t, newHandler(t, p, 0, &logs), in)
	if rec.got.Body != nil || rec.got.BodyTruncated {
		t.Fatalf("body %q truncated=%v with body inspection off", rec.got.Body, rec.got.BodyTruncated)
	}
}

func TestInvalidChecksAreRejected(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, newPipeline(t, pipeline.ModeBlock), 16, &logs)

	encode := func(mut func(*enginev1.CheckRequest)) []byte {
		in := checkRequest("GET", "/", "", "")
		mut(in)
		b, err := proto.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		contentType string
		body        []byte
		want        int
	}{
		{"GET", http.MethodGet, Path, ContentTypeProtobuf, nil, http.StatusMethodNotAllowed},
		{"wrong path", http.MethodPost, "/v1/other", ContentTypeProtobuf, nil, http.StatusNotFound},
		{"no content type", http.MethodPost, Path, "", nil, http.StatusUnsupportedMediaType},
		{"form content type", http.MethodPost, Path, "application/x-www-form-urlencoded", nil, http.StatusUnsupportedMediaType},
		{"garbage", http.MethodPost, Path, ContentTypeProtobuf, []byte{0xff, 0xff, 0xff}, http.StatusBadRequest},
		{"bad JSON", http.MethodPost, Path, ContentTypeJSON, []byte(`{"method":`), http.StatusBadRequest},
		{"no method", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.Method = "" }), http.StatusBadRequest},
		{"method with space", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.Method = "GET /" }), http.StatusBadRequest},
		{"absolute URI", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.RawUri = "http://a/" }), http.StatusBadRequest},
		{"fragment", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.RawUri = "/a#b" }), http.StatusBadRequest},
		{"bad scheme", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.Scheme = "ftp" }), http.StatusBadRequest},
		{"bad client IP", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) { in.ClientIp = "1.2.3" }), http.StatusBadRequest},
		{"bad header name", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) {
			in.Headers = append(in.Headers, &enginev1.Header{Name: "Bad Name", Value: "x"})
		}), http.StatusBadRequest},
		{"too large", http.MethodPost, Path, ContentTypeProtobuf, encode(func(in *enginev1.CheckRequest) {
			in.Body = bytes.Repeat([]byte("a"), envelope+17)
		}), http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d (%s), want %d", w.Code, strings.TrimSpace(w.Body.String()), tc.want)
			}
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(newPipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: -1}); err == nil {
		t.Fatal("negative body limit accepted")
	}
}

// TestSameVerdictAsReverseProxy checks the contract shared by all adapters:
// for the same client request, /v1/check reaches the reverse proxy's verdict
// with the same matched rules.
func TestSameVerdictAsReverseProxy(t *testing.T) {
	var logs bytes.Buffer
	hc := newHandler(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &logs)
	var rpSeen lastVerdict
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	rp, err := proxy.New(
		pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 500 * time.Millisecond, Observer: &rpSeen}),
		proxy.Config{Upstream: target, MaxBodyBytes: 64 << 10, Logger: slog.New(slog.DiscardHandler)},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ method, uri, contentType, body string }{
		{"GET", "/products?id=42", "", ""},
		{"GET", "/search?q=running+shoes&page=2", "", ""},
		{"POST", "/login", "application/x-www-form-urlencoded", "user=alice&password=hunter2"},
		{"POST", "/api/cart", "application/json", `{"sku":"A-1","qty":2}`},
		{"POST", "/logout", "", ""},
		{"DELETE", "/api/cart/1", "", ""},
		{"GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""},
		{"GET", "/?file=../../../../etc/passwd", "", ""},
		{"POST", "/ping", "application/x-www-form-urlencoded", "host=127.0.0.1;cat /etc/passwd"},
		{"POST", "/api/notes", "application/json", `{"note":"<script>alert(1)</script>"}`},
	} {
		direct := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(tc.body))
		direct.Host = "shop.example.com"
		direct.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
		direct.Header.Set("Accept", "text/html")
		in := checkRequest(tc.method, tc.uri, tc.contentType, tc.body)
		in.Scheme = "http"
		if tc.body != "" {
			direct.Header.Set("Content-Type", tc.contentType)
		} else if tc.method == "POST" {
			direct.Header.Set("Content-Length", "0")
			in.Headers = append(in.Headers, &enginev1.Header{Name: "Content-Length", Value: "0"})
		}
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, direct)
		out := send(t, hc, in)

		denied := out.GetAction() == enginev1.Action_ACTION_DENY
		if denied != (w.Code >= 400) || (denied && int(out.GetStatus()) != w.Code) {
			t.Errorf("%s %s: /v1/check %v/%d, reverse proxy %d", tc.method, tc.uri, out.GetAction(), out.GetStatus(), w.Code)
		}
		got := make([]int, 0, len(out.GetRuleIds()))
		for _, id := range out.GetRuleIds() {
			got = append(got, int(id))
		}
		if !slices.Equal(got, rpSeen.v.RuleIDs) {
			t.Errorf("%s %s: /v1/check matched %v, reverse proxy %v", tc.method, tc.uri, got, rpSeen.v.RuleIDs)
		}
	}
}

// lastVerdict records the most recent verdict of a pipeline.
type lastVerdict struct{ v pipeline.Verdict }

func (l *lastVerdict) ObserveVerdict(v pipeline.Verdict) { l.v = v }
