// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package crs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/inkwall-dev/inkwall/pkg/adapters/extproc"
	"github.com/inkwall-dev/inkwall/pkg/adapters/forwardauth"
	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/adapters/spoe"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// The fronts stand in for each proxy: an HTTP server that go-ftw sends the
// tests to, which asks its adapter for the verdict as the proxy would, and
// forwards what is allowed to the upstream (albedo).

// maxBody is large enough that no CRS test body is cut.
const maxBody = 1 << 20

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// proxyFront is the engine's own reverse proxy: the adapter is the front.
func proxyFront(t *testing.T, p pipeline.ExchangeInspector, upstream *url.URL) http.Handler {
	h, err := proxy.New(p, proxy.Config{Upstream: upstream, MaxBodyBytes: maxBody, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// forwardAuthFront asks the ForwardAuth adapter as Traefik does (with
// forwardBody): a subrequest with the client's headers, X-Forwarded-*, and
// the body. A 2xx forwards the request; anything else is the answer.
func forwardAuthFront(t *testing.T, p pipeline.ExchangeInspector, upstream *url.URL) http.Handler {
	fa, err := forwardauth.New(p, forwardauth.Config{MaxBodyBytes: maxBody, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sub, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+forwardauth.Path, bytes.NewReader(body))
		for k, vs := range clientHeaders(r) {
			sub.Header[k] = vs
		}
		sub.Header.Set("X-Forwarded-Method", r.Method)
		sub.Header.Set("X-Forwarded-Proto", "http")
		sub.Header.Set("X-Forwarded-Host", r.Host)
		sub.Header.Set("X-Forwarded-Uri", r.RequestURI)
		sub.Header.Set("X-Forwarded-For", "127.0.0.1")
		sub.ContentLength = int64(len(body))
		sub.RemoteAddr = "127.0.0.1:1"
		rec := &recorder{header: http.Header{}}
		fa.ServeHTTP(rec, sub)
		if rec.code/100 != 2 {
			copyHeader(w.Header(), rec.header)
			w.WriteHeader(rec.code)
			_, _ = w.Write(rec.body.Bytes())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rp.ServeHTTP(w, r)
	})
}

type recorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(b)
}

// clientHeaders are the headers as the client sent them, the framing ones
// (which Go's server takes out) restored, as a proxy passes them on.
func clientHeaders(r *http.Request) http.Header {
	h := r.Header.Clone()
	if len(r.TransferEncoding) > 0 && h.Get("Transfer-Encoding") == "" {
		h["Transfer-Encoding"] = r.TransferEncoding
	}
	if r.ContentLength > 0 && h.Get("Content-Length") == "" {
		h.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	return h
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		dst[k] = vs
	}
}

// extProcFront asks the ext_proc adapter as Envoy does, with buffered
// request and response bodies: the request headers and body, then the
// upstream's response headers and body, so the response rules run too.
func extProcFront(t *testing.T, p pipeline.ExchangeInspector, upstream *url.URL) http.Handler {
	s, err := extproc.New(p, extproc.Config{MaxBodyBytes: maxBody, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	// A Unix socket, as Envoy reaches the engine in a pod: the stream's
	// peer is then loopback, as there.
	sock := filepath.Join(t.TempDir(), "extproc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g := s.NewGRPCServer()
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///engine",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20), grpc.MaxCallSendMsgSize(16<<20)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := extprocv3.NewExternalProcessorClient(conn)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := envoyExchange(client, w, r, upstream); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
}

func envoyExchange(client extprocv3.ExternalProcessorClient, w http.ResponseWriter, r *http.Request, upstream *url.URL) error {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(r.Body)
	hs := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(r.Method)},
		{Key: ":path", RawValue: []byte(r.RequestURI)},
		{Key: ":authority", RawValue: []byte(r.Host)},
		{Key: ":scheme", RawValue: []byte("http")},
	}
	for k, vs := range clientHeaders(r) {
		for _, v := range vs {
			hs = append(hs, &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)})
		}
	}
	// exchange sends a message and returns the answer; an immediate
	// response is written to the client, and stops the exchange.
	exchange := func(m *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, bool, error) {
		if err := stream.Send(m); err != nil {
			return nil, true, err
		}
		resp, err := stream.Recv()
		if err != nil {
			return nil, true, err
		}
		if ir := resp.GetImmediateResponse(); ir != nil {
			for _, h := range ir.GetHeaders().GetSetHeaders() {
				w.Header().Set(h.GetHeader().GetKey(), string(h.GetHeader().GetRawValue()))
			}
			// A gRPC status: Envoy answers as a gRPC server, HTTP 200.
			if ir.GetGrpcStatus() != nil {
				w.WriteHeader(http.StatusOK)
				return resp, true, nil
			}
			w.WriteHeader(int(ir.GetStatus().GetCode()))
			_, _ = w.Write(ir.GetBody())
			return resp, true, nil
		}
		return resp, false, nil
	}
	first := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: len(body) == 0,
		}},
		// The attribute the operator's and examples' filters ask for.
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"request.protocol": structpb.NewStringValue(r.Proto),
		}}},
		ProtocolConfig: &extprocv3.ProtocolConfiguration{
			RequestBodyMode:  filterv3.ProcessingMode_BUFFERED,
			ResponseBodyMode: filterv3.ProcessingMode_BUFFERED,
		},
	}
	resp, done, err := exchange(first)
	if done || err != nil {
		return err
	}
	set := setHeaders(resp.GetRequestHeaders().GetResponse())
	if len(body) > 0 {
		resp, done, err = exchange(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: body, EndOfStream: true},
		}})
		if done || err != nil {
			return err
		}
		for k, v := range setHeaders(resp.GetRequestBody().GetResponse()) {
			set[k] = v
		}
	}

	// The upstream, with the headers the engine set.
	out, _ := http.NewRequestWithContext(ctx, r.Method, upstream.String()+r.RequestURI, bytes.NewReader(body))
	out.Header = r.Header.Clone()
	for k, v := range set {
		out.Header.Set(k, v)
	}
	out.Host = r.Host
	up, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		return err
	}
	defer up.Body.Close()
	respBody, _ := io.ReadAll(up.Body)

	rhs := []*corev3.HeaderValue{{Key: ":status", RawValue: []byte(strconv.Itoa(up.StatusCode))}}
	for k, vs := range up.Header {
		for _, v := range vs {
			rhs = append(rhs, &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)})
		}
	}
	resp, done, err = exchange(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: rhs}, EndOfStream: len(respBody) == 0},
	}})
	if done || err != nil {
		return err
	}
	if len(respBody) > 0 {
		_, done, err = exchange(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: respBody, EndOfStream: true},
		}})
		if done || err != nil {
			return err
		}
	}
	// Envoy ends the stream with the exchange; the engine then closes the
	// transaction, which logs the response's matches: wait for that, as
	// go-ftw reads the log right after the answer.
	_ = stream.CloseSend()
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}
	copyHeader(w.Header(), up.Header)
	w.WriteHeader(up.StatusCode)
	_, _ = w.Write(respBody)
	return nil
}

func setHeaders(c *extprocv3.CommonResponse) map[string]string {
	set := map[string]string{}
	for _, h := range c.GetHeaderMutation().GetSetHeaders() {
		set[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	return set
}

// spoeFront asks the SPOE agent as HAProxy does with examples/haproxy's
// spoe.conf: a NOTIFY with the request's method, path and query, version,
// headers (req.hdrs_bin), body, address and TLS flag, over one connection
// at a time; a denial is the answer, with the status the engine sent.
func spoeFront(t *testing.T, p pipeline.ExchangeInspector, upstream *url.URL) http.Handler {
	s, err := spoe.New(p, spoe.Config{MaxBodyBytes: maxBody, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "spoe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	rp := httputil.NewSingleHostReverseProxy(upstream)
	var mu sync.Mutex
	var c *spopConn
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		if c == nil {
			if c, err = dialSPOP(sock); err != nil {
				mu.Unlock()
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		vars, err := c.notify(r, body)
		if err != nil {
			c.close()
			c = nil
		}
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if id := vars["request_id"]; id != "" {
			r.Header.Set("X-Request-Id", id)
		}
		if vars["action"] == "deny" {
			status, _ := strconv.Atoi(vars["status"])
			switch status {
			case 400, 413, 503:
			default:
				status = http.StatusForbidden
			}
			w.Header().Set("X-Request-Id", vars["request_id"])
			w.WriteHeader(status)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rp.ServeHTTP(w, r)
	})
}

// SPOP, the little of it HAProxy speaks here (pkg/adapters/spoe/spop.go).
const (
	spopHello  = 1
	spopNotify = 3
	spopAck    = 103
	spopString = 8
	spopBinary = 9
	spopBool   = 1
	spopIPv4   = 6
	spopUint32 = 3
	spopInt32  = 2
)

type spopConn struct {
	c     net.Conn
	frame uint64
}

func appendVarint(dst []byte, v uint64) []byte {
	if v < 240 {
		return append(dst, byte(v))
	}
	dst = append(dst, byte(v&0xff)|240)
	v = (v - 240) >> 4
	for v >= 128 {
		dst = append(dst, byte(v&0x7f)|128)
		v = (v - 128) >> 7
	}
	return append(dst, byte(v))
}

func readVarint(b []byte) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errors.New("truncated")
	}
	v := uint64(b[0])
	if v < 240 {
		return v, b[1:], nil
	}
	shift := uint(4)
	for i := 1; i < len(b); i++ {
		v += uint64(b[i]) << shift
		shift += 7
		if b[i] < 128 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("truncated")
}

func appendString(b []byte, s string) []byte {
	return append(appendVarint(b, uint64(len(s))), s...)
}

func (c *spopConn) send(typ byte, streamID, frameID uint64, payload []byte) error {
	f := []byte{0, 0, 0, 0, typ, 0, 0, 0, 1}
	f = appendVarint(f, streamID)
	f = appendVarint(f, frameID)
	f = append(f, payload...)
	binary.BigEndian.PutUint32(f[:4], uint32(len(f)-4)) // #nosec G115 -- bounded
	_, err := c.c.Write(f)
	return err
}

func (c *spopConn) recv() (byte, []byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(c.c, n[:]); err != nil {
		return 0, nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(c.c, b); err != nil {
		return 0, nil, err
	}
	typ := b[0]
	rest := b[5:]
	var err error
	for range 2 { // stream-id, frame-id
		if _, rest, err = readVarint(rest); err != nil {
			return 0, nil, err
		}
	}
	return typ, rest, nil
}

func dialSPOP(sock string) (*spopConn, error) {
	nc, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	c := &spopConn{c: nc}
	var p []byte
	p = appendString(p, "supported-versions")
	p = append(p, spopString)
	p = appendString(p, "2.0")
	p = appendString(p, "max-frame-size")
	p = append(p, spopUint32)
	p = appendVarint(p, maxBody+64<<10)
	p = appendString(p, "capabilities")
	p = append(p, spopString)
	p = appendString(p, "")
	if err := c.send(spopHello, 0, 0, p); err != nil {
		nc.Close()
		return nil, err
	}
	if typ, _, err := c.recv(); err != nil || typ != 101 {
		nc.Close()
		return nil, fmt.Errorf("hello: frame %d, %v", typ, err)
	}
	return c, nil
}

func (c *spopConn) close() { _ = c.c.Close() }

// notify sends the request and returns the variables of the ACK.
func (c *spopConn) notify(r *http.Request, body []byte) (map[string]string, error) {
	c.frame++
	var hdrs []byte
	hdrs = appendString(hdrs, "host")
	hdrs = appendString(hdrs, r.Host)
	for k, vs := range clientHeaders(r) {
		for _, v := range vs {
			hdrs = appendString(hdrs, strings.ToLower(k))
			hdrs = appendString(hdrs, v)
		}
	}
	hdrs = append(hdrs, 0, 0)
	version := strings.TrimPrefix(r.Proto, "HTTP/")
	var p []byte
	p = appendString(p, spoe.MessageName)
	p = append(p, 7)
	arg := func(name string, typ byte, v []byte) {
		p = appendString(p, name)
		p = append(p, typ)
		p = append(p, v...)
	}
	arg(spoe.ArgMethod, spopString, appendString(nil, r.Method))
	arg(spoe.ArgPath, spopString, appendString(nil, r.RequestURI))
	arg(spoe.ArgVersion, spopString, appendString(nil, version))
	arg(spoe.ArgHeaders, spopBinary, appendString(nil, string(hdrs)))
	arg(spoe.ArgBody, spopBinary, appendString(nil, string(body)))
	ip := netip.MustParseAddr("127.0.0.1").As4()
	arg(spoe.ArgIP, spopIPv4, ip[:])
	p = appendString(p, spoe.ArgHTTPS)
	p = append(p, spopBool) // false
	if err := c.send(spopNotify, c.frame, c.frame, p); err != nil {
		return nil, err
	}
	typ, payload, err := c.recv()
	if err != nil {
		return nil, err
	}
	if typ != spopAck {
		return nil, fmt.Errorf("frame %d, want an ACK", typ)
	}
	return ackVars(payload)
}

// ackVars reads an ACK's set-var actions: type, nb-args, scope, name, value.
func ackVars(b []byte) (map[string]string, error) {
	vars := map[string]string{}
	for len(b) > 0 {
		if len(b) < 3 {
			return nil, errors.New("truncated action")
		}
		b = b[3:] // set-var, 3 arguments, the scope
		n, rest, err := readVarint(b)
		if err != nil || n > uint64(len(rest)) {
			return nil, errors.New("truncated name")
		}
		name := string(rest[:n])
		b = rest[n:]
		if len(b) == 0 {
			return nil, errors.New("truncated value")
		}
		typ := b[0] & 0x0f
		b = b[1:]
		switch typ {
		case spopString, spopBinary:
			n, rest, err := readVarint(b)
			if err != nil || n > uint64(len(rest)) {
				return nil, errors.New("truncated string")
			}
			vars[name] = string(rest[:n])
			b = rest[n:]
		case spopInt32, spopUint32, 4, 5:
			v, rest, err := readVarint(b)
			if err != nil {
				return nil, err
			}
			vars[name] = strconv.FormatInt(int64(int32(v)), 10) // #nosec G115 -- statuses and codes
			b = rest
		default:
			return nil, fmt.Errorf("value type %d", typ)
		}
	}
	return vars, nil
}
