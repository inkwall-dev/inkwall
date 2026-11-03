// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// inspector records the requests it is asked to check, and answers with
// verdict, or with what decide returns.
type inspector struct {
	mu      sync.Mutex
	got     []*request.Request
	verdict pipeline.Verdict
	decide  func(*request.Request) pipeline.Verdict
}

func (i *inspector) Check(_ context.Context, r *request.Request) pipeline.Verdict {
	i.mu.Lock()
	i.got = append(i.got, r)
	decide, v := i.decide, i.verdict
	i.mu.Unlock()
	if decide != nil {
		return decide(r)
	}
	return v
}

func (*inspector) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

func (i *inspector) requests() []*request.Request {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]*request.Request(nil), i.got...)
}

// agent runs a Server on a Unix socket.
type agent struct {
	srv  *Server
	sock string
	done chan error
}

func startAgent(t *testing.T, p pipeline.Inspector, cfg Config) *agent {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	srv, err := New(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "spoe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{srv: srv, sock: sock, done: make(chan error, 1)}
	go func() { a.done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if err := <-a.done; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return a
}

// haproxy is the HAProxy side of one connection.
type haproxy struct {
	t  *testing.T
	nc net.Conn
}

func (a *agent) dial(t *testing.T) *haproxy {
	t.Helper()
	nc, err := net.Dial("unix", a.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	return &haproxy{t: t, nc: nc}
}

func (h *haproxy) send(b []byte) {
	h.t.Helper()
	if _, err := h.nc.Write(b); err != nil {
		h.t.Fatal(err)
	}
}

func (h *haproxy) recv() frame {
	h.t.Helper()
	f, _, err := readFrame(h.nc, nil, 1<<24, nil)
	if err != nil {
		h.t.Fatalf("reading a frame: %v", err)
	}
	return f
}

// closed checks that the agent closed the connection.
func (h *haproxy) closed() {
	h.t.Helper()
	// A reset, when the agent closed with unread data.
	if _, err := h.nc.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		h.t.Fatalf("connection still open: %v", err)
	}
}

func kvs(t testing.TB, f frame) map[string]value {
	t.Helper()
	d := decoder{b: f.payload}
	items, err := d.kvList()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]value{}
	for _, it := range items {
		m[it.name] = it.val
	}
	return m
}

// hello runs the handshake with HAProxy's recorded HELLO.
func (h *haproxy) hello() map[string]value {
	h.t.Helper()
	h.send(readFixture(h.t, "hello.bin"))
	f := h.recv()
	if f.typ != frameAgentHello {
		h.t.Fatalf("answered HELLO with frame type %d: %v", f.typ, kvs(h.t, f))
	}
	return kvs(h.t, f)
}

// disconnected expects AGENT-DISCONNECT with status, then the end of the
// connection.
func (h *haproxy) disconnected(status uint64) {
	h.t.Helper()
	f := h.recv()
	if f.typ != frameAgentDisconnect {
		h.t.Fatalf("frame type %d, want AGENT-DISCONNECT", f.typ)
	}
	if got := kvs(h.t, f); got["status-code"].u != status {
		h.t.Fatalf("status-code %d (%s), want %d", got["status-code"].u, got["message"].String(), status)
	}
	h.closed()
}

// ack reads an ACK and returns its variables.
func (h *haproxy) ack() (frame, map[string]value) {
	h.t.Helper()
	f := h.recv()
	if f.typ != frameAck {
		h.t.Fatalf("frame type %d, want ACK", f.typ)
	}
	vars, err := decodeActions(f.payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return f, vars
}

func TestHello(t *testing.T) {
	a := startAgent(t, &inspector{}, Config{MaxBodyBytes: 1 << 10})
	got := a.dial(t).hello()
	if got["version"].String() != "2.0" || got["capabilities"].String() != "pipelining" {
		t.Errorf("AGENT-HELLO %+v", got)
	}
	// The lower of HAProxy's 16380 and the agent's own.
	if v := got["max-frame-size"]; v.typ != typeUint32 || v.u != 16380 {
		t.Errorf("max-frame-size %+v", v)
	}
}

// A health check (option spop-check) gets AGENT-HELLO, and the connection
// is closed.
func TestHealthcheck(t *testing.T) {
	a := startAgent(t, &inspector{}, Config{})
	h := a.dial(t)
	h.send(readFixture(t, "hello-healthcheck.bin"))
	if f := h.recv(); f.typ != frameAgentHello {
		t.Fatalf("frame type %d", f.typ)
	}
	h.closed()
}

func helloFrame(items func(*encoder)) []byte {
	e := newFrame(frameHAProxyHello, 0, 0)
	items(e)
	return e.finish()
}

func TestHelloErrors(t *testing.T) {
	for name, c := range map[string]struct {
		frame  []byte
		status uint64
	}{
		"no version": {helloFrame(func(e *encoder) {
			e.kvUint32("max-frame-size", 16380)
			e.kvString("capabilities", "")
		}), statusNoVersion},
		"no frame size": {helloFrame(func(e *encoder) {
			e.kvString("supported-versions", "2.0")
			e.kvString("capabilities", "")
		}), statusNoFrameSize},
		"no capabilities": {helloFrame(func(e *encoder) {
			e.kvString("supported-versions", "2.0")
			e.kvUint32("max-frame-size", 16380)
		}), statusNoCapabilities},
		"old version": {helloFrame(func(e *encoder) {
			e.kvString("supported-versions", "1.0")
			e.kvUint32("max-frame-size", 16380)
			e.kvString("capabilities", "")
		}), statusBadVersion},
		"small frames": {helloFrame(func(e *encoder) {
			e.kvString("supported-versions", "2.0")
			e.kvUint32("max-frame-size", 255)
			e.kvString("capabilities", "")
		}), statusBadFrameSize},
		"NOTIFY first":  {readFixture(t, "notify-get.bin"), statusInvalid},
		"bad KV-LIST":   {[]byte{0, 0, 0, 9, frameHAProxyHello, 0, 0, 0, 1, 0, 0, 5, 'a'}, statusInvalid},
		"frame too big": {[]byte{0, 2, 0, 0}, statusTooBig},
	} {
		t.Run(name, func(t *testing.T) {
			a := startAgent(t, &inspector{}, Config{})
			h := a.dial(t)
			h.send(c.frame)
			h.disconnected(c.status)
		})
	}
}

// A NOTIFY of HAProxy 3.2 is inspected as the request it describes, and
// answered with the verdict's variables.
func TestNotify(t *testing.T) {
	insp := &inspector{verdict: pipeline.Verdict{Action: pipeline.ActionDeny, Status: http.StatusForbidden, Reason: pipeline.ReasonRule}}
	a := startAgent(t, insp, Config{MaxBodyBytes: 1 << 10})
	h := a.dial(t)
	h.hello()
	notify := fixtureFrame(t, "notify-get.bin")
	h.send(readFixture(t, "notify-get.bin"))
	f, vars := h.ack()
	if f.streamID != notify.streamID || f.frameID != notify.frameID || f.flags != flagFin {
		t.Errorf("ACK %d/%d, flags %d, for NOTIFY %d/%d", f.streamID, f.frameID, f.flags, notify.streamID, notify.frameID)
	}
	if vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 403 || vars[VarRequestID].String() != "req-1" {
		t.Errorf("variables %+v", vars)
	}
	got := insp.requests()
	if len(got) != 1 {
		t.Fatalf("inspected %d requests", len(got))
	}
	r := got[0]
	if r.Method != "GET" || r.RawURI != "/hello?x=1" || r.Host != "127.0.0.1:47480" || r.Proto != "HTTP/1.1" ||
		r.Scheme != "http" || r.ID != "req-1" || r.Headers.Get("User-Agent") != "test/1.0" || r.Headers.Get("Host") != "" {
		t.Errorf("inspected %+v", r)
	}
	if r.ClientIP != netip.MustParseAddr("127.0.0.1") || r.PeerIP != r.ClientIP || r.Body != nil || r.BodyTruncated {
		t.Errorf("inspected %+v", r)
	}

	// Allowed: no status, and a request ID for HAProxy to pass on.
	insp.mu.Lock()
	insp.verdict = pipeline.Verdict{}
	insp.mu.Unlock()
	h.send(readFixture(t, "notify-sqli.bin"))
	_, vars = h.ack()
	if _, ok := vars[VarStatus]; ok || vars[VarAction].String() != ActionAllow || len(vars[VarRequestID].String()) != 16 {
		t.Errorf("variables %+v", vars)
	}

	// HAPROXY-DISCONNECT is answered, and the connection closed.
	e := newFrame(frameHAProxyDisconnect, 0, 0)
	e.kvUint32("status-code", 0)
	e.kvString("message", "")
	h.send(e.finish())
	h.disconnected(statusNormal)
}

// The recorded requests are rebuilt as HAProxy received them.
func TestRecordedRequests(t *testing.T) {
	for _, c := range []struct {
		file, method, uri, proto, body string
		truncated                      bool
		contentLength                  string
	}{
		{file: "notify-sqli.bin", method: "GET", uri: "/search?id=1%27%20OR%20%271%27%3D%271", proto: "HTTP/1.1"},
		{file: "notify-post-xss.bin", method: "POST", uri: "/form", proto: "HTTP/1.1", body: "q=<script>alert(1)</script>", contentLength: "27"},
		// Chunked, and complete.
		{file: "notify-chunked.bin", method: "POST", uri: "/form", proto: "HTTP/1.1", body: "name=joe"},
		{file: "notify-h2.bin", method: "GET", uri: "/h2?b=c", proto: "HTTP/2.0"},
		// 16000 bytes, of which HAProxy buffered what fit its buffer.
		{file: "notify-cut-body.bin", method: "POST", uri: "/form", proto: "HTTP/1.1", truncated: true, contentLength: "16030"},
	} {
		t.Run(c.file, func(t *testing.T) {
			srv, err := New(&inspector{}, Config{MaxBodyBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			req, _, err := srv.toRequest(fixtureFrame(t, c.file).payload, 16380)
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != c.method || req.RawURI != c.uri || req.Proto != c.proto || req.BodyTruncated != c.truncated {
				t.Errorf("%s %s %s, truncated %v", req.Method, req.RawURI, req.Proto, req.BodyTruncated)
			}
			if !c.truncated && string(req.Body) != c.body {
				t.Errorf("body %q, want %q", req.Body, c.body)
			}
			if c.truncated && (len(req.Body) < 15000 || len(req.Body) >= 16030) {
				t.Errorf("body of %d bytes", len(req.Body))
			}
			if got := req.Headers.Get("Content-Length"); got != c.contentLength {
				t.Errorf("Content-Length %q, want %q", got, c.contentLength)
			}
		})
	}
}

// notifyFrame builds a NOTIFY with the agent's message and the given
// arguments.
func notifyFrame(streamID, frameID uint64, args ...func(*encoder)) []byte {
	e := newFrame(frameNotify, streamID, frameID)
	e.bytes(MessageName)
	e.b = append(e.b, byte(len(args)))
	for _, a := range args {
		a(e)
	}
	return e.finish()
}

func argString(name, v string) func(*encoder) {
	return func(e *encoder) {
		e.bytes(name)
		e.str(v)
	}
}

func argBinary(name string, v []byte) func(*encoder) {
	return func(e *encoder) {
		e.bytes(name)
		e.b = append(e.b, typeBinary)
		e.bytes(string(v))
	}
}

func argIP(name string, a netip.Addr) func(*encoder) {
	return func(e *encoder) {
		e.bytes(name)
		if a.Is4() {
			e.b = append(e.b, typeIPv4)
		} else {
			e.b = append(e.b, typeIPv6)
		}
		e.b = append(e.b, a.AsSlice()...)
	}
}

func argBool(name string, v bool) func(*encoder) {
	return func(e *encoder) {
		e.bytes(name)
		if v {
			e.b = append(e.b, typeBool|0x10)
		} else {
			e.b = append(e.b, typeBool)
		}
	}
}

// hdrs encodes headers as req.hdrs_bin does.
func hdrs(kv ...string) []byte {
	var b []byte
	for i := 0; i+1 < len(kv); i += 2 {
		b = appendVarint(b, uint64(len(kv[i])))
		b = append(b, kv[i]...)
		b = appendVarint(b, uint64(len(kv[i+1])))
		b = append(b, kv[i+1]...)
	}
	return append(b, 0, 0)
}

// A request the agent can't read is denied with 400.
func TestUninspectable(t *testing.T) {
	ok := []func(*encoder){
		argString(ArgMethod, "GET"), argString(ArgPath, "/"), argBinary(ArgHeaders, hdrs("host", "a.example")),
	}
	for name, args := range map[string][]func(*encoder){
		"no method":       ok[1:],
		"bad method":      {argString(ArgMethod, "G T"), ok[1], ok[2]},
		"absolute path":   {ok[0], argString(ArgPath, "http://a/"), ok[2]},
		"fragment":        {ok[0], argString(ArgPath, "/#x"), ok[2]},
		"headers cut":     {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example")[:5])},
		"no headers end":  {ok[0], ok[1], argBinary(ArgHeaders, []byte{1, 'a', 1, 'b'})},
		"two hosts":       {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example", "Host", "b.example"))},
		"bad host":        {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a b"))},
		"bad header":      {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example", "x y", "1"))},
		"header newline":  {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example", "x", "1\nz: 2"))},
		"bad version":     {ok[0], ok[1], ok[2], argString(ArgVersion, "11")},
		"method twice":    {ok[0], ok[0], ok[1], ok[2]},
		"ip as string":    {ok[0], ok[1], ok[2], argString(ArgIP, "1.2.3.4")},
		"bad length":      {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example", "content-length", "-1"))},
		"two lengths":     {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a.example", "content-length", "1", "content-length", "2"))},
		"headers as bool": {ok[0], ok[1], argBool(ArgHeaders, true)},
		"chunked length":  {ok[0], ok[1], argBinary(ArgHeaders, hdrs("host", "a", "content-length", "1", "transfer-encoding", "chunked"))},
	} {
		t.Run(name, func(t *testing.T) {
			insp := &inspector{}
			a := startAgent(t, insp, Config{})
			h := a.dial(t)
			h.hello()
			h.send(notifyFrame(1, 1, args...))
			_, vars := h.ack()
			if vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 400 {
				t.Errorf("variables %+v", vars)
			}
			if n := len(insp.requests()); n != 0 {
				t.Errorf("inspected %d requests", n)
			}
		})
	}
	// Another message, or none, is not the agent's.
	a := startAgent(t, &inspector{}, Config{})
	h := a.dial(t)
	h.hello()
	e := newFrame(frameNotify, 1, 1)
	e.bytes("other")
	e.b = append(e.b, 0)
	h.send(e.finish())
	if _, vars := h.ack(); vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 400 {
		t.Errorf("variables %+v", vars)
	}
}

func TestBody(t *testing.T) {
	base := func(headers []byte, body func(*encoder)) []func(*encoder) {
		args := []func(*encoder){argString(ArgMethod, "POST"), argString(ArgPath, "/f"), argBinary(ArgHeaders, headers)}
		if body != nil {
			args = append(args, body)
		}
		return args
	}
	nullBody := func(e *encoder) {
		e.bytes(ArgBody)
		e.b = append(e.b, typeNull)
	}
	for name, c := range map[string]struct {
		args          []func(*encoder)
		body          string
		truncated     bool
		contentLength string
	}{
		"complete":         {args: base(hdrs("host", "a", "content-length", "5"), argBinary(ArgBody, []byte("x=123"))), body: "x=123", contentLength: "5"},
		"cut":              {args: base(hdrs("host", "a", "content-length", "9"), argBinary(ArgBody, []byte("x=123"))), body: "x=123", truncated: true, contentLength: "9"},
		"over the limit":   {args: base(hdrs("host", "a", "content-length", "12"), argBinary(ArgBody, []byte("x=1234567890"))), body: "x=12345678", truncated: true, contentLength: "12"},
		"not sent":         {args: base(hdrs("host", "a", "content-length", "5"), nil), truncated: true, contentLength: "5"},
		"null":             {args: base(hdrs("host", "a", "content-length", "5"), nullBody), truncated: true, contentLength: "5"},
		"empty POST":       {args: base(hdrs("host", "a"), argBinary(ArgBody, nil)), contentLength: "0"},
		"chunked":          {args: base(hdrs("host", "a", "transfer-encoding", "chunked"), argBinary(ArgBody, []byte("x=1"))), body: "x=1"},
		"chunked, no body": {args: base(hdrs("host", "a", "transfer-encoding", "chunked"), nil), truncated: true},
		// HTTP/2 without Content-Length: given one.
		"no length": {args: base(hdrs("host", "a"), argBinary(ArgBody, []byte("x=1"))), body: "x=1", contentLength: "3"},
		// Chunked, and as large as a full buffer: maybe cut.
		"chunked, large": {args: base(hdrs("host", "a", "transfer-encoding", "chunked"), argBinary(ArgBody, bytes.Repeat([]byte("a"), 8))), body: "aaaaaaaa", truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv, err := New(&inspector{}, Config{MaxBodyBytes: 10})
			if err != nil {
				t.Fatal(err)
			}
			payload := notifyFrame(1, 1, c.args...)
			f, _, err := readFrame(bytes.NewReader(payload), nil, 1<<20, nil)
			if err != nil {
				t.Fatal(err)
			}
			maxFrame := uint32(1 << 16)
			if name == "chunked, large" {
				// The frame is over half the maximum, less the slack.
				maxFrame = uint32(2 * (len(f.payload) + 1024 + 16 + 1))
			}
			req, _, err := srv.toRequest(f.payload, maxFrame)
			if err != nil {
				t.Fatal(err)
			}
			if string(req.Body) != c.body || req.BodyTruncated != c.truncated {
				t.Errorf("body %q, truncated %v", req.Body, req.BodyTruncated)
			}
			if got := req.Headers.Get("Content-Length"); got != c.contentLength {
				t.Errorf("Content-Length %q, want %q", got, c.contentLength)
			}
		})
	}
	// Under the slack, the same chunked body is complete.
	srv, _ := New(&inspector{}, Config{MaxBodyBytes: 10})
	payload := notifyFrame(1, 1, base(hdrs("host", "a", "transfer-encoding", "chunked"), argBinary(ArgBody, []byte("aaaaaaaa")))...)
	f, _, _ := readFrame(bytes.NewReader(payload), nil, 1<<20, nil)
	req, _, err := srv.toRequest(f.payload, uint32(2*(len(f.payload)+1024+16+1)+2))
	if err != nil || req.BodyTruncated {
		t.Errorf("truncated %v, %v", req.BodyTruncated, err)
	}
}

// The client is src, or who X-Forwarded-For names when src is a trusted
// proxy; HTTPS comes from ssl_fc.
func TestClientIPAndScheme(t *testing.T) {
	resolver, err := clientip.NewResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(&inspector{}, Config{ClientIP: resolver})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		src, want string
	}{
		{"10.1.2.3", "203.0.113.7"},
		{"198.51.100.1", "198.51.100.1"},
		{"2001:db8::1", "2001:db8::1"},
	} {
		payload := notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/"),
			argBinary(ArgHeaders, hdrs("host", "a", "x-forwarded-for", "203.0.113.7")),
			argIP(ArgIP, netip.MustParseAddr(c.src)), argBool(ArgHTTPS, true))
		f, _, _ := readFrame(bytes.NewReader(payload), nil, 1<<20, nil)
		req, _, err := srv.toRequest(f.payload, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		if req.ClientIP.String() != c.want || req.PeerIP.String() != c.src || req.Scheme != "https" {
			t.Errorf("src %s: client %s, peer %s, scheme %s", c.src, req.ClientIP, req.PeerIP, req.Scheme)
		}
	}
}

// With pipelining, NOTIFY frames are answered as they are decided, not in
// order.
func TestPipelining(t *testing.T) {
	release := make(chan struct{})
	insp := &inspector{decide: func(r *request.Request) pipeline.Verdict {
		if r.RawURI == "/slow" {
			<-release
		}
		return pipeline.Verdict{}
	}}
	a := startAgent(t, insp, Config{})
	h := a.dial(t)
	h.hello()
	req := func(sid uint64, path string) []byte {
		return notifyFrame(sid, 1, argString(ArgMethod, "GET"), argString(ArgPath, path), argBinary(ArgHeaders, hdrs("host", "a")))
	}
	h.send(req(1, "/slow"))
	h.send(req(2, "/fast"))
	if f, _ := h.ack(); f.streamID != 2 {
		t.Fatalf("first ACK for stream %d, want 2", f.streamID)
	}
	close(release)
	if f, _ := h.ack(); f.streamID != 1 {
		t.Fatalf("second ACK for stream %d, want 1", f.streamID)
	}
}

func TestFrameErrors(t *testing.T) {
	notify := notifyFrame(1, 1, argString(ArgMethod, "GET"))
	notFin := bytes.Clone(notify)
	notFin[8] = 0 // the low byte of the flags
	for name, c := range map[string]struct {
		frame  []byte
		status uint64
	}{
		"fragmented":    {notFin, statusFragmentation},
		"unknown type":  {newFrame(42, 0, 0).finish(), statusInvalid},
		"AGENT-HELLO":   {newFrame(frameAgentHello, 0, 0).finish(), statusInvalid},
		"over the size": {append([]byte{0, 0, 0x40, 0}, make([]byte, 0x4000)...), statusTooBig},
		"no stream id":  {[]byte{0, 0, 0, 5, frameNotify, 0, 0, 0, 1}, statusInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			a := startAgent(t, &inspector{}, Config{})
			h := a.dial(t)
			h.hello()
			h.send(c.frame)
			h.disconnected(c.status)
		})
	}
}

// An aborted NOTIFY is not answered.
func TestAbort(t *testing.T) {
	insp := &inspector{}
	a := startAgent(t, insp, Config{})
	h := a.dial(t)
	h.hello()
	aborted := notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/a"), argBinary(ArgHeaders, hdrs("host", "a")))
	aborted[8] |= flagAbort
	h.send(aborted)
	h.send(notifyFrame(2, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/b"), argBinary(ArgHeaders, hdrs("host", "a"))))
	if f, _ := h.ack(); f.streamID != 2 {
		t.Fatalf("ACK for stream %d", f.streamID)
	}
	if got := insp.requests(); len(got) != 1 || got[0].RawURI != "/b" {
		t.Fatalf("inspected %v", got)
	}
}

// A frame begun must arrive within the read timeout; an idle connection
// may wait.
func TestReadTimeout(t *testing.T) {
	a := startAgent(t, &inspector{}, Config{ReadTimeout: 100 * time.Millisecond})
	h := a.dial(t)
	h.hello()
	time.Sleep(300 * time.Millisecond)
	frame := notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/"), argBinary(ArgHeaders, hdrs("host", "a")))
	h.send(frame)
	h.ack()
	h.send(frame[:10])
	h.disconnected(statusTimeout)
}

// Shutdown lets a NOTIFY being answered finish, then says goodbye; Serve
// returns.
func TestShutdown(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	insp := &inspector{decide: func(*request.Request) pipeline.Verdict {
		close(started)
		<-release
		return pipeline.Verdict{}
	}}
	srv, err := New(insp, Config{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "spoe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	h := (&agent{sock: sock}).dial(t)
	idle := (&agent{sock: sock}).dial(t)
	h.hello()
	idle.hello()
	h.send(notifyFrame(1, 1, argString(ArgMethod, "GET"), argString(ArgPath, "/"), argBinary(ArgHeaders, hdrs("host", "a"))))
	<-started

	shut := make(chan error, 1)
	go func() { shut <- srv.Shutdown(context.Background()) }()
	idle.disconnected(statusNormal)
	if err := <-served; !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve: %v", err)
	}
	close(release)
	if _, vars := h.ack(); vars[VarAction].String() != ActionAllow {
		t.Errorf("variables %+v", vars)
	}
	h.disconnected(statusNormal)
	if err := <-shut; err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := srv.Serve(ln); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve after Shutdown: %v", err)
	}
}

// With the Core Rule Set, the recorded attacks are denied and the benign
// request allowed, as the reverse proxy would.
func TestRecordedFramesWithCRS(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
	var logs strings.Builder
	a := startAgent(t, p, Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	h := a.dial(t)
	h.hello()
	for file, want := range map[string]string{
		"notify-get.bin":      ActionAllow,
		"notify-h2.bin":       ActionAllow,
		"notify-chunked.bin":  ActionAllow,
		"notify-sqli.bin":     ActionDeny,
		"notify-post-xss.bin": ActionDeny,
	} {
		h.send(readFixture(t, file))
		_, vars := h.ack()
		if got := vars[VarAction].String(); got != want {
			t.Errorf("%s: %s, want %s", file, got, want)
		}
		if want == ActionDeny && vars[VarStatus].u != 403 {
			t.Errorf("%s: status %d", file, vars[VarStatus].u)
		}
	}
	if n := strings.Count(logs.String(), `"msg":"security event"`); n != 2 {
		t.Errorf("%d security events", n)
	}
	// In block mode, a body HAProxy cut is denied as oversized.
	h.send(readFixture(t, "notify-cut-body.bin"))
	if _, vars := h.ack(); vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 413 {
		t.Errorf("cut body: %+v", vars)
	}
}
