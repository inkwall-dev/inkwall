// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package spoe implements an SPOE agent (an SPOA): the adapter HAProxy's
// Stream Processing Offload Engine calls over SPOP, its binary protocol
// (doc/SPOE.txt in HAProxy).
//
// HAProxy opens a few connections to the agent and starts each with a HELLO
// handshake, which settles the protocol version (2.0), the maximum frame
// size and pipelining. A HELLO with healthcheck set (option spop-check) is
// answered, and the connection closed. HAProxy then sends one NOTIFY frame
// per event that has messages: the agent answers each with an ACK carrying
// actions, here set-var actions in the transaction scope that HAProxy's
// rules act on. With pipelining, several NOTIFY frames are in flight on a
// connection and are answered in any order.
//
// The agent reads the message named MessageName, whose arguments describe
// the request: method, path (pathq: path and query), version, headers
// (req.hdrs_bin), body (req.body), ip (src) and https (ssl_fc). It answers
// with the variables action ("allow" or "deny"), status (the status to deny
// with) and request_id, under the prefix of the spoe-agent section (txn.
// inkwall.action with option var-prefix inkwall). The variables are set on
// every answer, so an unset action means HAProxy didn't get one: the agent
// is down, or timed out. HAProxy then sets no variable at all, and its
// rules decide (the failure mode): a rule that denies when action is unset
// fails closed.
//
// A denied gRPC call (by its Content-Type) also gets grpc_status,
// grpc_message and grpc_content_type, for HAProxy to answer it as a gRPC
// server would: HTTP 200 with the gRPC status in the headers.
//
// The operator's probe (package haproxyprobe), a request whose
// X-Inkwall-Probe header has a valid MAC under the bundle's probe key, is answered uninspected with the
// variable probe, which the route's rules return: it tells the operator
// that HAProxy runs the filter on that route.
//
// A NOTIFY without the message, or with arguments the agent can't read,
// gets action deny with status 400: only a misconfigured HAProxy sends one,
// and the request is not let through.
//
// The body is inspected as HAProxy buffered it (option http-buffer-request).
// HAProxy buffers at most its buffer size (tune.bufsize), and sends no body
// without that option. A body shorter than its Content-Length was cut, and
// counts as truncated (body.onOversize decides). A body without
// Content-Length (chunked, or HTTP/2) counts as complete only when its
// frame is well under half the maximum frame size: HAProxy's buffer, of
// which the frame size is 4 bytes less, holds at least half its size of a
// request before it is full, whatever tune.maxrewrite is.
//
// The client address is src, HAProxy's client (the PROXY protocol's, if
// HAProxy accepts it), resolved through the trusted proxies with the
// request's X-Forwarded-For.
package spoe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/clientip"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// MessageName is the spoe-message the agent inspects.
const MessageName = "inkwall-request"

// Message arguments.
const (
	ArgMethod  = "method"
	ArgPath    = "path"
	ArgVersion = "version"
	ArgHeaders = "headers"
	ArgBody    = "body"
	ArgIP      = "ip"
	ArgHTTPS   = "https"
)

// Variables the agent sets, in the transaction scope.
const (
	VarAction    = "action"
	VarStatus    = "status"
	VarRequestID = "request_id"
	// VarGRPCStatus, VarGRPCMessage and VarGRPCContentType are set only
	// to deny a gRPC call (by its Content-Type): its gRPC status, the
	// grpc-message and the Content-Type to answer it with, trailers-only,
	// as the other adapters answer one.
	VarGRPCStatus      = "grpc_status"
	VarGRPCMessage     = "grpc_message"
	VarGRPCContentType = "grpc_content_type"
	// VarProbe is set only to answer the operator's probe
	// (haproxyprobe): the answer, which the route's rules return with
	// status 299. The probe is denied as well.
	VarProbe = "probe"
)

// Values of VarAction.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// version is the SPOP version the agent speaks.
const version = "2.0"

// envelope bounds a frame beyond the body it carries: the headers and the
// other arguments.
const envelope = 1 << 20

const (
	// helloTimeout bounds the wait for HAPROXY-HELLO.
	helloTimeout = 10 * time.Second
	// writeTimeout bounds writing one frame.
	writeTimeout = 10 * time.Second
	// maxHelloSize bounds HAPROXY-HELLO, a few short items.
	maxHelloSize = 64 << 10
	// maxInFlight bounds the NOTIFY frames of one connection answered at
	// once; HAProxy waits for some to be answered before sending more.
	maxInFlight = 256
)

// Config configures a Server.
type Config struct {
	// MaxBodyBytes is how much of a request body is inspected. Zero
	// disables body inspection.
	MaxBodyBytes int64
	// ClientIP resolves the client address from src and X-Forwarded-For.
	// Nil trusts no proxies: the client is src.
	ClientIP *clientip.Resolver
	// ReadTimeout bounds reading one frame once it has begun. Zero: no
	// limit. A connection may stay idle between frames.
	ReadTimeout time.Duration
	// Logger receives one security event per denied or logged request.
	// Nil uses slog.Default().
	Logger *slog.Logger
	// Metrics counts the messages and connections the agent can't read
	// (nil: none).
	Metrics *telemetry.Metrics
	// Events records each security event for the operator (nil: logged
	// only).
	Events *events.Recorder
	// ProbeKey returns the key of the operator's probe (the bundle's), or
	// nil: no probes are answered. Nil: none.
	ProbeKey func() []byte
}

// Server is an SPOE agent.
type Server struct {
	pipeline    pipeline.Inspector
	maxBody     int64
	maxFrame    uint32
	clientIP    *clientip.Resolver
	readTimeout time.Duration
	logger      *slog.Logger
	metrics     *telemetry.Metrics
	events      *events.Recorder
	probeKey    func() []byte

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*conn]struct{}
	// closing is set, under mu, by Shutdown; read without mu by the
	// connections (closingNow), which hold their own lock then: taking mu
	// there would invert Shutdown's order (#338).
	closing atomic.Bool
	wg      sync.WaitGroup
}

// New returns a Server that inspects requests with p.
func New(p pipeline.Inspector, cfg Config) (*Server, error) {
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("max body bytes %d must not be negative", cfg.MaxBodyBytes)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	resolver := cfg.ClientIP
	if resolver == nil {
		resolver = &clientip.Resolver{}
	}
	// HAProxy's frames are at most its buffer size; the agent takes the
	// body limit and the headers.
	maxFrame := uint64(cfg.MaxBodyBytes) + envelope
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		pipeline:    p,
		maxBody:     cfg.MaxBodyBytes,
		maxFrame:    uint32(min(maxFrame, 1<<31)), // #nosec G115 -- bounded
		clientIP:    resolver,
		readTimeout: cfg.ReadTimeout,
		logger:      logger,
		metrics:     cfg.Metrics,
		events:      cfg.Events,
		probeKey:    cfg.ProbeKey,
		ctx:         ctx,
		cancel:      cancel,
		listeners:   map[net.Listener]struct{}{},
		conns:       map[*conn]struct{}{},
	}, nil
}

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("spoe: server closed")

// Serve accepts HAProxy's connections on ln until Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closing.Load() {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing.Load()
			s.mu.Unlock()
			if closing {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		c := &conn{srv: s, nc: nc, idle: true}
		s.mu.Lock()
		if s.closing.Load() {
			s.mu.Unlock()
			_ = nc.Close()
			return ErrServerClosed
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			c.serve()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// Shutdown stops accepting connections, lets the NOTIFY frames being
// answered finish, says goodbye to HAProxy with AGENT-DISCONNECT and closes
// the connections. When ctx ends first, the connections are closed at once.
func (s *Server) Shutdown(ctx context.Context) error {
	// Each connection's lock is taken without the server's (wake), which
	// a connection going idle holds its own while it reads closing: the
	// other order deadlocked (#338). A connection added before closing is
	// set is woken here; one after sees it in Serve; one going idle after
	// the wake sees it in setIdle.
	s.mu.Lock()
	s.closing.Store(true)
	for ln := range s.listeners {
		_ = ln.Close()
	}
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.wake()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.cancel()
		return nil
	case <-ctx.Done():
		s.cancel()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.nc.Close()
		}
		s.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

// closingNow reports whether Shutdown has begun. It takes no lock: a
// connection calls it holding its own.
func (s *Server) closingNow() bool { return s.closing.Load() }

// conn is one connection from HAProxy.
type conn struct {
	srv *Server
	nc  net.Conn

	// maxFrame is the negotiated maximum frame size.
	maxFrame   uint32
	pipelining bool

	// mu guards idle: the connection waits for a frame, and Shutdown may
	// interrupt the wait.
	mu   sync.Mutex
	idle bool

	writeMu  sync.Mutex
	inFlight sync.WaitGroup
}

// wake interrupts the wait for a frame, so the connection sees Shutdown.
func (c *conn) wake() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idle {
		_ = c.nc.SetReadDeadline(time.Now())
	}
}

func (c *conn) setIdle(idle bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idle = idle
	if idle && c.srv.closingNow() {
		_ = c.nc.SetReadDeadline(time.Now())
	}
}

// serve runs the HELLO handshake, then answers frames until HAProxy or the
// server ends the connection.
func (c *conn) serve() {
	defer func() { _ = c.nc.Close() }()
	if !c.hello() {
		return
	}
	var buf []byte
	sem := make(chan struct{}, maxInFlight)
	defer c.inFlight.Wait()
	for {
		_ = c.nc.SetReadDeadline(time.Time{})
		c.setIdle(true)
		var (
			f   frame
			err error
		)
		f, buf, err = readFrame(c.nc, buf, c.maxFrame, func() {
			// The frame has begun: it is read whole, even during Shutdown.
			c.setIdle(false)
			var deadline time.Time
			if c.srv.readTimeout > 0 {
				deadline = time.Now().Add(c.srv.readTimeout)
			}
			_ = c.nc.SetReadDeadline(deadline)
		})
		c.setIdle(false)
		if err != nil {
			if c.srv.closingNow() {
				c.inFlight.Wait()
				c.disconnect(statusNormal, "agent shutting down")
				return
			}
			c.fail(err)
			return
		}
		switch f.typ {
		case frameNotify:
			if f.flags&flagFin == 0 {
				c.disconnect(statusFragmentation, "fragmented frames are not supported")
				return
			}
			if f.flags&flagAbort != 0 {
				continue
			}
			if !c.pipelining {
				c.notify(f)
				continue
			}
			// The payload is read into buf, which the next frame reuses.
			f.payload = append([]byte(nil), f.payload...)
			sem <- struct{}{}
			c.inFlight.Add(1)
			go func() {
				defer func() {
					<-sem
					c.inFlight.Done()
				}()
				c.notify(f)
			}()
		case frameHAProxyDisconnect:
			c.inFlight.Wait()
			c.disconnect(statusNormal, "")
			return
		default:
			c.disconnect(statusInvalid, fmt.Sprintf("unexpected frame type %d", f.typ))
			return
		}
	}
}

// fail ends the connection after a read error.
func (c *conn) fail(err error) {
	var tooBig frameTooBigError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		// HAProxy closed the connection.
	case errors.As(err, &tooBig):
		c.disconnect(statusTooBig, err.Error())
	case isTimeout(err):
		c.disconnect(statusTimeout, "timeout reading a frame")
	case errors.Is(err, io.ErrUnexpectedEOF):
	default:
		c.disconnect(statusInvalid, "invalid frame: "+err.Error())
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		c.srv.logger.LogAttrs(c.srv.ctx, slog.LevelError, "spoe connection closed", slog.Any("error", err))
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// hello answers HAPROXY-HELLO. It reports whether frames follow: not after
// an error or a health check.
func (c *conn) hello() bool {
	_ = c.nc.SetReadDeadline(time.Now().Add(helloTimeout))
	f, _, err := readFrame(c.nc, nil, min(c.srv.maxFrame, maxHelloSize), nil)
	if err != nil {
		c.fail(err)
		return false
	}
	if f.typ != frameHAProxyHello {
		c.disconnect(statusInvalid, fmt.Sprintf("frame type %d before HAPROXY-HELLO", f.typ))
		return false
	}
	d := decoder{b: f.payload}
	items, err := d.kvList()
	if err != nil {
		c.disconnect(statusInvalid, "invalid HAPROXY-HELLO: "+err.Error())
		return false
	}
	var (
		versions, capabilities string
		maxFrame               uint64
		haveVersions, haveSize bool
		haveCaps, healthcheck  bool
	)
	for _, it := range items {
		switch it.name {
		case "supported-versions":
			versions, haveVersions = it.val.String(), it.val.typ == typeString
		case "max-frame-size":
			switch it.val.typ {
			case typeUint32, typeInt32, typeUint64, typeInt64:
				maxFrame, haveSize = it.val.u, true
			}
		case "capabilities":
			capabilities, haveCaps = it.val.String(), it.val.typ == typeString
		case "healthcheck":
			healthcheck = it.val.typ == typeBool && it.val.b
		}
	}
	switch {
	case !haveVersions:
		c.disconnect(statusNoVersion, "supported-versions not found")
		return false
	case !haveSize:
		c.disconnect(statusNoFrameSize, "max-frame-size not found")
		return false
	case !haveCaps:
		c.disconnect(statusNoCapabilities, "capabilities not found")
		return false
	case !supportsVersion(versions):
		c.disconnect(statusBadVersion, "unsupported version: "+versions+", want "+version)
		return false
	case maxFrame < minFrameSize:
		c.disconnect(statusBadFrameSize, fmt.Sprintf("max-frame-size %d under %d", maxFrame, minFrameSize))
		return false
	}
	c.maxFrame = uint32(min(maxFrame, uint64(c.srv.maxFrame))) // #nosec G115 -- bounded
	var caps []string
	for capability := range strings.SplitSeq(capabilities, ",") {
		if strings.TrimSpace(capability) == "pipelining" {
			c.pipelining = true
			caps = append(caps, "pipelining")
		}
	}
	e := newFrame(frameAgentHello, 0, 0)
	e.kvString("version", version)
	e.kvUint32("max-frame-size", c.maxFrame)
	e.kvString("capabilities", strings.Join(caps, ","))
	if err := c.write(e.finish()); err != nil {
		return false
	}
	return !healthcheck
}

// supportsVersion reports whether HAProxy's supported-versions include
// SPOP 2.0: a "Major.Minor" in the list with major 2 covers all minors up
// to it.
func supportsVersion(list string) bool {
	for v := range strings.SplitSeq(list, ",") {
		major, minor, ok := strings.Cut(strings.TrimSpace(v), ".")
		if !ok {
			continue
		}
		if _, err := strconv.ParseUint(minor, 10, 16); err == nil && major == "2" {
			return true
		}
	}
	return false
}

// disconnect sends AGENT-DISCONNECT; the caller closes the connection.
func (c *conn) disconnect(status uint32, msg string) {
	if status != statusNormal && status != statusTimeout {
		c.srv.metrics.AdapterError(telemetry.ErrProtocol)
	}
	e := newFrame(frameAgentDisconnect, 0, 0)
	e.kvUint32("status-code", status)
	e.kvString("message", msg)
	_ = c.write(e.finish())
}

func (c *conn) write(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.nc.Write(b)
	return err
}

// notify answers one NOTIFY frame with an ACK.
func (c *conn) notify(f frame) {
	ack := newFrame(frameAck, f.streamID, f.frameID)
	c.srv.answer(c.srv.ctx, ack, f.payload, c.maxFrame, peerAddr(c.nc))
	if err := c.write(ack.finish()); err != nil {
		c.srv.logger.LogAttrs(c.srv.ctx, slog.LevelError, "spoe: writing an ACK", slog.Any("error", err))
	}
}

// answer inspects the request of a NOTIFY payload and adds the verdict's
// variables to ack.
func (s *Server) answer(ctx context.Context, ack *encoder, payload []byte, maxFrame uint32, peer netip.Addr) {
	req, path, err := s.toRequest(payload, maxFrame)
	if err != nil {
		s.metrics.AdapterError(telemetry.ErrInvalidRequest)
		id := httpadapter.NewRequestID()
		s.logger.LogAttrs(ctx, slog.LevelError, "invalid spoe message", slog.Any("error", err), slog.String("peer", addrString(peer)), slog.String("request_id", id))
		setVerdict(ack, ActionDeny, http.StatusBadRequest, id)
		return
	}
	if s.answerProbe(ack, req) {
		return
	}
	v := s.pipeline.Check(ctx, req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, s.logger, s.events, req, path, v)
	}
	if v.Action == pipeline.ActionDeny {
		setVerdict(ack, ActionDeny, v.Status, req.ID)
		if g := httpadapter.GRPCOf(req.Headers); g != httpadapter.NotGRPC {
			setGRPCDenial(ack, g, v.Status, req.ID)
		}
		return
	}
	setVerdict(ack, ActionAllow, 0, req.ID)
}

// answerProbe answers the operator's probe, uninspected, and reports
// whether req is one: its X-Inkwall-Probe header has a valid MAC of its
// host and URI under the probe key. It is denied too, so that rules without the
// probe's return rule don't pass it on to the app.
func (s *Server) answerProbe(ack *encoder, req *request.Request) bool {
	header := req.Headers.Get(haproxyprobe.Header)
	if s.probeKey == nil || header == "" {
		return false
	}
	answer, ok := haproxyprobe.Check(s.probeKey(), req.RawURI, req.Host, header)
	if !ok {
		return false
	}
	setVerdict(ack, ActionDeny, http.StatusForbidden, req.ID)
	ack.setVar(VarProbe, func(e *encoder) { e.str(answer) })
	return true
}

// setVerdict adds the verdict's variables. Status is set only to deny.
func setVerdict(ack *encoder, action string, status int, id string) {
	ack.setVar(VarAction, func(e *encoder) { e.str(action) })
	if status != 0 {
		ack.setVar(VarStatus, func(e *encoder) { e.int32(int32(status)) }) // #nosec G115 -- an HTTP status
	}
	ack.setVar(VarRequestID, func(e *encoder) { e.str(id) })
}

// setGRPCDenial adds the variables HAProxy answers a denied gRPC call
// with: HTTP 200 and the gRPC status in the headers (trailers-only), which
// gRPC and gRPC-Web clients read.
func setGRPCDenial(ack *encoder, g httpadapter.GRPCProtocol, status int, id string) {
	ack.setVar(VarGRPCStatus, func(e *encoder) { e.int32(int32(httpadapter.GRPCCode(status))) }) // #nosec G115 -- a gRPC code
	ack.setVar(VarGRPCMessage, func(e *encoder) { e.str(httpadapter.GRPCMessage(status, id)) })
	ack.setVar(VarGRPCContentType, func(e *encoder) { e.str(g.ContentType()) })
}

// args are the arguments of the agent's message.
type args struct {
	method, path, version string
	headers               []byte
	body                  []byte
	hasBody               bool
	ip                    netip.Addr
	https                 bool
}

// readArgs finds the agent's message in a NOTIFY payload and reads its
// arguments.
func readArgs(payload []byte) (args, error) {
	d := decoder{b: payload}
	msgs, err := d.messages()
	if err != nil {
		return args{}, fmt.Errorf("NOTIFY payload: %w", err)
	}
	var (
		a     args
		found bool
	)
	seen := map[string]bool{}
	for _, m := range msgs {
		if m.name != MessageName {
			continue
		}
		if found {
			return args{}, fmt.Errorf("message %s sent twice", MessageName)
		}
		found = true
		for _, arg := range m.args {
			if seen[arg.name] {
				return args{}, fmt.Errorf("argument %s sent twice", arg.name)
			}
			seen[arg.name] = true
			v := arg.val
			switch arg.name {
			case ArgMethod:
				a.method, err = stringArg(arg)
			case ArgPath:
				a.path, err = stringArg(arg)
			case ArgVersion:
				a.version, err = stringArg(arg)
			case ArgHeaders:
				if v.typ != typeBinary && v.typ != typeString {
					err = fmt.Errorf("argument %s: type %d, want binary", arg.name, v.typ)
				}
				a.headers = v.data
			case ArgBody:
				switch v.typ {
				case typeNull:
				case typeBinary, typeString:
					a.body, a.hasBody = v.data, true
				default:
					err = fmt.Errorf("argument %s: type %d, want binary", arg.name, v.typ)
				}
			case ArgIP:
				switch v.typ {
				case typeIPv4, typeIPv6:
					a.ip = v.ip.Unmap()
				case typeNull:
					// A client on a Unix socket has no address.
				default:
					err = fmt.Errorf("argument %s: type %d, want an address", arg.name, v.typ)
				}
			case ArgHTTPS:
				switch v.typ {
				case typeBool:
					a.https = v.b
				case typeNull:
				default:
					err = fmt.Errorf("argument %s: type %d, want a boolean", arg.name, v.typ)
				}
			}
			if err != nil {
				return args{}, err
			}
		}
	}
	if !found {
		return args{}, fmt.Errorf("no message %s", MessageName)
	}
	for _, name := range []string{ArgMethod, ArgPath, ArgHeaders} {
		if !seen[name] {
			return args{}, fmt.Errorf("argument %s missing", name)
		}
	}
	return a, nil
}

func stringArg(arg kv) (string, error) {
	if arg.val.typ != typeString {
		return "", fmt.Errorf("argument %s: type %d, want a string", arg.name, arg.val.typ)
	}
	return string(arg.val.data), nil
}

// toRequest reconstructs the client's request from a NOTIFY payload. It
// also returns the decoded path for logging.
func (s *Server) toRequest(payload []byte, maxFrame uint32) (*request.Request, string, error) {
	a, err := readArgs(payload)
	if err != nil {
		return nil, "", err
	}
	if !httpadapter.IsToken(a.method) {
		return nil, "", errors.New("invalid method")
	}
	path, err := httpadapter.URIPath(a.path)
	if err != nil {
		return nil, "", fmt.Errorf("path: %w", err)
	}
	proto, err := protoName(a.version)
	if err != nil {
		return nil, "", err
	}
	headers, host, err := parseHeaders(a.headers)
	if err != nil {
		return nil, "", fmt.Errorf("headers: %w", err)
	}
	scheme := "http"
	if a.https {
		scheme = "https"
	}
	id := httpadapter.RequestID(headers.Get("X-Request-Id"))
	if id == "" {
		id = httpadapter.NewRequestID()
	}
	req := &request.Request{
		ID:       id,
		Proto:    proto,
		Method:   a.method,
		Scheme:   scheme,
		Host:     host,
		RawURI:   a.path,
		Headers:  headers,
		PeerIP:   a.ip,
		ClientIP: s.clientIP.Resolve(a.ip, headers),
	}
	contentLength, hasLength, err := bodyLength(headers)
	if err != nil {
		return nil, "", err
	}
	te := headers.Get("Transfer-Encoding") != ""
	if te && hasLength {
		// HAProxy drops Content-Length from a chunked request.
		return nil, "", errors.New("both Transfer-Encoding and Content-Length")
	}
	if !te && (!hasLength || contentLength == 0) && len(a.body) == 0 {
		// No body. Clients send "Content-Length: 0" for an empty POST, PUT
		// or PATCH, but HTTP/2 clients may not; without it, rule 920180
		// (POST without Content-Length) scores every empty POST.
		if !hasLength && (a.method == http.MethodPost || a.method == http.MethodPut || a.method == http.MethodPatch) {
			headers.Set("Content-Length", "0")
		}
		return req, path, nil
	}
	limit := s.pipeline.BodyLimit(req, s.maxBody)
	if limit <= 0 {
		return req, path, nil
	}
	n := int64(len(a.body))
	var complete bool
	switch {
	case !a.hasBody:
		// HAProxy didn't send the body: it goes uninspected.
	case hasLength:
		complete = n == contentLength
	default:
		complete = uncut(len(payload), len(headers), len(host), maxFrame)
	}
	if complete && !hasLength && !te {
		// As in SnapshotHeaders, rules must not see a body without either
		// header.
		headers.Set("Content-Length", strconv.FormatInt(n, 10))
	}
	req.Body = a.body[:min(n, limit)]
	req.BodyTruncated = n > limit || !complete
	return req, path, nil
}

// uncut reports whether a frame of size bytes carries a body HAProxy
// didn't cut, for a request with n headers and the authority host: a body
// without Content-Length, which only the size tells. HAProxy stops
// buffering a body when its buffer (tune.bufsize, 4 bytes more than the
// maximum frame size by default) is full but for tune.maxrewrite, which is
// at most half of it: the request then takes at least half the buffer. In
// the buffer, the request has 8 bytes per header and other block that the
// frame doesn't (the frame spends more than that on lengths and argument
// names), and an HTTP/2 request has its authority in the URI, which pathq
// leaves out. A frame clearly under half the maximum size couldn't have
// filled the buffer.
func uncut(size, n, host int, maxFrame uint32) bool {
	slack := 1024 + 16*n + host
	return size+slack < int(maxFrame/2)
}

// bodyLength returns the request's Content-Length, and whether it has one.
// Several different values, or an invalid one, can't be inspected.
func bodyLength(h http.Header) (int64, bool, error) {
	vs := h.Values("Content-Length")
	if len(vs) == 0 {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(vs[0], 10, 64)
	if err != nil || n < 0 {
		return 0, false, errors.New("invalid Content-Length")
	}
	for _, v := range vs[1:] {
		if v != vs[0] {
			return 0, false, errors.New("several Content-Length values")
		}
	}
	return n, true, nil
}

// protoName turns req.ver ("1.1", "2.0") into a protocol name. HAProxy
// sends "2.0" for HTTP/2; an empty version is HTTP/1.1.
func protoName(v string) (string, error) {
	if v == "" {
		return "HTTP/1.1", nil
	}
	major, minor, ok := strings.Cut(v, ".")
	if !ok || len(major) != 1 || len(minor) != 1 || major[0] < '0' || major[0] > '9' || minor[0] < '0' || minor[0] > '9' {
		return "", errors.New("invalid version")
	}
	return "HTTP/" + v, nil
}

// parseHeaders decodes req.hdrs_bin: a name and a value per header, each a
// varint length and bytes, until an empty name and value. The Host header
// is returned apart, as in request.Request.
func parseHeaders(b []byte) (http.Header, string, error) {
	d := decoder{b: b}
	h := http.Header{}
	var (
		host     string
		haveHost bool
	)
	for {
		name, err := d.bytes()
		if err != nil {
			return nil, "", err
		}
		val, err := d.bytes()
		if err != nil {
			return nil, "", err
		}
		if len(name) == 0 {
			if len(val) != 0 {
				return nil, "", errors.New("a value without a name")
			}
			break
		}
		if !httpadapter.IsToken(string(name)) {
			return nil, "", errors.New("invalid header name")
		}
		if !httpguts.ValidHeaderFieldValue(string(val)) {
			return nil, "", fmt.Errorf("invalid value of header %q", name)
		}
		if strings.EqualFold(string(name), "Host") {
			if haveHost {
				return nil, "", errors.New("several Host headers")
			}
			host, haveHost = string(val), true
			continue
		}
		h.Add(string(name), string(val))
	}
	if !d.empty() {
		return nil, "", errors.New("data after the end of the headers")
	}
	// HAProxy forwards the Host it received; inspect only a valid one, as
	// the reverse proxy does.
	if !httpguts.ValidHostHeader(host) {
		return nil, "", errors.New("invalid Host")
	}
	return h, host, nil
}

// loopback is the address of a Unix-socket peer: a process on the same
// host, like a loopback one.
var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// peerAddr returns the address of HAProxy, the connection's peer.
func peerAddr(nc net.Conn) netip.Addr {
	switch a := nc.RemoteAddr().(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.UnixAddr:
		return loopback
	}
	return netip.Addr{}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
