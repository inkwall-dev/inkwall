// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// Responses (docs/design/0006 §4, "Responses through SPOE").
//
// With Config.Responses, a request whose policy inspects responses keeps
// its inspection (pipeline.Exchange) in a table, under a key of the
// agent's own, and its answer sets VarResponses to the key and
// VarResponseFailure to the policy's failure mode. HAProxy's rules send
// the message ResponseMessageName for the responses of those requests
// only, with the key and the failure mode back: the agent takes the state
// out of the table, inspects the response with it and answers with
// VarResponseAction and VarResponseStatus.
//
// The key is not the request ID, which a client may choose: two requests
// with one ID would swap their states, and so their policies.
//
// The table is bounded by entries, by an estimate of their memory and by a
// TTL. A request whose state doesn't fit gets the policy's failure mode as
// an overload (503 in block mode by default): its response would go
// uninspected otherwise. A response whose state isn't there (expired, an
// engine restarted in between) is a miss: it gets the failure mode HAProxy
// sent back, 502 when it fails closed.

// ResponseMessageName is the spoe-message describing a response.
const ResponseMessageName = "inkwall-response"

// Arguments of ResponseMessageName, besides ArgHeaders (res.hdrs_bin) and
// ArgBody (res.body).
const (
	// ArgStatus is the response's status (status).
	ArgStatus = "status"
	// ArgKey is the request's VarResponses.
	ArgKey = "key"
	// ArgFailure is the request's VarResponseFailure.
	ArgFailure = "failure"
)

// Variables of responses, in the transaction scope.
const (
	// VarResponses is set on a request's answer when its response is to
	// be inspected: the key its response message sends back.
	VarResponses = "responses"
	// VarResponseFailure is set with VarResponses: FailureOpen or
	// FailureClosed, what a response without an answer gets.
	VarResponseFailure = "response_failure"
	// VarResponseAction is ActionAllow or ActionDeny, on every answer to
	// a response message.
	VarResponseAction = "response_action"
	// VarResponseStatus is the status to replace a denied response with:
	// 403 for a leak, 502 for a body that couldn't be inspected or a
	// response the agent can't inspect, 503 when inspecting it failed.
	VarResponseStatus = "response_status"
)

// Values of VarResponseFailure.
const (
	FailureOpen   = "open"
	FailureClosed = "closed"
)

// Bounds of the table, by default.
const (
	DefaultMaxPendingResponses     = 4096
	DefaultMaxPendingResponseBytes = 64 << 20
	// DefaultResponseTTL is above HAProxy's usual timeout server (30s in
	// examples/haproxy, 50s in the HAProxy Kubernetes Ingress Controller):
	// a state must outlive the slowest response it waits for.
	DefaultResponseTTL = time.Minute
)

// The estimate of a state's memory: a kept Coraza transaction with the
// Core Rule Set holds about 77 KiB for a GET with a few headers, and about
// 5 bytes more per byte of an urlencoded body (124 KiB at 1 KiB, 198 KiB
// at 16 KiB, 454 KiB at 64 KiB), measured with runtime.MemStats. The
// estimate is above each.
const (
	stateBaseCost = 128 << 10
	stateBodyCost = 6
	stateHdrCost  = 2
)

// stateCost estimates the memory of r's kept inspection.
func stateCost(r *request.Request) int64 {
	n := int64(len(r.RawURI) + len(r.Host))
	for k, vs := range r.Headers {
		for _, v := range vs {
			n += int64(len(k) + len(v))
		}
	}
	return stateBaseCost + stateBodyCost*int64(len(r.Body)) + stateHdrCost*n
}

// state is a request kept for its response.
type state struct {
	key     string
	x       *pipeline.Exchange
	req     *request.Request
	path    string
	cost    int64
	expires time.Time
	elem    *list.Element
}

// pendingTable holds the states, bounded by entries, bytes and a TTL.
// Expired states are swept on each add and take, oldest first: the TTL is
// the same for all, so the list is in expiry order.
type pendingTable struct {
	maxEntries int
	maxBytes   int64
	ttl        time.Duration

	mu sync.Mutex
	// now is the clock, under mu (tests change it).
	now     func() time.Time
	entries map[string]*state
	order   *list.List
	bytes   int64

	outcomes *prometheus.CounterVec
}

func newPendingTable(maxEntries int, maxBytes int64, ttl time.Duration) *pendingTable {
	return &pendingTable{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ttl:        ttl,
		now:        time.Now,
		entries:    map[string]*state{},
		order:      list.New(),
	}
}

// Outcomes of inkwall_spoe_response_states_total.
const (
	outcomeKept     = "kept"
	outcomeFull     = "full"
	outcomeAnswered = "answered"
	outcomeExpired  = "expired"
	outcomeMiss     = "miss"
)

func (t *pendingTable) count(outcome string, n int) {
	if t.outcomes != nil && n > 0 {
		t.outcomes.WithLabelValues(outcome).Add(float64(n))
	}
}

// register exports the table's size and outcomes.
func (t *pendingTable) register(m *telemetry.Metrics) {
	t.outcomes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_spoe_response_states_total",
		Help: "Requests kept for their responses through SPOE, by outcome: kept, full (refused: the table is full), answered, expired (at the TTL), miss (a response whose request wasn't kept).",
	}, []string{"outcome"})
	for _, o := range []string{outcomeKept, outcomeFull, outcomeAnswered, outcomeExpired, outcomeMiss} {
		t.outcomes.WithLabelValues(o)
	}
	m.Register(t.outcomes,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_spoe_response_states",
			Help: "Requests kept for their responses through SPOE now.",
		}, func() float64 { return float64(t.len()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "inkwall_spoe_response_state_bytes",
			Help: "Estimated memory of the requests kept for their responses through SPOE.",
		}, func() float64 {
			t.mu.Lock()
			defer t.mu.Unlock()
			return float64(t.bytes)
		}),
	)
}

// len returns the number of states; 0 on a nil table.
func (t *pendingTable) len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// add keeps s under a new key, unless the table is full: it reports
// whether it did. The caller closes s.x when it didn't.
func (t *pendingTable) add(s *state) bool {
	t.mu.Lock()
	now := t.now()
	expired := t.sweepLocked(now)
	ok := len(t.entries) < t.maxEntries && t.bytes+s.cost <= t.maxBytes
	if ok {
		s.key = newKey()
		s.expires = now.Add(t.ttl)
		s.elem = t.order.PushBack(s)
		t.entries[s.key] = s
		t.bytes += s.cost
	}
	t.mu.Unlock()
	closeStates(expired)
	t.count(outcomeExpired, len(expired))
	if ok {
		t.count(outcomeKept, 1)
	} else {
		t.count(outcomeFull, 1)
	}
	return ok
}

// take removes and returns the state under key, or nil: the caller closes
// its exchange.
func (t *pendingTable) take(key string) *state {
	t.mu.Lock()
	expired := t.sweepLocked(t.now())
	s := t.entries[key]
	if s != nil {
		t.removeLocked(s)
	}
	t.mu.Unlock()
	closeStates(expired)
	t.count(outcomeExpired, len(expired))
	if s != nil {
		t.count(outcomeAnswered, 1)
	} else {
		t.count(outcomeMiss, 1)
	}
	return s
}

func (t *pendingTable) removeLocked(s *state) {
	delete(t.entries, s.key)
	t.order.Remove(s.elem)
	t.bytes -= s.cost
}

// sweepLocked removes the states expired at now, which the caller closes
// without the lock.
func (t *pendingTable) sweepLocked(now time.Time) []*state {
	var expired []*state
	for e := t.order.Front(); e != nil; e = t.order.Front() {
		s := e.Value.(*state) //nolint:forcetypeassert // only states are pushed
		if now.Before(s.expires) {
			break
		}
		t.removeLocked(s)
		expired = append(expired, s)
	}
	return expired
}

// closeAll releases every state, at Shutdown.
func (t *pendingTable) closeAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	var all []*state
	for _, s := range t.entries {
		all = append(all, s)
	}
	t.entries = map[string]*state{}
	t.order.Init()
	t.bytes = 0
	t.mu.Unlock()
	closeStates(all)
}

func closeStates(states []*state) {
	for _, s := range states {
		s.x.Close()
	}
}

// newKey returns a key no client can guess: 128 random bits.
func newKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b[:])
}

// keep keeps the exchange of req, let through with v, for its response,
// and adds the response's variables to ack. When the table is full, it
// returns the verdict of the policy's failure mode for an overload
// instead, and keeps nothing.
func (s *Server) keep(ctx context.Context, ack *encoder, x *pipeline.Exchange, req *request.Request, path string, v pipeline.Verdict) pipeline.Verdict {
	failure := x.FailureMode()
	kept := *req
	kept.Body = nil // the transaction has it
	st := &state{x: x, req: &kept, path: path, cost: stateCost(req)}
	if !s.pending.add(st) {
		x.Close()
		s.logger.LogAttrs(ctx, slog.LevelWarn, "spoe: too many responses pending, the request gets the failure mode",
			slog.String("request_id", req.ID), slog.Int("max_entries", s.pending.maxEntries), slog.Int64("max_bytes", s.pending.maxBytes))
		over := pipeline.Verdict{Action: pipeline.ActionAllow, Reason: pipeline.ReasonOverload, Policy: v.Policy}
		if failure == pipeline.FailClosed {
			over.Action, over.Status = pipeline.ActionDeny, http.StatusServiceUnavailable
		}
		return over
	}
	ack.setVar(VarResponses, func(e *encoder) { e.str(st.key) })
	f := FailureOpen
	if failure == pipeline.FailClosed {
		f = FailureClosed
	}
	ack.setVar(VarResponseFailure, func(e *encoder) { e.str(f) })
	return v
}

// responseArgs are the arguments of the response message.
type responseArgs struct {
	status  int
	headers []byte
	body    []byte
	hasBody bool
	key     string
	failure string
}

// isResponse reports whether a NOTIFY payload carries the response message
// and not the request's.
func isResponse(msgs []message) bool {
	var resp, req bool
	for _, m := range msgs {
		switch m.name {
		case ResponseMessageName:
			resp = true
		case MessageName:
			req = true
		}
	}
	return resp && !req
}

// readResponseArgs reads the response message's arguments. The key and
// the failure mode are read first, so that a message otherwise unreadable
// still releases its state and gets its failure mode.
func readResponseArgs(msgs []message) (responseArgs, error) {
	var (
		a     responseArgs
		found bool
		err   error
	)
	seen := map[string]bool{}
	for _, m := range msgs {
		if m.name != ResponseMessageName {
			continue
		}
		if found {
			return a, fmt.Errorf("message %s sent twice", ResponseMessageName)
		}
		found = true
		for _, arg := range m.args {
			if seen[arg.name] {
				return a, fmt.Errorf("argument %s sent twice", arg.name)
			}
			seen[arg.name] = true
			switch arg.name {
			case ArgKey:
				a.key, err = optionalString(arg)
			case ArgFailure:
				a.failure, err = optionalString(arg)
			}
			if err != nil {
				return a, err
			}
		}
		for _, arg := range m.args {
			v := arg.val
			switch arg.name {
			case ArgStatus:
				switch v.typ {
				case typeInt32, typeUint32, typeInt64, typeUint64:
					if v.u < 100 || v.u > 999 {
						err = fmt.Errorf("argument %s: %d is not a status", arg.name, v.u)
					}
					a.status = int(v.u) // #nosec G115 -- bounded above
				default:
					err = fmt.Errorf("argument %s: type %d, want an integer", arg.name, v.typ)
				}
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
			}
			if err != nil {
				return a, err
			}
		}
	}
	if !found {
		return a, fmt.Errorf("no message %s", ResponseMessageName)
	}
	for _, name := range []string{ArgStatus, ArgHeaders, ArgKey} {
		if !seen[name] {
			return a, fmt.Errorf("argument %s missing", name)
		}
	}
	return a, nil
}

// optionalString reads a string argument; an unset variable is null.
func optionalString(arg kv) (string, error) {
	if arg.val.typ == typeNull {
		return "", nil
	}
	return stringArg(arg)
}

// toResponse builds the response to req from its message's arguments, with
// the body x inspects, cut at its limit. A body HAProxy cut (shorter than
// its Content-Length; or, without one, in a frame that may have filled
// HAProxy's buffer) is truncated, and one it didn't send uninspected.
func toResponse(a responseArgs, req *request.Request, x *pipeline.Exchange, size int, maxFrame uint32) (*request.Response, error) {
	headers, err := parseResponseHeaders(a.headers)
	if err != nil {
		return nil, fmt.Errorf("headers: %w", err)
	}
	resp := &request.Response{Status: a.status, Proto: req.Proto, Headers: headers}
	if !x.WantsBody(headers.Get("Content-Type")) || !hasResponseBody(req.Method, a.status, headers) {
		return resp, nil
	}
	if !a.hasBody {
		resp.BodyUninspected = true
		return resp, nil
	}
	length, hasLength, err := bodyLength(headers)
	if err != nil {
		return nil, err
	}
	n := int64(len(a.body))
	complete := n == length
	if !hasLength || headers.Get("Transfer-Encoding") != "" {
		complete = uncut(size, len(headers), 0, maxFrame)
	}
	limit := x.BodyLimit()
	resp.Body = a.body[:min(n, limit)]
	resp.BodyTruncated = n > limit || !complete
	return resp, nil
}

// hasResponseBody reports whether a response may have a body: not one to
// HEAD, a 1xx, 204 or 304, or with Content-Length 0.
func hasResponseBody(method string, status int, h http.Header) bool {
	if method == http.MethodHead || status < 200 || status == http.StatusNoContent || status == http.StatusNotModified {
		return false
	}
	return h.Get("Content-Length") != "0"
}

// parseResponseHeaders decodes res.hdrs_bin, as parseHeaders does a
// request's, without a Host.
func parseResponseHeaders(b []byte) (http.Header, error) {
	d := decoder{b: b}
	h := http.Header{}
	for {
		name, err := d.bytes()
		if err != nil {
			return nil, err
		}
		val, err := d.bytes()
		if err != nil {
			return nil, err
		}
		if len(name) == 0 {
			if len(val) != 0 {
				return nil, errors.New("a value without a name")
			}
			break
		}
		if !httpadapter.IsToken(string(name)) {
			return nil, errors.New("invalid header name")
		}
		if !httpguts.ValidHeaderFieldValue(string(val)) {
			return nil, fmt.Errorf("invalid value of header %q", name)
		}
		h.Add(string(name), string(val))
	}
	if !d.empty() {
		return nil, errors.New("data after the end of the headers")
	}
	return h, nil
}

// answerResponse inspects the response of a NOTIFY payload and adds the
// verdict's variables to ack.
func (s *Server) answerResponse(ctx context.Context, ack *encoder, msgs []message, size int, maxFrame uint32) {
	a, err := readResponseArgs(msgs)
	var st *state
	if a.key != "" && s.pending != nil {
		st = s.pending.take(a.key)
	}
	if err != nil {
		if st != nil {
			st.x.Close()
		}
		s.metrics.AdapterError(telemetry.ErrInvalidRequest)
		s.logger.LogAttrs(ctx, slog.LevelError, "invalid spoe response message", slog.Any("error", err))
		setResponseVerdict(ack, ActionDeny, http.StatusBadGateway)
		return
	}
	if st == nil {
		// A miss: the failure mode HAProxy sent back, closed unless it
		// says open.
		s.logger.LogAttrs(ctx, slog.LevelWarn, "spoe: a response whose request isn't kept (expired, or the engine restarted)",
			slog.String("failure", a.failure))
		if a.failure == FailureOpen {
			setResponseVerdict(ack, ActionAllow, 0)
		} else {
			setResponseVerdict(ack, ActionDeny, http.StatusBadGateway)
		}
		return
	}
	defer st.x.Close()
	resp, err := toResponse(a, st.req, st.x, size, maxFrame)
	if err != nil {
		s.metrics.AdapterError(telemetry.ErrInvalidRequest)
		s.logger.LogAttrs(ctx, slog.LevelError, "invalid spoe response message", slog.Any("error", err), slog.String("request_id", st.req.ID))
		setResponseVerdict(ack, ActionDeny, http.StatusBadGateway)
		return
	}
	v := st.x.CheckResponse(ctx, resp)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(ctx, s.logger, s.events, st.req, st.path, v)
	}
	if v.Action == pipeline.ActionDeny {
		setResponseVerdict(ack, ActionDeny, v.Status)
		return
	}
	setResponseVerdict(ack, ActionAllow, 0)
}

// setResponseVerdict adds a response's verdict. Status is set only to
// deny.
func setResponseVerdict(ack *encoder, action string, status int) {
	ack.setVar(VarResponseAction, func(e *encoder) { e.str(action) })
	if status != 0 {
		ack.setVar(VarResponseStatus, func(e *encoder) { e.int32(int32(status)) }) // #nosec G115 -- an HTTP status
	}
}
