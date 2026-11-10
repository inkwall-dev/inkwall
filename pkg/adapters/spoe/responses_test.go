// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"context"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqlError = "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax</body></html>"

// responseFrame builds a NOTIFY with the response message and the given
// arguments, as the inkwall-response group sends it.
func responseFrame(streamID, frameID uint64, args ...func(*encoder)) []byte {
	e := newFrame(frameNotify, streamID, frameID)
	e.bytes(ResponseMessageName)
	e.b = append(e.b, byte(len(args)))
	for _, a := range args {
		a(e)
	}
	return e.finish()
}

func argInt(name string, v int32) func(*encoder) {
	return func(e *encoder) {
		e.bytes(name)
		e.int32(v)
	}
}

// response returns the arguments of a response to the request whose
// answer set key and failure, with a body.
func response(key, failure string, status int32, contentType, body string) []func(*encoder) {
	return []func(*encoder){
		argInt(ArgStatus, status),
		argBinary(ArgHeaders, hdrs("content-type", contentType, "content-length", strconv.Itoa(len(body)))),
		argBinary(ArgBody, []byte(body)),
		argString(ArgKey, key),
		argString(ArgFailure, failure),
	}
}

// responsePipeline returns a pipeline with the Core Rule Set that inspects
// responses, up to 1 KiB of their bodies.
func responsePipeline(t *testing.T, mode pipeline.Mode) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{ResponseBodyLimit: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 1 << 10}})
}

var keyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// request sends a benign GET and returns the answer's variables.
func (h *haproxy) request(frameID uint64, path string) map[string]value {
	h.t.Helper()
	h.send(notifyFrame(1, frameID, argString(ArgMethod, "GET"), argString(ArgPath, path),
		argBinary(ArgHeaders, hdrs("host", "a.example", "user-agent", "test/1.0", "accept", "*/*"))))
	_, vars := h.ack()
	return vars
}

// respond sends a response and returns the answer's variables.
func (h *haproxy) respond(frameID uint64, args ...func(*encoder)) map[string]value {
	h.t.Helper()
	h.send(responseFrame(1, frameID, args...))
	_, vars := h.ack()
	return vars
}

// In block mode, a response that leaks a SQL error is denied with 403, a
// benign one allowed; each request's answer says its response is to be
// inspected, with a key of its own and the policy's failure mode.
func TestResponseBlock(t *testing.T) {
	var logs syncBuilder
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: 1 << 10, Responses: true,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	h := a.dial(t)
	h.hello()

	leak := h.request(1, "/products?id=42")
	key := leak[VarResponses].String()
	if leak[VarAction].String() != ActionAllow || !keyPattern.MatchString(key) || leak[VarResponseFailure].String() != FailureClosed {
		t.Fatalf("request's variables %+v", leak)
	}
	benign := h.request(2, "/products?id=43")
	if benign[VarResponses].String() == key {
		t.Fatal("two requests share a key")
	}

	vars := h.respond(3, response(key, FailureClosed, 200, "text/html", sqlError)...)
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 403 {
		t.Errorf("leaking response: %+v", vars)
	}
	vars = h.respond(4, response(benign[VarResponses].String(), FailureClosed, 200, "text/html", "<html>hello</html>")...)
	if vars[VarResponseAction].String() != ActionAllow {
		t.Errorf("benign response: %+v", vars)
	}
	if _, ok := vars[VarResponseStatus]; ok {
		t.Errorf("benign response has a status: %+v", vars)
	}
	if !strings.Contains(logs.String(), `"phase":"response"`) || !strings.Contains(logs.String(), `"request_id":"`+leak[VarRequestID].String()+`"`) {
		t.Errorf("the leak isn't logged with its request ID: %s", logs.String())
	}

	// A key is used once: the same response again is a miss, which fails
	// closed with 502.
	vars = h.respond(5, response(key, FailureClosed, 200, "text/html", "<html>hello</html>")...)
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 502 {
		t.Errorf("miss: %+v", vars)
	}
	if n := a.srv.pending.len(); n != 0 {
		t.Errorf("%d states left", n)
	}
}

// In detect mode, a leaking response passes and is logged.
func TestResponseDetect(t *testing.T) {
	var logs syncBuilder
	a := startAgent(t, responsePipeline(t, pipeline.ModeDetect), Config{Responses: true, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	h := a.dial(t)
	h.hello()
	req := h.request(1, "/")
	if req[VarResponseFailure].String() != FailureOpen {
		t.Errorf("detect mode fails open: %+v", req)
	}
	vars := h.respond(2, response(req[VarResponses].String(), FailureOpen, 200, "text/html", sqlError)...)
	if vars[VarResponseAction].String() != ActionAllow {
		t.Errorf("detect mode: %+v", vars)
	}
	if !strings.Contains(logs.String(), `"action":"log"`) || !strings.Contains(logs.String(), `"phase":"response"`) {
		t.Errorf("the leak isn't logged: %s", logs.String())
	}
}

// A response whose request the agent doesn't hold gets the failure mode
// HAProxy sent back: open passes, closed (or none) gets 502.
func TestResponseMiss(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true})
	h := a.dial(t)
	h.hello()
	unknown := strings.Repeat("ab", 16)
	for i, c := range []struct {
		failure string
		action  string
		status  uint64
	}{
		{FailureOpen, ActionAllow, 0},
		{FailureClosed, ActionDeny, 502},
		{"", ActionDeny, 502},
		{"sideways", ActionDeny, 502},
	} {
		args := response(unknown, c.failure, 200, "text/html", "<html>hello</html>")
		if c.failure == "" {
			args = args[:4]
		}
		vars := h.respond(uint64(i+1), args...)
		if vars[VarResponseAction].String() != c.action || vars[VarResponseStatus].u != c.status {
			t.Errorf("failure %q: %+v", c.failure, vars)
		}
	}
}

// A response message HAProxy shouldn't send (no key, headers that don't
// parse) is denied with 502, and its request's state is released.
func TestResponseUnreadable(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true})
	h := a.dial(t)
	h.hello()
	key := h.request(1, "/")[VarResponses].String()
	vars := h.respond(2, argInt(ArgStatus, 200), argBinary(ArgHeaders, []byte{3, 'a'}), argString(ArgKey, key), argString(ArgFailure, FailureOpen))
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 502 {
		t.Errorf("unreadable headers: %+v", vars)
	}
	vars = h.respond(3, argInt(ArgStatus, 200), argBinary(ArgHeaders, hdrs()))
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 502 {
		t.Errorf("no key: %+v", vars)
	}
	if n := a.srv.pending.len(); n != 0 {
		t.Errorf("%d states left", n)
	}
}

// A body HAProxy cut (shorter than its Content-Length) is inspected as a
// prefix, and oversized: 502 in block mode. A body the rules don't read
// (an image) isn't inspected, nor counted as oversized.
func TestResponseBody(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true})
	h := a.dial(t)
	h.hello()
	key := h.request(1, "/")[VarResponses].String()
	vars := h.respond(2, argInt(ArgStatus, 200), argBinary(ArgHeaders, hdrs("content-type", "text/html", "content-length", "20000")),
		argBinary(ArgBody, []byte("<html>hello")), argString(ArgKey, key), argString(ArgFailure, FailureClosed))
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 502 {
		t.Errorf("cut body: %+v", vars)
	}
	key = h.request(3, "/")[VarResponses].String()
	vars = h.respond(4, response(key, FailureClosed, 200, "image/png", sqlError)...)
	if vars[VarResponseAction].String() != ActionAllow {
		t.Errorf("image: %+v", vars)
	}
}

// The table is bounded: past its entries, a request whose response is to
// be inspected gets the failure mode (503 in block mode), as an overload,
// and keeps nothing.
func TestResponseTableFull(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true, MaxPendingResponses: 1})
	h := a.dial(t)
	h.hello()
	first := h.request(1, "/")
	if !keyPattern.MatchString(first[VarResponses].String()) {
		t.Fatalf("first request: %+v", first)
	}
	vars := h.request(2, "/")
	if vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 503 {
		t.Errorf("table full: %+v", vars)
	}
	if has(vars, VarResponses) {
		t.Errorf("table full, and a key: %+v", vars)
	}
	// The first response frees its entry.
	h.respond(3, response(first[VarResponses].String(), FailureClosed, 200, "text/html", "ok")...)
	if vars := h.request(4, "/"); vars[VarAction].String() != ActionAllow {
		t.Errorf("after the response: %+v", vars)
	}
}

// The table is bounded by memory as well: a request larger than the bound
// keeps nothing.
func TestResponseTableBytes(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true, MaxPendingResponseBytes: 1 << 10})
	h := a.dial(t)
	h.hello()
	if vars := h.request(1, "/"); vars[VarAction].String() != ActionDeny || vars[VarStatus].u != 503 {
		t.Errorf("over the memory bound: %+v", vars)
	}
}

// A state expires at its TTL: its response is then a miss.
func TestResponseTTL(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true, ResponseTTL: time.Hour})
	var mu sync.Mutex
	now := time.Now()
	a.srv.pending.mu.Lock()
	a.srv.pending.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	a.srv.pending.mu.Unlock()
	h := a.dial(t)
	h.hello()
	key := h.request(1, "/")[VarResponses].String()
	mu.Lock()
	now = now.Add(time.Hour + time.Second)
	mu.Unlock()
	// A new request sweeps the expired one.
	h.request(2, "/")
	if n := a.srv.pending.len(); n != 1 {
		t.Errorf("%d states, want 1", n)
	}
	vars := h.respond(3, response(key, FailureClosed, 200, "text/html", "ok")...)
	if vars[VarResponseAction].String() != ActionDeny || vars[VarResponseStatus].u != 502 {
		t.Errorf("expired: %+v", vars)
	}
}

// Without Responses, the agent keeps nothing, whatever the policy says:
// HAProxy isn't configured to send the responses (the operator's wiring
// before #470).
func TestResponsesOff(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{})
	h := a.dial(t)
	h.hello()
	vars := h.request(1, "/")
	if has(vars, VarResponses) || vars[VarAction].String() != ActionAllow {
		t.Errorf("variables %+v", vars)
	}
	if n := a.srv.pending.len(); n != 0 {
		t.Errorf("%d states kept", n)
	}
}

// A request whose policy doesn't inspect responses, or that is denied,
// keeps nothing, and its answer has no key.
func TestResponsesNotInspected(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
	a := startAgent(t, p, Config{Responses: true})
	h := a.dial(t)
	h.hello()
	if vars := h.request(1, "/"); vars[VarAction].String() != ActionAllow || has(vars, VarResponses) {
		t.Errorf("variables %+v", vars)
	}
	b := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true})
	h = b.dial(t)
	h.hello()
	vars := h.request(1, "/products?id=1%27%20OR%20%271%27%3D%271")
	if has(vars, VarResponses) || vars[VarAction].String() != ActionDeny {
		t.Errorf("denied: %+v", vars)
	}
	if n := b.srv.pending.len(); n != 0 {
		t.Errorf("%d states kept", n)
	}
}

// Shutdown releases the states left.
func TestResponseShutdown(t *testing.T) {
	a := startAgent(t, responsePipeline(t, pipeline.ModeBlock), Config{Responses: true})
	h := a.dial(t)
	h.hello()
	h.request(1, "/")
	_ = h.nc.Close()
	shutdown(t, a)
	if n := a.srv.pending.len(); n != 0 {
		t.Errorf("%d states left after Shutdown", n)
	}
}

func TestNewResponseConfig(t *testing.T) {
	for _, cfg := range []Config{
		{Responses: true, MaxPendingResponses: -1},
		{Responses: true, MaxPendingResponseBytes: -1},
		{Responses: true, ResponseTTL: -time.Second},
	} {
		if _, err := New(&inspector{}, cfg); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
}

func has(vars map[string]value, name string) bool {
	_, ok := vars[name]
	return ok
}

// shutdown stops the agent; the test's cleanup does again, which is fine.
func shutdown(t *testing.T, a *agent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

// syncBuilder is a strings.Builder safe for the agent's goroutines.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
