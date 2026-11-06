// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// WebSocketMessages is what the engine's reverse proxy does with the
// messages of a WebSocket it forwards (#276). Only the proxy sees them:
// ext_proc and forward-auth see the handshake alone (docs/design/0002 §6).
type WebSocketMessages int

const (
	// MessagesOff forwards messages uninspected.
	MessagesOff WebSocketMessages = iota
	// MessagesInspect inspects text messages; binary ones pass uninspected.
	MessagesInspect
	// MessagesTextOnly inspects text messages and refuses binary ones,
	// which the rules can't read.
	MessagesTextOnly
)

// The bounds of a JSON message's arguments: past them, its whole text is
// one more argument, so nothing goes uninspected.
const (
	maxMessageArgs  = 1024
	maxMessageDepth = 32
)

// CheckWebSocketMessage inspects the text of a message a client sent on
// the WebSocket that handshake opened, with the policy's rules, on its own
// (#363): as a request whose form arguments are the message
// (request.Request.WebSocketText), with the handshake's identity (request
// ID, client IP, host) and path, for exclusions and path rules, but not its
// query arguments or headers. Those were inspected with the handshake; run
// again, they would add the handshake's score to every message and count
// toward the message's argument limit. A message cut at the body limit
// (truncated) is handled as an oversized body. A route the policy skips,
// or whose body it skips, isn't inspected.
func (p *Pipeline) CheckWebSocketMessage(ctx context.Context, handshake *request.Request, text []byte, truncated bool) Verdict {
	start := time.Now()
	var v Verdict
	if p.routes.Decide(handshake.RawURI) != router.InspectAll {
		v = Verdict{Action: ActionAllow, Reason: ReasonSkipped}
	} else {
		msg := messageRequest(handshake)
		msg.WebSocketText = messageArgs(text)
		// No exchange is kept: a message has no response to inspect.
		if truncated {
			v, _ = p.partly(ctx, &msg, false)
		} else {
			v, _ = p.evaluate(ctx, p.request(&msg, false))
		}
	}
	v.Duration = time.Since(start)
	v.WebSocketMessage = true
	if p.observer != nil {
		p.observer.ObserveVerdict(v)
	}
	return v
}

// messageHeaders are a message's request headers: what a clean request
// has, so the rules on headers (missing Accept, User-Agent...) add nothing.
// The handshake's own headers were inspected with it.
var messageHeaders = http.Header{
	"Accept":     {"*/*"},
	"User-Agent": {"inkwall-websocket-message"},
}

// messageRequest is the request a message of the WebSocket handshake
// opened is evaluated as: GET of the handshake's path, without its query
// or headers.
func messageRequest(handshake *request.Request) request.Request {
	path, _, _ := strings.Cut(handshake.RawURI, "?")
	return request.Request{
		ID:       handshake.ID,
		Proto:    handshake.Proto,
		Method:   http.MethodGet,
		Scheme:   handshake.Scheme,
		Host:     handshake.Host,
		RawURI:   path,
		Headers:  messageHeaders.Clone(),
		PeerIP:   handshake.PeerIP,
		ClientIP: handshake.ClientIP,
	}
}

// messageArgs returns a message's arguments: a JSON object's or array's
// values by path, as Coraza's JSON body processor names them; any other
// text as one argument, "message".
func messageArgs(text []byte) []request.Arg {
	trimmed := bytes.TrimSpace(text)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		d := json.NewDecoder(bytes.NewReader(trimmed))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err == nil && !d.More() {
			var args []request.Arg
			if flatten("json", v, 0, &args) {
				return args
			}
			return append(args, request.Arg{Name: "message", Value: string(text)})
		}
	}
	return []request.Arg{{Name: "message", Value: string(text)}}
}

// flatten adds v's scalar values, named by path, to args. It reports
// whether it added all of them, within the bounds.
func flatten(name string, v any, depth int, args *[]request.Arg) bool {
	if depth > maxMessageDepth {
		return false
	}
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			if !flatten(name+"."+k, e, depth+1, args) {
				return false
			}
		}
		return true
	case []any:
		for i, e := range v {
			if !flatten(name+"."+strconv.Itoa(i), e, depth+1, args) {
				return false
			}
		}
		return true
	}
	if len(*args) >= maxMessageArgs {
		return false
	}
	var s string
	switch v := v.(type) {
	case string:
		s = v
	case json.Number:
		s = v.String()
	case bool:
		s = strconv.FormatBool(v)
	case nil:
		s = ""
	}
	*args = append(*args, request.Arg{Name: name, Value: s})
	return true
}

// Mode returns the pipeline's mode: the engine's proxy holds each message
// until it is inspected in block mode, and forwards it at once in detect
// mode.
func (p *Pipeline) Mode() Mode { return p.mode }
