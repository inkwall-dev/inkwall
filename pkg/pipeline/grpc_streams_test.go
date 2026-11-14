// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

func grpcCall(uri, contentType string) *request.Request {
	return &request.Request{ID: "call-1", Method: http.MethodPost, RawURI: uri, Proto: "HTTP/2", Host: "grpc.example.com",
		Headers: http.Header{"Content-Type": {contentType}, "X-Api-Key": {"secret"}, "Te": {"trailers"}}}
}

// Whether a call's messages are inspected one by one (#315): a gRPC call
// (not gRPC-Web, whose clients don't stream), on a policy that inspects
// messages per message, on a route inspected with its body.
func TestGRPCPerMessage(t *testing.T) {
	routes, err := router.New([]string{"/skip/*"}, []string{"/nobody/*"})
	if err != nil {
		t.Fatal(err)
	}
	on := New(fakeEvaluator{}, Config{GRPCMessages: true, GRPCPerMessage: true, Routes: routes})
	for _, tt := range []struct {
		name string
		p    *Pipeline
		r    *request.Request
		want bool
	}{
		{"gRPC", on, grpcCall("/chat.Chat/Talk", "application/grpc"), true},
		{"gRPC proto", on, grpcCall("/chat.Chat/Talk", "application/grpc+proto; charset=x"), true},
		{"gRPC-Web", on, grpcCall("/chat.Chat/Talk", "application/grpc-web"), false},
		{"another codec", on, grpcCall("/chat.Chat/Talk", "application/grpc+json"), false},
		{"not a POST", on, &request.Request{Method: "GET", RawURI: "/", Headers: http.Header{"Content-Type": {"application/grpc"}}}, false},
		{"skipped route", on, grpcCall("/skip/a", "application/grpc"), false},
		{"body skipped", on, grpcCall("/nobody/a", "application/grpc"), false},
		{"buffered policy", New(fakeEvaluator{}, Config{GRPCMessages: true}), grpcCall("/chat.Chat/Talk", "application/grpc"), false},
		{"messages not inspected", New(fakeEvaluator{}, Config{GRPCPerMessage: true}), grpcCall("/chat.Chat/Talk", "application/grpc"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.GRPCStream(tt.r) != nil; got != tt.want {
				t.Errorf("GRPCStream %v, want %v", got, tt.want)
			}
		})
	}
}

// Each message is inspected on its own: a fresh evaluation of the call
// (its identity, path and content type, but not its other headers or its
// query, inspected with the call), whose form arguments are the message's
// text fields, named as grpcMessages names them.
func TestCheckGRPCMessage(t *testing.T) {
	ev := &recordingEvaluator{}
	p := New(ev, Config{Mode: ModeBlock, Policy: "ns/p", GRPCMessages: true, GRPCPerMessage: true})
	call := grpcCall("/chat.Chat/Talk?x=1", "application/grpc")
	msg := streams.Event{Data: []byte("hi\nthere"), Fields: []grpcwire.Field{{Name: "1", Value: "hi"}, {Name: "2.1", Value: "there"}}}
	v := p.CheckGRPCMessage(context.Background(), call, msg, 4)
	if v.Action != ActionAllow || v.StreamEvent != 4 || v.Response || v.Policy != "ns/p" {
		t.Fatalf("verdict %+v", v)
	}
	got := ev.got
	if got.ID != "call-1" || got.Method != http.MethodPost || got.RawURI != "/chat.Chat/Talk" || !got.GRPC || got.Host != "grpc.example.com" {
		t.Errorf("evaluated %+v", got)
	}
	if got.Headers.Get("X-Api-Key") != "" || got.Headers.Get("Content-Type") != "application/grpc" {
		t.Errorf("headers %v: the call's content type only", got.Headers)
	}
	if len(got.GRPCText) != 2 || got.GRPCText[1] != (request.Arg{Name: "2.1", Value: "there"}) {
		t.Errorf("arguments %v", got.GRPCText)
	}

	// Denied by the rules: denied, as a request.
	ev.res = blocked
	if v := p.CheckGRPCMessage(context.Background(), call, msg, 5); v.Action != ActionDeny || v.Status != http.StatusForbidden || v.Reason != ReasonRule {
		t.Errorf("attack: %v %d %v", v.Action, v.Status, v.Reason)
	}
	ev.res = blocked
	detect := New(ev, Config{Mode: ModeDetect, GRPCMessages: true, GRPCPerMessage: true})
	if v := detect.CheckGRPCMessage(context.Background(), call, msg, 5); v.Action != ActionLog {
		t.Errorf("attack in detect mode: %v", v.Action)
	}
	ev.res = rules.Result{}
	// Cut: the oversize action.
	if v := p.CheckGRPCMessage(context.Background(), call, streams.Event{Truncated: true}, 6); v.Action != ActionDeny || v.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("cut message: %v %d", v.Action, v.Status)
	}
	// Not gRPC framing: denied whatever onOversize says.
	allow := New(ev, Config{Mode: ModeBlock, Oversize: OversizeAllow, GRPCMessages: true, GRPCPerMessage: true})
	if v := allow.CheckGRPCMessage(context.Background(), call, streams.Event{Truncated: true, Unframed: true}, 1); v.Action != ActionDeny || v.Reason != ReasonGRPC {
		t.Errorf("unframed: %v %v", v.Action, v.Reason)
	}
	if v := allow.CheckGRPCMessage(context.Background(), call, streams.Event{Truncated: true}, 1); v.Action != ActionAllow {
		t.Errorf("cut under Allow: %v", v.Action)
	}
}

// A stream of many tiny messages costs one evaluation each, under the
// same admission control as requests: when every slot is busy, a message
// is shed at once with the failure mode, as a request is, rather than
// queueing more work. Fail closed: the call ends (503, UNAVAILABLE).
func TestGRPCMessagesShedUnderOverload(t *testing.T) {
	for _, tt := range []struct {
		mode   FailureMode
		action Action
	}{{FailClosed, ActionDeny}, {FailOpen, ActionAllow}} {
		p := New(fakeEvaluator{block: hung(t)}, Config{Mode: ModeBlock, FailureMode: tt.mode, Timeout: 5 * time.Millisecond,
			MaxConcurrent: 1, GRPCMessages: true, GRPCPerMessage: true})
		call := grpcCall("/chat.Chat/Talk", "application/grpc")
		tiny := streams.Event{Data: []byte("a"), Fields: []grpcwire.Field{{Name: "1", Value: "a"}}}
		// The first takes the one slot, and outlives its deadline.
		if v := p.CheckGRPCMessage(context.Background(), call, tiny, 1); v.Reason != ReasonTimeout {
			t.Fatalf("first message: %v", v.Reason)
		}
		start := time.Now()
		for n := 2; n <= 1000; n++ {
			v := p.CheckGRPCMessage(context.Background(), call, tiny, n)
			if v.Reason != ReasonOverload || v.Action != tt.action {
				t.Fatalf("failure mode %v, message %d: %v %v, want %v overload", tt.mode, n, v.Action, v.Reason, tt.action)
			}
			if tt.action == ActionDeny && v.Status != http.StatusServiceUnavailable {
				t.Fatalf("message %d: status %d", n, v.Status)
			}
		}
		// Shed without waiting for the slot; loose, for a loaded machine.
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("failure mode %v: 999 shed messages took %s", tt.mode, d)
		}
	}
}
