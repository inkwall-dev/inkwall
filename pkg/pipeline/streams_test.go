// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"net/http"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// Each event of a streamed response is inspected on its own (#323): as a
// response with the stream's status and headers whose body is the event's
// text, readable by the rules; the verdict is a response's, with the
// event's index. Off unless the policy asks for it.
func TestCheckEvent(t *testing.T) {
	stream := &request.Response{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}}
	for _, tt := range []struct {
		name    string
		mode    Mode
		streams bool
		ev      streams.Event
		action  Action
		status  int
		reason  Reason
	}{
		{name: "clean", mode: ModeBlock, streams: true, ev: streams.Event{Data: []byte("hello")}, action: ActionAllow},
		{name: "leak blocked", mode: ModeBlock, streams: true, ev: streams.Event{Data: []byte("a LEAK")}, action: ActionDeny, status: 403, reason: ReasonRule},
		{name: "leak logged", mode: ModeDetect, streams: true, ev: streams.Event{Data: []byte("a LEAK")}, action: ActionLog, reason: ReasonRule},
		{name: "cut: block mode default", mode: ModeBlock, streams: true, ev: streams.Event{Data: []byte("ok"), Truncated: true}, action: ActionDeny, status: 502, reason: ReasonOversize},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ev := &exchangeEvaluator{}
			p := New(ev, Config{Mode: tt.mode, Policy: "ns/p", Responses: ResponseConfig{Inspect: true, MaxBytes: 64, Streams: tt.streams}})
			v, x := p.CheckExchange(context.Background(), get("/chat"))
			if v.Action != ActionAllow || x == nil {
				t.Fatalf("request: %v", v.Action)
			}
			if !x.Streams() {
				t.Fatal("Streams() false with Streams set")
			}
			// The stream's headers are decided first, and the exchange
			// closed; its events are inspected after.
			x.CheckResponse(context.Background(), stream)
			x.Close()
			got := x.CheckEvent(context.Background(), get("/chat?q=1"), stream, tt.ev, 3)
			if got.Action != tt.action || got.Status != tt.status || got.Reason != tt.reason {
				t.Errorf("verdict %v %d %v, want %v %d %v", got.Action, got.Status, got.Reason, tt.action, tt.status, tt.reason)
			}
			if !got.Response || got.StreamEvent != 3 || got.Policy != "ns/p" {
				t.Errorf("verdict Response %v, StreamEvent %d, Policy %q", got.Response, got.StreamEvent, got.Policy)
			}
			ev.mu.Lock()
			last := ev.got[len(ev.got)-1]
			ev.mu.Unlock()
			if string(last.Body) != string(tt.ev.Data) || last.Headers.Get("Content-Type") != "text/plain" || last.Status != 200 {
				t.Errorf("evaluated %d %q %q", last.Status, last.Headers.Get("Content-Type"), last.Body)
			}
			if n := ev.open.Load(); n != 0 {
				t.Errorf("%d evaluations left open", n)
			}
		})
	}
	// Off by default.
	p := New(&exchangeEvaluator{}, Config{Mode: ModeBlock, Responses: ResponseConfig{Inspect: true, MaxBytes: 64}})
	_, x := p.CheckExchange(context.Background(), get("/"))
	defer x.Close()
	if x.Streams() {
		t.Error("streams inspected by default")
	}
}
