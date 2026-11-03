// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// TestGRPCMessages: with the policy's grpcMessages, an attack in a gRPC
// call's message, buffered by Envoy, is denied with a gRPC status; a
// stream Envoy cut at its buffer is handled as an oversized body.
func TestGRPCMessages(t *testing.T) {
	const limit = 64
	stream := grpcMessages("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota")
	tests := []struct {
		name string
		body string
		eos  bool
		want int    // HTTP status of the denial; 0 allows
		code uint32 // its grpc_status
	}{
		{"clean", grpcMessages("world"), true, 0, 0},
		{"sqli in the message", grpcMessages("1' OR '1'='1' -- "), true, 403, 7},
		{"sqli in a later message", grpcMessages("a", "b", "<script>alert(1)</script>"), true, 403, 7},
		{"stream cut at the buffer", stream[:limit], false, 413, 8},
	}
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: true})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := newEnvoy(t, p, limit, &logs)
			resps := e.exchange(t, grpcHeaders("/helloworld.Greeter/SayHello"), body(tt.body, tt.eos))
			if len(resps) != 2 {
				t.Fatalf("answers %v", resps)
			}
			if tt.want == 0 {
				continued(t, resps[1])
				return
			}
			ir, set := immediate(t, resps[1])
			if int(ir.GetStatus().GetCode()) != tt.want || ir.GetGrpcStatus().GetStatus() != tt.code {
				t.Fatalf("denial %v (%v), want %d, grpc-status %d; events %s", ir, set, tt.want, tt.code, logs.String())
			}
		})
	}
}

// TestGRPCWebText: a gRPC-Web text call (base64) through Envoy passes
// when clean, and an attack in its message is denied with a gRPC-Web
// answer. Before v0.4.0 every one was denied (920420).
func TestGRPCWebText(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, GRPCMessages: true})
	webText := func() *extprocv3.ProcessingRequest {
		m := grpcHeaders("/helloworld.Greeter/SayHello")
		for _, h := range m.GetRequestHeaders().GetHeaders().GetHeaders() {
			if h.GetKey() == "content-type" {
				h.RawValue = []byte("application/grpc-web-text")
			}
		}
		return m
	}
	for _, tt := range []struct {
		name, message string
		denied        bool
	}{
		{"clean", "world", false},
		{"sqli in the message", "1' OR '1'='1' -- ", true},
	} {
		var logs bytes.Buffer
		e := newEnvoy(t, p, 1<<10, &logs)
		resps := e.exchange(t, webText(), body(base64.StdEncoding.EncodeToString([]byte(grpcMessages(tt.message))), true))
		if !tt.denied {
			continued(t, resps[len(resps)-1])
			continue
		}
		ir, set := immediate(t, resps[len(resps)-1])
		if ir.GetStatus().GetCode() != 200 || set["grpc-status"] != "7" || set["content-type"] != "application/grpc-web-text" {
			t.Errorf("%s: denial %v (%v), want HTTP 200, grpc-status 7", tt.name, ir, set)
		}
	}
}
