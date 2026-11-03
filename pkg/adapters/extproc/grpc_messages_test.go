// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"testing"
	"time"

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
