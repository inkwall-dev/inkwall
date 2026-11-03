// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// b64 is gRPC-Web text: each piece base64-encoded on its own, with its
// padding, as a client encodes each message it sends.
func b64(pieces ...[]byte) []byte {
	var b []byte
	for _, p := range pieces {
		b = append(b, base64.StdEncoding.EncodeToString(p)...)
	}
	return b
}

// TestGRPCWebText: a gRPC-Web text call (base64) is a gRPC call as a
// binary one is: its metadata inspected, its content type allowed, and,
// with GRPCMessages, its messages. Before v0.4.0 every one was denied in
// block mode (920420) and its base64 read as a form.
func TestGRPCWebText(t *testing.T) {
	const svc = "/helloworld.Greeter/SayHello"
	const sqli = "1' OR '1'='1' -- "
	attack := b64(helloRequest(sqli))
	tests := []struct {
		name        string
		contentType string
		body        []byte
		truncated   bool
		skip, on    int // status in block mode, GRPCMessages off and on: 0 allows
		rule        int // a rule that must match when denied
	}{
		{"one message", "application/grpc-web-text", b64(helloRequest("world")), false, 0, 0, 0},
		{"+proto", "application/grpc-web-text+proto", b64(helloRequest("world")), false, 0, 0, 0},
		{"messages encoded one by one", "application/grpc-web-text", b64(helloRequest("w"), helloRequest("wo"), clientStream()), false, 0, 0, 0},
		{"all in one", "application/grpc-web-text", b64(append(helloRequest("w"), clientStream()...)), false, 0, 0, 0},
		{"empty message", "application/grpc-web-text", b64(grpcFrame(nil)), false, 0, 0, 0},
		{"sqli in the message", "application/grpc-web-text", attack, false, 0, 403, 942100},
		{"sqli in a later message", "application/grpc-web-text", b64(clientStream(), helloRequest(sqli)), false, 0, 403, 942100},
		// Cut at the limit, in the middle of a base64 group: a gRPC call,
		// whose messages can't all be read.
		{"cut", "application/grpc-web-text", attack[:len(attack)-3], true, 0, 413, 0},
		// Not gRPC-Web text: inspected as any request, and CRS denies its
		// content type.
		{"not base64", "application/grpc-web-text", []byte(`{"q":"` + sqli + `"}`), false, 403, 403, 920420},
		{"base64, not gRPC messages", "application/grpc-web-text", b64([]byte(sqli)), false, 403, 403, 920420},
		{"padding inside a group", "application/grpc-web-text", []byte("AA=A"), false, 403, 403, 920420},
		{"cut group, not truncated", "application/grpc-web-text", b64(helloRequest("world"))[:7], false, 403, 403, 920420},
		{"binary body", "application/grpc-web-text", helloRequest("world"), false, 403, 403, 920420},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, on := range []bool{false, true} {
				want := tt.skip
				if on {
					want = tt.on
				}
				r := grpcCall(svc, tt.contentType, tt.body)
				r.BodyTruncated = tt.truncated
				v := messagesPipeline(t, pipeline.ModeBlock, on).Check(context.Background(), r)
				got := 0
				if v.Action == pipeline.ActionDeny {
					got = v.Status
				}
				if got != want {
					t.Fatalf("GRPCMessages %v: %s/%s %d, rules %v, want status %d", on, v.Action, v.Reason, v.Status, v.RuleIDs, want)
				}
				if got == 403 && tt.rule != 0 && !slices.Contains(v.RuleIDs, tt.rule) {
					t.Fatalf("GRPCMessages %v: rules %v, want %d", on, v.RuleIDs, tt.rule)
				}
			}
		})
	}
}
