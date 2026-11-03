// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"math/rand/v2"
	"testing"

	_ "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	_ "google.golang.org/grpc/health/grpc_health_v1"
	_ "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// idArgumentsLimit is the rule that denies a body with more arguments
// than the policy allows (1000 by default), as for a form or JSON body.
const idArgumentsLimit = 200005

// TestGRPCMessagesFalsePositives measures what the default CRS denies in
// messages that carry no attack, with GRPCMessages (docs/design/0002 §8.7):
//
//   - every protobuf file linked in this test (Envoy's, gRPC's, protobuf's
//     own), as a FileDescriptorProto: real messages, nested, with many
//     names, paths and options;
//   - everyday text: names, addresses, URLs, sentences, JSON;
//   - binary: fields of random bytes (ids, hashes, keys), and numbers.
//
// Text and descriptors must pass. Random bytes are sometimes printable
// UTF-8, and a short run like "|W", "`W" or `u1j"!N` can match a
// command-injection or SQL injection rule (932250, 932340, 942190): about
// 1 message in 10,000 with four 1-24 byte fields, which is why
// GRPCMessages is off by default.
func TestGRPCMessagesFalsePositives(t *testing.T) {
	p := messagesPipeline(t, pipeline.ModeBlock, true)
	check := func(kind string, msg []byte) pipeline.Verdict {
		t.Helper()
		v := p.Check(context.Background(), grpcCall("/pkg.Service/Method", "application/grpc", grpcFrame(msg)))
		if v.Reason == pipeline.ReasonOversize {
			t.Fatalf("%s: not read whole: %+v", kind, v)
		}
		return v
	}

	var files, tooMany int
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		msg, err := proto.Marshal(protodesc.ToFileDescriptorProto(fd))
		if err != nil {
			t.Fatal(err)
		}
		files++
		v := check(fd.Path(), msg)
		switch {
		case v.Action != pipeline.ActionDeny:
		case v.InterruptingRuleID == idArgumentsLimit:
			tooMany++
		default:
			t.Errorf("%s: denied (%s), rules %v, matches %+v", fd.Path(), v.Reason, v.RuleIDs, v.Matches)
		}
		return true
	})
	if files < 50 {
		t.Fatalf("%d descriptors, want a corpus", files)
	}
	t.Logf("%d descriptors: %d over the argument limit, none denied by CRS", files, tooMany)

	var text []byte
	for i, s := range everyday {
		text = protowire.AppendTag(text, protowire.Number(i%30+1), protowire.BytesType)
		text = protowire.AppendString(text, s)
	}
	if v := check("everyday text", text); v.Action == pipeline.ActionDeny || len(v.RuleIDs) != 0 {
		t.Errorf("everyday text: %+v", v)
	}

	const n = 5000
	rng := rand.New(rand.NewPCG(275, 1))
	denied := 0
	for range n {
		var msg []byte
		for f := protowire.Number(1); f <= 4; f++ {
			b := make([]byte, 1+rng.IntN(24))
			for j := range b {
				b[j] = byte(rng.Uint32())
			}
			msg = protowire.AppendTag(msg, f, protowire.BytesType)
			msg = protowire.AppendBytes(msg, b)
			msg = protowire.AppendTag(msg, f+10, protowire.VarintType)
			msg = protowire.AppendVarint(msg, rng.Uint64())
		}
		v := p.Check(context.Background(), grpcCall("/pkg.Service/Method", "application/grpc", grpcFrame(msg)))
		if v.Action == pipeline.ActionDeny {
			denied++
			t.Logf("random bytes denied: %+v", v.Matches)
		}
	}
	t.Logf("%d of %d messages of random bytes denied", denied, n)
	if denied > n/1000 {
		t.Errorf("%d of %d messages of random bytes denied, want at most 1 in 1000", denied, n)
	}
}

// everyday is text that application messages carry.
var everyday = []string{
	"world", "Alice O'Brien", "Zoë Müller", "李小龙", "alice@example.com", "+1 (555) 010-9999",
	"221B Baker Street, London NW1 6XE", "https://shop.example.com/products/42?ref=email&utm_source=news",
	"The quick brown fox jumps over the lazy dog.", "Please select your plan and update your profile.",
	`{"sku":"A-1001","qty":2,"gift":true}`, "2026-11-03T15:04:05Z", "6f1c2a3e-8b9d-4c1e-9f2a-7d3b5e8a1c04",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "en-US", "Europe/Berlin", "image/png", "v1.2.3",
	"orders/2026/11/invoice-0042.pdf", "Hello, how are you today? I'd like to order 3 items.",
	"SKU-12345", "true", "42", "-3.14", "projects/demo/locations/eu/instances/main",
	"Customer asked: can we ship before Friday? Also, add a note: \"leave at door\".",
	"Line one\nLine two\n\tindented", "café crème", "#hashtag @mention", "50% off - today only!",
}
