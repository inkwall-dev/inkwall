// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func messagesPipeline(t *testing.T, mode pipeline.Mode, on bool) *pipeline.Pipeline {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// The deadline isn't under test: the race detector on a loaded machine
	// takes over 10 s on the largest descriptor of the false-positive
	// corpus (a 503, reason timeout).
	return pipeline.New(eval, pipeline.Config{Mode: mode, Timeout: 2 * time.Minute, GRPCMessages: on})
}

// gzipFrame is msg compressed with gzip, framed with the compressed flag.
func gzipFrame(t *testing.T, msg []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f := grpcFrame(b.Bytes())
	f[0] = 1
	return f
}

// TestGRPCMessages: with GRPCMessages, the text in a call's messages goes
// through the rules; without (the default), it doesn't.
func TestGRPCMessages(t *testing.T) {
	const svc = "/shop.Catalog/Search"
	const sqli = "1' OR '1'='1' -- "
	nested := grpcFrame(append(pbString(1, "books"), pbString(2, string(pbString(3, sqli)))...))
	tests := []struct {
		name    string
		body    []byte
		extra   []string
		trunc   bool
		on, off int // status in block mode: 0 allows
		rule    int // a rule that must match when on
	}{
		{"clean", helloRequest("world"), nil, false, 0, 0, 0},
		{"clean stream", clientStream(), nil, false, 0, 0, 0},
		{"sqli in a field", helloRequest(sqli), nil, false, 403, 0, 942100},
		{"sqli in a nested message", nested, nil, false, 403, 0, 942100},
		{"sqli in a later message", append(clientStream(), helloRequest(sqli)...), nil, false, 403, 0, 942100},
		{"xss", helloRequest(`<script>alert(1)</script>`), nil, false, 403, 0, 941100},
		{"gzip", gzipFrame(t, pbString(1, sqli)), []string{"Grpc-Encoding", "gzip"}, false, 403, 0, 942100},
		// Can't be read: handled as an oversized body, 413 in block mode.
		{"unknown encoding", gzipFrame(t, pbString(1, "world")), []string{"Grpc-Encoding", "zstd"}, false, 413, 0, 0},
		{"compressed, no encoding", gzipFrame(t, pbString(1, "world")), nil, false, 413, 0, 0},
		{"not protobuf", grpcFrame([]byte{0xff, 0xff, 0xff}), nil, false, 413, 0, 0},
		{"cut", clientStream()[:12], nil, true, 413, 0, 0},
		// Decompresses past 1 MiB: what fit is read, the rest isn't.
		{"gzip bomb", gzipFrame(t, protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType),
			strings.Repeat("a", 2<<20))), []string{"Grpc-Encoding", "gzip"}, false, 413, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, on := range []bool{true, false} {
				want := tt.off
				if on {
					want = tt.on
				}
				v := messagesPipeline(t, pipeline.ModeBlock, on).Check(context.Background(),
					truncated(grpcCall(svc, "application/grpc", tt.body, tt.extra...), tt.trunc))
				got := 0
				if v.Action == pipeline.ActionDeny {
					got = v.Status
				}
				if got != want {
					t.Fatalf("GRPCMessages %v: %+v, want status %d", on, v, want)
				}
				if on && tt.rule != 0 && !slices.Contains(v.RuleIDs, tt.rule) {
					t.Fatalf("rules %v, want %d", v.RuleIDs, tt.rule)
				}
			}
		})
	}
}

// truncated marks r's body as cut at the limit.
func truncated(r *request.Request, cut bool) *request.Request {
	r.BodyTruncated = cut
	return r
}
