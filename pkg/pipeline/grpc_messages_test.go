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

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
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
	// A group (proto2, editions' DELIMITED encoding): fields between a
	// start and an end tag.
	group := func(num byte, fields []byte) []byte {
		return append(append([]byte{num<<3 | 3}, fields...), num<<3|4)
	}
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
		{"sqli in a group", grpcFrame(append(pbString(1, "books"), group(2, pbString(3, sqli))...)), nil, false, 403, 0, 942100},
		// An injection split between the fields of a nested message, its
		// tags and lengths whitespace and control characters: an
		// application reading the field as a string gets it whole.
		{"sqli split between fields", grpcFrame(pbString(1, string(splitSQLi))), nil, false, 403, 0, 942100},
		{"xss in nested groups", grpcFrame(group(1, group(2, pbString(1, `<script>alert(1)</script>`)))), nil, false, 403, 0, 941100},
		// Can't be read: handled as an oversized body, 413 in block mode.
		{"unknown encoding", gzipFrame(t, pbString(1, "world")), []string{"Grpc-Encoding", "zstd"}, false, 413, 0, 0},
		{"compressed, no encoding", gzipFrame(t, pbString(1, "world")), nil, false, 413, 0, 0},
		{"not protobuf", grpcFrame([]byte{0xff, 0xff, 0xff}), nil, false, 413, 0, 0},
		{"unclosed group", grpcFrame(append([]byte{1<<3 | 3}, pbString(2, "world")...)), nil, false, 413, 0, 0},
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

// splitSQLi is an SQL injection in three fields, none of which is one.
var splitSQLi = append(append(pbString(1, "1' UNION"), pbString(1, " SELECT password")...), pbString(1, " FROM users --")...)

// truncated marks r's body as cut at the limit.
func truncated(r *request.Request, cut bool) *request.Request {
	r.BodyTruncated = cut
	return r
}

// deepGroupsFrame is a gzip message of depth nested groups, each with a
// number: a few bytes compressed, and each group's tags were read again for
// each group around it (9,000 took 49 seconds).
func deepGroupsFrame(t *testing.T, depth int) []byte {
	t.Helper()
	var m []byte
	for range depth {
		m = protowire.AppendTag(m, 1, protowire.StartGroupType)
		m = protowire.AppendTag(m, 2, protowire.VarintType)
		m = protowire.AppendVarint(m, 1<<40)
	}
	for range depth {
		m = protowire.AppendTag(m, 1, protowire.EndGroupType)
	}
	return gzipFrame(t, m)
}

// TestGRPCMessagesNestedGroups: a call of deeply nested groups, as many as
// the decompression budget reads, is read in about its size, and is past
// the depth read: handled as an oversized body.
func TestGRPCMessagesNestedGroups(t *testing.T) {
	var body []byte
	for range 12 {
		body = append(body, deepGroupsFrame(t, 9000)...)
	}
	start := time.Now()
	v := messagesPipeline(t, pipeline.ModeBlock, true).Check(context.Background(),
		grpcCall("/shop.Catalog/Search", "application/grpc", body, "Grpc-Encoding", "gzip"))
	// Far above what the reading takes, even with -race.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("read in %v", d)
	}
	if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonOversize {
		t.Errorf("%+v, want a deny for an oversized body", v)
	}
}

// TestGRPCMessagesUnderDeadline: a call's messages are read within the
// inspection deadline (and admission), as the rules run: reading them
// doesn't hold up the verdict past the deadline.
func TestGRPCMessagesUnderDeadline(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: time.Microsecond, GRPCMessages: true})
	frame := deepGroupsFrame(t, 9000)
	var body []byte
	for range 12 {
		body = append(body, frame...)
	}
	// What reading the messages takes.
	start := time.Now()
	for range 12 {
		m, _ := grpcwire.Gunzip(frame[5:], 1<<20)
		grpcwire.Strings(m, grpcwire.Limits{Depth: 16, Fields: 4096}, nil)
	}
	read := time.Since(start)

	start = time.Now()
	v := p.Check(context.Background(), grpcCall("/shop.Catalog/Search", "application/grpc", body, "Grpc-Encoding", "gzip"))
	// A fixed bound, far below what reading the messages takes (read), even
	// with -race.
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("verdict in %v, reading the messages takes %v: not within the deadline", d, read)
	}
	if v.Reason != pipeline.ReasonTimeout {
		t.Errorf("%+v, want a timeout", v)
	}
}

// TestGRPCMessagesSplitInjection: an SQL injection split between the
// fields of a nested message, as an application reading the field as a
// string gets it, whatever its tags and lengths: blank, a length that is a
// character (40, "("), a field number whose tag is one (5, "*"). Each is
// denied.
func TestGRPCMessagesSplitInjection(t *testing.T) {
	long := " SELECT password,email,name,id,role,salt" // 40 bytes: length "("
	for name, inner := range map[string][]byte{
		"blank":            splitSQLi,
		"length a char":    append(append(pbString(1, "1' UNION"), pbString(1, long)...), pbString(1, " FROM users) --")...),
		"tag a char":       append(append(pbString(1, "1' UNION/"), pbString(5, "*/ SELECT password")...), pbString(1, " FROM users --")...),
		"the whole string": []byte("1' UNION ( SELECT password,email FROM users) --"),
	} {
		v := messagesPipeline(t, pipeline.ModeBlock, true).Check(context.Background(),
			grpcCall("/shop.Catalog/Search", "application/grpc", grpcFrame(pbString(1, string(inner)))))
		if v.Action != pipeline.ActionDeny {
			t.Errorf("%s: %+v, want a deny", name, v)
		}
	}
}
