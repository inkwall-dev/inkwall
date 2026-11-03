// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"testing"
	"unicode/utf8"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// FuzzGRPCText checks the reading of a gRPC call's messages, a client's
// body (with its grpc-encoding): what the rules get is valid UTF-8 text,
// within the limits, and a cut body is never taken as read whole.
func FuzzGRPCText(f *testing.F) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("\x0a\x05world"))
	_ = zw.Close()
	frame := func(flag byte, msg []byte) []byte {
		n := len(msg)
		return append([]byte{flag, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, msg...)
	}
	f.Add(frame(0, []byte("\x0a\x05world\x12\x04\x0a\x02in")), "", false)
	f.Add(frame(1, gz.Bytes()), "gzip", false)
	f.Add(frame(0, []byte("\x0a\x05wor")), "", true)
	f.Fuzz(func(t *testing.T, body []byte, encoding string, truncated bool) {
		r := &request.Request{Method: http.MethodPost, Body: body, BodyTruncated: truncated,
			Headers: http.Header{"Content-Type": {"application/grpc"}, "Grpc-Encoding": {encoding}}}
		if asGRPC(r) == nil {
			return
		}
		args, complete := grpcText(r)
		if complete && truncated {
			t.Fatal("a cut body read whole")
		}
		if len(args) > grpcTextLimits.Fields {
			t.Fatalf("%d fields over the limit", len(args))
		}
		for _, a := range args {
			if a.Name == "" || a.Value == "" || !utf8.ValidString(a.Value) {
				t.Fatalf("argument %q = %q", a.Name, a.Value)
			}
		}
	})
}
