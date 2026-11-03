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
// body (binary, or gRPC-Web text: base64), with its grpc-encoding: what
// the rules get is valid UTF-8 text, within the limits, and a cut body is
// never taken as read whole.
func FuzzGRPCText(f *testing.F) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("\x0a\x05world"))
	_ = zw.Close()
	frame := func(flag byte, msg []byte) []byte {
		n := len(msg)
		return append([]byte{flag, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, msg...)
	}
	f.Add(frame(0, []byte("\x0a\x05world\x12\x04\x0a\x02in")), "", false, false)
	f.Add(frame(1, gz.Bytes()), "gzip", false, false)
	f.Add(frame(0, []byte("\x0a\x05wor")), "", true, false)
	f.Add([]byte("AAAAAAcKBXdvcmxk"), "", false, true)
	f.Add([]byte("AAAAAAIKAA==AAAAAAA="), "", false, true)
	f.Add([]byte("AAAAAAcKBXdvc"), "", true, true)
	f.Fuzz(func(t *testing.T, body []byte, encoding string, truncated, text bool) {
		contentType := "application/grpc"
		if text {
			contentType = "application/grpc-web-text"
		}
		r := &request.Request{Method: http.MethodPost, Body: body, BodyTruncated: truncated,
			Headers: http.Header{"Content-Type": {contentType}, "Grpc-Encoding": {encoding}}}
		call, messages := asGRPC(r)
		if call == nil {
			return
		}
		if call.Body != nil || !call.GRPC {
			t.Fatalf("call %+v", call)
		}
		if text {
			// The messages are what the body's base64 says, no more.
			if len(messages) > len(body)/4*3 {
				t.Fatalf("%d bytes of messages from %d of base64", len(messages), len(body))
			}
		} else if !bytes.Equal(messages, body) {
			t.Fatal("binary messages aren't the body")
		}
		args, complete := grpcText(r, messages)
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
