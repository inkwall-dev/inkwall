// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"net/http"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

func TestGRPCFramed(t *testing.T) {
	msg := []byte{0, 0, 0, 0, 3, 'a', 'b', 'c'}
	tests := []struct {
		name      string
		body      []byte
		truncated bool
		want      bool
	}{
		{"empty", nil, false, true},
		{"one message", msg, false, true},
		{"two messages", append(append([]byte{}, msg...), msg...), false, true},
		{"empty message", []byte{0, 0, 0, 0, 0}, false, true},
		{"compressed", []byte{1, 0, 0, 0, 1, 'x'}, false, true},
		{"bad flag", []byte{2, 0, 0, 0, 1, 'x'}, false, false},
		{"json", []byte(`{"a":1}`), false, false},
		{"short prefix", []byte{0, 0, 0}, false, false},
		{"message past the end", []byte{0, 0, 0, 0, 9, 'x'}, false, false},
		{"bytes after the last message", append(append([]byte{}, msg...), 0), false, false},
		{"truncated in a message", []byte{0, 0, 0, 0, 9, 'x'}, true, true},
		{"truncated in a prefix", append(append([]byte{}, msg...), 0, 0), true, true},
		{"truncated, bad flag after a message", append(append([]byte{}, msg...), 5, 0, 0, 0, 0), true, false},
		{"truncated before a prefix", []byte{0, 0}, true, false},
		{"truncated, empty", nil, true, false},
		{"huge length", []byte{0, 0xff, 0xff, 0xff, 0xff, 'x'}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := grpcFramed(tt.body, tt.truncated); got != tt.want {
				t.Fatalf("grpcFramed(%q, %v) = %v, want %v", tt.body, tt.truncated, got, tt.want)
			}
		})
	}
}

func TestAsGRPC(t *testing.T) {
	body := []byte{0, 0, 0, 0, 0}
	r := &request.Request{Method: http.MethodPost, Headers: http.Header{"Content-Type": {"application/grpc"}}, Body: body, BodyTruncated: false}
	call := asGRPC(r)
	if call == nil || !call.GRPC || call.Body != nil || call.BodyTruncated {
		t.Fatalf("asGRPC = %+v, want the call without its body", call)
	}
	if r.GRPC || r.Body == nil {
		t.Fatal("asGRPC changed its argument")
	}
	for _, ct := range []string{"application/grpc", "application/grpc+proto", "APPLICATION/GRPC; charset=x", " application/grpc-web ", "application/grpc-web+proto"} {
		if asGRPC(&request.Request{Method: http.MethodPost, Headers: http.Header{"Content-Type": {ct}}, Body: body}) == nil {
			t.Errorf("%q: not a gRPC call", ct)
		}
	}
	for _, ct := range []string{"application/grpc+json", "application/grpc-web-text", "application/grpcx", "application/json", ""} {
		if asGRPC(&request.Request{Method: http.MethodPost, Headers: http.Header{"Content-Type": {ct}}, Body: body}) != nil {
			t.Errorf("%q: a gRPC call", ct)
		}
	}
	if asGRPC(&request.Request{Method: http.MethodGet, Headers: http.Header{"Content-Type": {"application/grpc"}}}) != nil {
		t.Error("GET: a gRPC call")
	}
	if asGRPC(&request.Request{Method: http.MethodPost, Headers: http.Header{}}) != nil {
		t.Error("no content type: a gRPC call")
	}
}
