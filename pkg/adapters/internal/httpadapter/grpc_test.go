// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
)

func TestGRPCOf(t *testing.T) {
	tests := []struct {
		contentType []string
		want        GRPCProtocol
	}{
		{nil, NotGRPC},
		{[]string{"application/json"}, NotGRPC},
		{[]string{"application/grpc"}, GRPC},
		{[]string{"application/grpc+proto"}, GRPC},
		{[]string{"application/grpc+json"}, GRPC},
		{[]string{"Application/GRPC; charset=utf-8"}, GRPC},
		{[]string{" application/grpc "}, GRPC},
		{[]string{"application/grpc-web"}, GRPCWeb},
		{[]string{"application/grpc-web+proto"}, GRPCWeb},
		{[]string{"application/grpc-web-text"}, GRPCWebText},
		{[]string{"application/grpc-web-text+proto"}, GRPCWebText},
		// Not gRPC: another media type that only starts the same way, or
		// two content types.
		{[]string{"application/grpcx"}, NotGRPC},
		{[]string{"application/grpc-webx"}, NotGRPC},
		{[]string{"application/grpc-websocket"}, NotGRPC},
		{[]string{"application/grpc", "application/grpc"}, NotGRPC},
	}
	for _, tt := range tests {
		h := http.Header{}
		for _, v := range tt.contentType {
			h.Add("Content-Type", v)
		}
		if got := GRPCOf(h); got != tt.want {
			t.Errorf("GRPCOf(%q) = %v, want %v", tt.contentType, got, tt.want)
		}
	}
}

func TestGRPCCode(t *testing.T) {
	tests := map[int]codes.Code{
		http.StatusBadRequest:            codes.Internal,
		http.StatusUnauthorized:          codes.Unauthenticated,
		http.StatusForbidden:             codes.PermissionDenied,
		http.StatusNotFound:              codes.Unimplemented,
		http.StatusRequestEntityTooLarge: codes.ResourceExhausted,
		http.StatusTooManyRequests:       codes.Unavailable,
		http.StatusBadGateway:            codes.Unavailable,
		http.StatusServiceUnavailable:    codes.Unavailable,
		http.StatusGatewayTimeout:        codes.Unavailable,
		http.StatusTeapot:                codes.Unknown,
		599:                              codes.Unknown,
	}
	for status, want := range tests {
		if got := GRPCCode(status); got != want {
			t.Errorf("GRPCCode(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestGRPCMessage(t *testing.T) {
	tests := []struct {
		status int
		id     string
		want   string
	}{
		{http.StatusForbidden, "0123abcd", "Forbidden (request ID 0123abcd)"},
		{http.StatusServiceUnavailable, "a:b.c_d-e", "Service Unavailable (request ID a:b.c_d-e)"},
		// No status text: still a message.
		{599, "x", "Denied (request ID x)"},
		// Percent-encoded, as the spec says, outside 0x20-0x7E and '%'.
		{http.StatusForbidden, "50%\n\xff", "Forbidden (request ID 50%25%0A%FF)"},
	}
	for _, tt := range tests {
		if got := GRPCMessage(tt.status, tt.id); got != tt.want {
			t.Errorf("GRPCMessage(%d, %q) = %q, want %q", tt.status, tt.id, got, tt.want)
		}
	}
}

func TestWriteGRPCDenial(t *testing.T) {
	tests := []struct {
		proto       GRPCProtocol
		contentType string
	}{
		{GRPC, "application/grpc"},
		{GRPCWeb, "application/grpc-web"},
		{GRPCWebText, "application/grpc-web-text"},
	}
	for _, tt := range tests {
		for _, httpStatus := range []int{http.StatusOK, http.StatusForbidden} {
			w := httptest.NewRecorder()
			w.Header().Set("Content-Type", "text/html") // replaced
			WriteGRPCDenial(w, tt.proto, httpStatus, http.StatusForbidden, "id-1")
			res := w.Result()
			if res.StatusCode != httpStatus {
				t.Errorf("%v: status %d, want %d", tt.proto, res.StatusCode, httpStatus)
			}
			want := map[string]string{
				"Content-Type":           tt.contentType,
				"Grpc-Status":            "7",
				"Grpc-Message":           "Forbidden (request ID id-1)",
				"X-Request-Id":           "id-1",
				"X-Content-Type-Options": "nosniff",
			}
			for k, v := range want {
				if got := res.Header.Values(k); len(got) != 1 || got[0] != v {
					t.Errorf("%v: %s %q, want %q", tt.proto, k, got, v)
				}
			}
			// Trailers-only: no message, so no body.
			if w.Body.Len() != 0 {
				t.Errorf("%v: body %q, want none", tt.proto, w.Body.String())
			}
		}
	}
}
