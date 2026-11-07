// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"google.golang.org/grpc/test/bufconn"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// With JSON denials on, a client that accepts JSON gets the JSON body;
// others get text (#366).
func TestJSONDenial(t *testing.T) {
	s, err := New(newPipeline(t, pipeline.ModeBlock), Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), JSONDenials: true})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })

	resps := e.exchange(t, headers("GET", "/products?id=1'%20OR%20'1'='1", true, "accept", "application/json"))
	ir := resps[0].GetImmediateResponse()
	ct := ""
	for _, h := range ir.GetHeaders().GetSetHeaders() {
		if h.GetHeader().GetKey() == "content-type" {
			ct = string(h.GetHeader().GetRawValue())
		}
	}
	if denied(t, resps[0]) != 403 || ct != "application/json" ||
		string(ir.GetBody()) != `{"error":"forbidden","status":403,"request_id":"envoy-id-1"}`+"\n" {
		t.Errorf("JSON denial: %q %q", ct, ir.GetBody())
	}

	resps = e.exchange(t, headers("GET", "/products?id=1'%20OR%20'1'='1", true))
	if string(resps[0].GetImmediateResponse().GetBody()) != "Forbidden\n" {
		t.Errorf("a browser's denial: %q", resps[0].GetImmediateResponse().GetBody())
	}
}
