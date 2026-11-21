// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/test/bufconn"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// verdictInspector denies every request with its verdict.
type verdictInspector struct{ v pipeline.Verdict }

func (i verdictInspector) Check(context.Context, *request.Request) pipeline.Verdict { return i.v }
func (verdictInspector) BodyLimit(*request.Request, int64) int64                    { return 0 }

func immediateHeaders(r *extprocv3.ProcessingResponse) map[string]string {
	got := map[string]string{}
	for _, h := range r.GetImmediateResponse().GetHeaders().GetSetHeaders() {
		got[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	return got
}

// A policy's spec.denyResponse is the ImmediateResponse's body, with the
// verdict's status and Retry-After, and Envoy's request ID in it (#725); a
// gRPC call keeps its trailers-only denial.
func TestDenyResponse(t *testing.T) {
	deny, err := pipeline.CompileDenyResponse("application/problem+json",
		`{"type":"about:blank","title":"Too many requests","request_id":"{{request_id}}"}`)
	if err != nil {
		t.Fatal(err)
	}
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 429, Reason: pipeline.ReasonRateLimit,
		RetryAfter: 30 * time.Second, DenyResponse: deny}
	s, err := New(verdictInspector{v}, Config{MaxBodyBytes: 1 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), JSONDenials: true})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	e := startServer(t, s, ln, func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) })

	resps := e.exchange(t, headers("GET", "/", true, "accept", "application/json"))
	got := immediateHeaders(resps[0])
	want := `{"type":"about:blank","title":"Too many requests","request_id":"envoy-id-1"}`
	if denied(t, resps[0]) != 429 || got["content-type"] != "application/problem+json" || got["retry-after"] != "30" ||
		got["x-request-id"] != "envoy-id-1" || string(resps[0].GetImmediateResponse().GetBody()) != want {
		t.Errorf("denial: %d %v %q", denied(t, resps[0]), got, resps[0].GetImmediateResponse().GetBody())
	}

	resps = e.exchange(t, headers("POST", "/shop.Cart/Add", true, "content-type", "application/grpc"))
	if ir := resps[0].GetImmediateResponse(); len(ir.GetBody()) != 0 || ir.GetGrpcStatus().GetStatus() != 8 {
		t.Errorf("gRPC denial: body %q, grpc_status %v; want none and 8", ir.GetBody(), ir.GetGrpcStatus())
	}
}

// A response replaced in the response phase gets the policy's denial too.
func TestDenyResponseOfAResponse(t *testing.T) {
	deny, err := pipeline.CompileDenyResponse("text/html", "<p>{{request_id}}</p>")
	if err != nil {
		t.Fatal(err)
	}
	eval, err := coraza.New(coraza.Config{ResponseBodyLimit: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
		Responses: pipeline.ResponseConfig{Inspect: true, MaxBytes: 1 << 10}, DenyResponse: deny})
	var logs bytes.Buffer
	e := newEnvoy(t, p, 64, &logs)
	resps := e.exchange(t, withModes(headers("GET", "/", true), 0, filterv3.ProcessingMode_BUFFERED_PARTIAL),
		respHeaders(500, false, "content-type", "text/html"), respBody(sqlError, true))
	last := resps[len(resps)-1]
	if denied(t, last) != 403 || immediateHeaders(last)["content-type"] != "text/html; charset=utf-8" ||
		string(last.GetImmediateResponse().GetBody()) != "<p>envoy-id-1</p>" {
		t.Errorf("replaced response: %d %v %q", denied(t, last), immediateHeaders(last), last.GetImmediateResponse().GetBody())
	}
}
