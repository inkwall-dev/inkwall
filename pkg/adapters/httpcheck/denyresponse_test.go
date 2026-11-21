// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpcheck

import (
	"bytes"
	"testing"
	"time"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// The check API returns a policy's spec.denyResponse with the request ID in
// it, for the caller to answer the client with (#725); without one, or on
// an allow, nothing: the caller writes its own.
func TestDenyResponse(t *testing.T) {
	deny, err := pipeline.CompileDenyResponse("text/html", "<p>Blocked: {{request_id}}</p>")
	if err != nil {
		t.Fatal(err)
	}
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(t, pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, DenyResponse: deny}), 64<<10, &bytes.Buffer{})
	in := checkRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", "")
	in.Headers = append(in.Headers, &enginev1.Header{Name: "X-Request-Id", Value: "client-7"})
	out := send(t, h, in)
	if out.GetAction() != enginev1.Action_ACTION_DENY || out.GetStatus() != 403 || out.GetDenyContentType() != "text/html; charset=utf-8" ||
		out.GetDenyBody() != "<p>Blocked: "+out.GetRequestId()+"</p>" {
		t.Errorf("deny: %v %d %q %q", out.GetAction(), out.GetStatus(), out.GetDenyContentType(), out.GetDenyBody())
	}
	headers := map[string]string{}
	for _, hd := range out.GetResponseHeaders() {
		headers[hd.GetName()] = hd.GetValue()
	}
	if headers["Cache-Control"] != "no-store" || headers["Content-Security-Policy"] != "default-src 'none'; style-src 'unsafe-inline'; img-src data:" || headers["X-Request-Id"] != out.GetRequestId() {
		t.Errorf("deny: response headers %v", headers)
	}
	// A gRPC call: its gRPC status, no body, as the other adapters answer it.
	grpc := checkRequest("POST", "/shop.Cart/Add?id=1%27%20OR%20%271%27%3D%271", "application/grpc", "\x00\x00\x00\x00\x00")
	if out := send(t, h, grpc); out.GetAction() != enginev1.Action_ACTION_DENY || out.GetDenyContentType() != "" || out.GetDenyBody() != "" || len(out.GetResponseHeaders()) != 1 {
		t.Errorf("gRPC deny: %v %q %q %v", out.GetAction(), out.GetDenyContentType(), out.GetDenyBody(), out.GetResponseHeaders())
	}
	if out := send(t, h, checkRequest("GET", "/products?id=1", "", "")); out.GetDenyContentType() != "" || out.GetDenyBody() != "" {
		t.Errorf("allow: %q %q", out.GetDenyContentType(), out.GetDenyBody())
	}
	h = newHandler(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &bytes.Buffer{})
	if out := send(t, h, checkRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", "")); out.GetDenyContentType() != "" || out.GetDenyBody() != "" {
		t.Errorf("deny without one: %q %q", out.GetDenyContentType(), out.GetDenyBody())
	}
}
