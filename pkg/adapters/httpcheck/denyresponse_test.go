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
	if out := send(t, h, checkRequest("GET", "/products?id=1", "", "")); out.GetDenyContentType() != "" || out.GetDenyBody() != "" {
		t.Errorf("allow: %q %q", out.GetDenyContentType(), out.GetDenyBody())
	}
	h = newHandler(t, newPipeline(t, pipeline.ModeBlock), 64<<10, &bytes.Buffer{})
	if out := send(t, h, checkRequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", "")); out.GetDenyContentType() != "" || out.GetDenyBody() != "" {
		t.Errorf("deny without one: %q %q", out.GetDenyContentType(), out.GetDenyBody())
	}
}
