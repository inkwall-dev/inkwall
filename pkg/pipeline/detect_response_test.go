// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqlErrorPage = `<html><body><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p></body></html>`

func sqliRequest() *request.Request {
	return &request.Request{Proto: "HTTP/1.1", Method: http.MethodGet, Scheme: "https", Host: "shop.example.com",
		RawURI: "/products?id=1%27%20OR%20%271%27%3D%271", ClientIP: netip.MustParseAddr("198.51.100.7"),
		Headers: http.Header{"User-Agent": {"Mozilla/5.0"}, "Accept": {"text/html"}}}
}

func leak() *request.Response {
	return &request.Response{Status: 500, Proto: "HTTP/1.1", Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte(sqlErrorPage)}
}

// TestDetectModeInspectsFlaggedResponses (#360): in Detect mode, a request
// the rules flag is let through, and so its response is inspected too: two
// events, the request's and the response's. In Block mode the request is
// denied and there is no response.
func TestDetectModeInspectsFlaggedResponses(t *testing.T) {
	eval, err := coraza.New(coraza.Config{ResponseBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	responses := pipeline.ResponseConfig{Inspect: true, MaxBytes: 1 << 20}
	detect := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeDetect, Timeout: 10 * time.Second, Responses: responses})
	v, x := detect.CheckExchange(context.Background(), sqliRequest())
	if v.Action != pipeline.ActionLog || v.Reason != pipeline.ReasonRule || !slices.Contains(v.RuleIDs, 942100) {
		t.Fatalf("request: %s/%s %v, want logged with 942100", v.Action, v.Reason, v.RuleIDs)
	}
	if x == nil {
		t.Fatal("detect mode: no exchange for the flagged request's response")
	}
	rv := x.CheckResponse(context.Background(), leak())
	x.Close()
	if rv.Action != pipeline.ActionLog || rv.Reason != pipeline.ReasonRule || !slices.Contains(rv.RuleIDs, 951230) || slices.Contains(rv.RuleIDs, 942100) {
		t.Errorf("response: %s/%s %v, want logged with 951230 only", rv.Action, rv.Reason, rv.RuleIDs)
	}

	block := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second, Responses: responses})
	v, x = block.CheckExchange(context.Background(), sqliRequest())
	if v.Action != pipeline.ActionDeny || x != nil {
		t.Errorf("block mode: %s, exchange %v, want denied without one", v.Action, x)
	}
}
