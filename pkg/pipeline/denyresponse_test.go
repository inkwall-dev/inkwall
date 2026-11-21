// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func TestCompileDenyResponse(t *testing.T) {
	for _, tc := range []struct {
		contentType, body string
		served            string // "": refused
	}{
		{"text/html", "<p>blocked</p>", "text/html; charset=utf-8"},
		{"TEXT/HTML; Charset=UTF-8", "<p>blocked</p>", "text/html; charset=utf-8"},
		{"text/plain;charset=utf-8", "blocked", "text/plain; charset=utf-8"},
		{"application/json", `{"error":"blocked"}`, "application/json"},
		{"application/problem+json; charset=utf-8", `{"title":"blocked"}`, "application/problem+json"},
		{"text/xml", "<blocked/>", ""},
		{"application/javascript", "alert(1)", ""},
		{"text/html; charset=iso-8859-1", "x", ""},
		{"text/html; boundary=x", "x", ""},
		{"text/html", "", ""},
		{"text/html", strings.Repeat("a", pipeline.MaxDenyResponseBytes), "text/html; charset=utf-8"},
		{"text/html", strings.Repeat("a", pipeline.MaxDenyResponseBytes+1), ""},
		// 8 KiB counts bytes: 2,731 three-byte characters are 8,193.
		{"text/html", strings.Repeat("€", 2731), ""},
		{"text/plain", "blocked \xff", ""},
	} {
		d, err := pipeline.CompileDenyResponse(tc.contentType, tc.body)
		switch {
		case tc.served == "" && err == nil:
			t.Errorf("%q, %d bytes: compiled, want an error", tc.contentType, len(tc.body))
		case tc.served != "" && err != nil:
			t.Errorf("%q, %d bytes: %v", tc.contentType, len(tc.body), err)
		case err == nil && d.ContentType() != tc.served:
			t.Errorf("%q: served as %q, want %q", tc.contentType, d.ContentType(), tc.served)
		}
	}
}

// The request ID is the only substitution, escaped for the content type:
// an ID an adapter didn't vet still can't add markup or break the JSON.
func TestDenyResponseEscapesTheRequestID(t *testing.T) {
	const evil = `"></p><script>alert(1)</script>{"x":"\`
	html, err := pipeline.CompileDenyResponse("text/html", "<p>Request {{request_id}}, again {{request_id}}.</p>")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(html.Render("abc-123")); got != "<p>Request abc-123, again abc-123.</p>" {
		t.Errorf("HTML: %q", got)
	}
	if got := string(html.Render(evil)); strings.Contains(got, "<script>") || strings.Contains(got, `"></p>`) {
		t.Errorf("HTML with %q: %q", evil, got)
	}

	js, err := pipeline.CompileDenyResponse("application/json", `{"error":"blocked","id":"{{request_id}}"}`)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := json.Unmarshal(js.Render(evil), &doc); err != nil || len(doc) != 2 || doc["id"] != evil {
		t.Errorf("JSON with %q: %v %q", evil, err, js.Render(evil))
	}
	if strings.Contains(string(js.Render(evil)), "<") {
		t.Errorf("JSON with %q keeps <: %q", evil, js.Render(evil))
	}

	text, err := pipeline.CompileDenyResponse("text/plain", "denied: {{request_id}}\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(text.Render("abc-123")); got != "denied: abc-123\n" {
		t.Errorf("text: %q", got)
	}
	// Nothing else is a template: other braces stay.
	other, err := pipeline.CompileDenyResponse("text/plain", "{{.Host}} {{ request_id }} {{request_id}}")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(other.Render("id")); got != "{{.Host}} {{ request_id }} id" {
		t.Errorf("other braces: %q", got)
	}
}

func TestDenyResponseCheckJSON(t *testing.T) {
	for _, tc := range []struct {
		contentType, body string
		ok                bool
	}{
		{"application/json", `{"id":"{{request_id}}"}`, true},
		{"application/problem+json", `{"type":"about:blank","title":"Forbidden","status":403}`, true},
		{"application/json", `{"id":{{request_id}}}`, false},
		{"application/json", `not json`, false},
		{"text/html", `not json`, true},
	} {
		d, err := pipeline.CompileDenyResponse(tc.contentType, tc.body)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.CheckJSON(); (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.contentType, tc.body, err)
		}
	}
}

type interrupting struct{}

func (interrupting) Evaluate(context.Context, *request.Request) (rules.Result, error) {
	return rules.Result{Interrupted: true, RuleID: 942100, Status: 403}, nil
}

// Every verdict of the pipeline carries its denial, the deny's and the
// response's.
func TestVerdictsCarryTheDenyResponse(t *testing.T) {
	d, err := pipeline.CompileDenyResponse("text/plain", "no")
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(interrupting{}, pipeline.Config{Mode: pipeline.ModeBlock, Policy: "shop/web", DenyResponse: d})
	v := p.Check(context.Background(), &request.Request{Method: "GET", RawURI: "/"})
	if v.Action != pipeline.ActionDeny || v.Status != 403 || v.DenyResponse != d {
		t.Errorf("verdict: %v %d %p, want deny 403 with the denial", v.Action, v.Status, v.DenyResponse)
	}
	p = pipeline.New(interrupting{}, pipeline.Config{Mode: pipeline.ModeBlock})
	if v := p.Check(context.Background(), &request.Request{Method: "GET", RawURI: "/"}); v.DenyResponse != nil {
		t.Errorf("without one: %p", v.DenyResponse)
	}
}
