// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	htmltext "html"
	"mime"
	"strings"
	"unicode/utf8"
)

// MaxDenyResponseBytes bounds a DenyResponse's body, as the CRD does.
const MaxDenyResponseBytes = 8 << 10

// RequestIDToken is the one substitution a DenyResponse's body has: each
// is replaced with the request's ID.
const RequestIDToken = "{{request_id}}" // #nosec G101 -- a placeholder, not a credential

// The media types a DenyResponse may have, and the Content-Type each is
// served with.
var denyContentTypes = map[string]string{
	"text/html":                "text/html; charset=utf-8",
	"text/plain":               "text/plain; charset=utf-8",
	"application/json":         "application/json",
	"application/problem+json": "application/problem+json",
}

// DenyResponse is the body of a policy's denials (WAFPolicy
// spec.denyResponse, or the InkwallConfig's default), compiled: the verdicts
// of the policy's pipeline carry it (Verdict.DenyResponse), and the
// adapters that write a body answer a denial with it instead of their own.
// It is immutable and safe for concurrent use.
type DenyResponse struct {
	contentType string
	// parts is the body split at RequestIDToken: the ID goes between each
	// two.
	parts []string
	// escape escapes the ID for the content type.
	escape func(string) string
}

// CompileDenyResponse checks and compiles a denial's content type and body:
// one of the allowed media types, with charset=utf-8 or no parameter; a
// body of at most MaxDenyResponseBytes of UTF-8, not empty. Whether a JSON
// body is a JSON document is the webhook's to check (CheckJSON): the
// engine serves it as it is, rather than refuse a bundle for it.
func CompileDenyResponse(contentType, body string) (*DenyResponse, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("content type %q: %w", contentType, err)
	}
	served, ok := denyContentTypes[mediaType]
	if !ok {
		return nil, fmt.Errorf("content type %q: only text/html, text/plain, application/json and application/problem+json", contentType)
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return nil, fmt.Errorf("content type %q: only the parameter charset=utf-8", contentType)
		}
	}
	switch {
	case body == "":
		return nil, errors.New("empty body")
	case len(body) > MaxDenyResponseBytes:
		return nil, fmt.Errorf("body of %d bytes, over %d", len(body), MaxDenyResponseBytes)
	case !utf8.ValidString(body):
		return nil, errors.New("body is not UTF-8")
	}
	d := &DenyResponse{contentType: served, parts: strings.Split(body, RequestIDToken), escape: noEscape}
	switch mediaType {
	case "text/html":
		d.escape = htmltext.EscapeString
	case "application/json", "application/problem+json":
		d.escape = jsonEscape
	}
	return d, nil
}

// CheckJSON returns an error when d's content type is JSON and its body,
// with a request ID in it, isn't a JSON document.
func (d *DenyResponse) CheckJSON() error {
	if !strings.HasPrefix(d.contentType, "application/") {
		return nil
	}
	if err := json.Unmarshal(d.Render("0123456789abcdef"), new(any)); err != nil {
		return fmt.Errorf("body is not a JSON document: %w", err)
	}
	return nil
}

// ContentType is the Content-Type the denial is served with.
func (d *DenyResponse) ContentType() string { return d.contentType }

// Render returns the body for the request ID id, escaped for the content
// type: HTML-escaped for text/html, as in a JSON string for JSON (the
// token goes inside a string's quotes), as it is for text/plain. Adapters
// keep only IDs of [A-Za-z0-9._:-] (httpadapter.RequestID), which no
// escaping changes; the escaping holds for any ID.
func (d *DenyResponse) Render(id string) []byte {
	if len(d.parts) == 1 {
		return []byte(d.parts[0])
	}
	esc := d.escape(id)
	n := len(esc) * (len(d.parts) - 1)
	for _, p := range d.parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	for i, p := range d.parts {
		if i > 0 {
			b = append(b, esc...)
		}
		b = append(b, p...)
	}
	return b
}

func noEscape(s string) string { return s }

// jsonEscape is s as in a JSON string, without the quotes: <, > and & as
// \u escapes too, so a JSON body inlined in HTML stays inert.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s) // a string always marshals
	return string(b[1 : len(b)-1])
}
