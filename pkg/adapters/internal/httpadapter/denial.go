// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// Denial is a denied request's answer, the same from every adapter
// (docs/troubleshooting.md, "What a denied client sees"): the status,
// X-Request-Id, and a short body. A client that accepts application/json
// gets a JSON body instead of text when JSON denials are on
// (--json-denials).
type Denial struct {
	ContentType string
	Body        []byte
}

// DenialBody returns the body of a denial with status for the request
// ID, as JSON when jsonOK and the request's Accept takes application/json.
func DenialBody(status int, id string, reqHeaders http.Header, jsonOK bool) Denial {
	if jsonOK && acceptsJSON(reqHeaders.Values("Accept")) {
		b, _ := json.Marshal(struct {
			Error     string `json:"error"`
			Status    int    `json:"status"`
			RequestID string `json:"request_id"`
		}{errorCode(status), status, id})
		return Denial{ContentType: "application/json", Body: append(b, '\n')}
	}
	return Denial{ContentType: "text/plain; charset=utf-8", Body: []byte(http.StatusText(status) + "\n")}
}

// VerdictDenial returns the body of v's denial for the request ID: the
// policy's (v.DenyResponse) when it has one, DenialBody's otherwise.
func VerdictDenial(v pipeline.Verdict, id string, reqHeaders http.Header, jsonOK bool) Denial {
	if d := v.DenyResponse; d != nil {
		return Denial{ContentType: d.ContentType(), Body: d.Render(id)}
	}
	return DenialBody(v.Status, id, reqHeaders, jsonOK)
}

// WriteDenial answers an unreadable request with status: its request ID in
// X-Request-Id, and DenialBody's body. A verdict's denial is
// WriteVerdictDenial's.
func WriteDenial(w http.ResponseWriter, status int, id string, reqHeaders http.Header, jsonOK bool) {
	writeDenial(w, status, id, DenialBody(status, id, reqHeaders, jsonOK))
}

// WriteVerdictDenial answers a request v denies (or whose response it
// replaces) with v's status, the request ID in X-Request-Id, and
// VerdictDenial's body. The caller sets Retry-After (SetRetryAfter).
func WriteVerdictDenial(w http.ResponseWriter, v pipeline.Verdict, id string, reqHeaders http.Header, jsonOK bool) {
	writeDenial(w, v.Status, id, VerdictDenial(v, id, reqHeaders, jsonOK))
}

func writeDenial(w http.ResponseWriter, status int, id string, d Denial) {
	h := w.Header()
	h.Set("Content-Length", strconv.Itoa(len(d.Body)))
	h.Set("Content-Type", d.ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Request-Id", id)
	w.WriteHeader(status)
	_, _ = w.Write(d.Body)
}

// errorCode is a status's text in snake case: "forbidden",
// "request_entity_too_large".
func errorCode(status int) string {
	t := http.StatusText(status)
	if t == "" {
		return "status_" + strconv.Itoa(status)
	}
	return strings.ReplaceAll(strings.ToLower(t), " ", "_")
}

// acceptsJSON reports whether Accept headers take application/json (with
// a q above 0). Wildcards don't count: a browser's */* gets text.
func acceptsJSON(values []string) bool {
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || mt != "application/json" {
				continue
			}
			if q, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(q, 64); err != nil || f <= 0 {
					continue
				}
			}
			return true
		}
	}
	return false
}

// RetryAfter is the Retry-After of a verdict's denial, in whole seconds:
// set on a rate limit's 429, "" otherwise.
func RetryAfter(v pipeline.Verdict) string {
	if v.Status != http.StatusTooManyRequests || v.RetryAfter <= 0 {
		return ""
	}
	return strconv.FormatInt(int64((v.RetryAfter+time.Second-1)/time.Second), 10)
}

// SetRetryAfter sets h's Retry-After from v, if it has one.
func SetRetryAfter(h http.Header, v pipeline.Verdict) {
	if ra := RetryAfter(v); ra != "" {
		h.Set("Retry-After", ra)
	}
}
