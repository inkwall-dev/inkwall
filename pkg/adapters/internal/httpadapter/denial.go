// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
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

// WriteDenial answers a denied (or unreadable) request with status: its
// request ID in X-Request-Id, and DenialBody's body.
func WriteDenial(w http.ResponseWriter, status int, id string, reqHeaders http.Header, jsonOK bool) {
	d := DenialBody(status, id, reqHeaders, jsonOK)
	h := w.Header()
	h.Del("Content-Length")
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
