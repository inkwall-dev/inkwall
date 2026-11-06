// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A denial carries the request ID, and a JSON body only when asked for and
// turned on (#366).
func TestWriteDenial(t *testing.T) {
	for _, c := range []struct {
		name        string
		json        bool
		accept      string
		status      int
		contentType string
		body        string
	}{
		{"text", false, "", 403, "text/plain; charset=utf-8", "Forbidden\n"},
		{"JSON off", false, "application/json", 403, "text/plain; charset=utf-8", "Forbidden\n"},
		{"JSON, not asked", true, "text/html,*/*;q=0.8", 403, "text/plain; charset=utf-8", "Forbidden\n"},
		{"JSON", true, "text/html, application/json;q=0.9", 403, "application/json", `{"error":"forbidden","status":403,"request_id":"abc-1"}` + "\n"},
		{"JSON refused", true, "application/json;q=0", 403, "text/plain; charset=utf-8", "Forbidden\n"},
		{"JSON 413", true, "Application/JSON", 413, "application/json", `{"error":"request_entity_too_large","status":413,"request_id":"abc-1"}` + "\n"},
		{"JSON 503", true, "application/json", 503, "application/json", `{"error":"service_unavailable","status":503,"request_id":"abc-1"}` + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h := http.Header{}
			if c.accept != "" {
				h.Set("Accept", c.accept)
			}
			WriteDenial(w, c.status, "abc-1", h, c.json)
			if w.Code != c.status || w.Header().Get("X-Request-Id") != "abc-1" || w.Header().Get("Content-Type") != c.contentType ||
				w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Body.String() != c.body {
				t.Errorf("%d %v %q", w.Code, w.Header(), w.Body.String())
			}
			if c.contentType == "application/json" && !json.Valid(w.Body.Bytes()) {
				t.Errorf("invalid JSON %q", w.Body.String())
			}
		})
	}
}
