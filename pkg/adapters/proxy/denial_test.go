// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// A denial carries the request ID of its security event, and so does the
// 400 for a request the proxy can't read; JSON bodies only when on and
// asked for (#366).
func TestDenialResponse(t *testing.T) {
	up := newUpstream(t)
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, up, &logs)

	r := httptest.NewRequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var event struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		t.Fatalf("event: %v: %s", err, logs.String())
	}
	if w.Code != 403 || w.Header().Get("X-Request-Id") == "" || w.Header().Get("X-Request-Id") != event.RequestID {
		t.Fatalf("denial: %d, X-Request-Id %q, event's %q", w.Code, w.Header().Get("X-Request-Id"), event.RequestID)
	}
	if w.Body.String() != "Forbidden\n" {
		t.Errorf("JSON denials off: body %q", w.Body.String())
	}

	// An unreadable request: a 400, with an ID too.
	r = httptest.NewRequest("GET", "/", nil)
	r.Host = "bad host"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("X-Request-Id") == "" {
		t.Errorf("400: %d, X-Request-Id %q", w.Code, w.Header().Get("X-Request-Id"))
	}

	// JSON denials on.
	h.jsonDenials = true
	r = httptest.NewRequest("GET", "/?id=1%27%20OR%20%271%27%3D%271", nil)
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	id := w.Header().Get("X-Request-Id")
	if w.Code != 403 || w.Header().Get("Content-Type") != "application/json" ||
		w.Body.String() != `{"error":"forbidden","status":403,"request_id":"`+id+`"}`+"\n" {
		t.Errorf("JSON denial: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("a browser got %q", w.Header().Get("Content-Type"))
	}
	_ = http.StatusOK
}
