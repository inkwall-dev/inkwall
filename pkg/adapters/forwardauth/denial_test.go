// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// Traefik copies the engine's denial to the client: it carries the request
// ID of the security event, and so does the 400 (#366).
func TestDenialResponse(t *testing.T) {
	var logs bytes.Buffer
	h := newHandler(t, pipeline.ModeBlock, 64<<10, &logs)
	w := serve(h, subrequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", ""))
	var event struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		t.Fatalf("event: %v: %s", err, logs.String())
	}
	if w.Code != 403 || w.Header().Get("X-Request-Id") == "" || w.Header().Get("X-Request-Id") != event.RequestID {
		t.Fatalf("denial: %d, X-Request-Id %q, event's %q", w.Code, w.Header().Get("X-Request-Id"), event.RequestID)
	}

	r := subrequest("GET", "/", "", "")
	r.Header.Del("X-Forwarded-Method")
	w = serve(h, r)
	if w.Code != 400 || w.Header().Get("X-Request-Id") == "" {
		t.Errorf("400: %d, X-Request-Id %q", w.Code, w.Header().Get("X-Request-Id"))
	}

	h.jsonDenials = true
	r = subrequest("GET", "/products?id=1%27%20OR%20%271%27%3D%271", "", "")
	r.Header.Set("Accept", "application/json")
	w = serve(h, r)
	if w.Code != 403 || w.Header().Get("Content-Type") != "application/json" ||
		w.Body.String() != `{"error":"forbidden","status":403,"request_id":"`+w.Header().Get("X-Request-Id")+`"}`+"\n" {
		t.Errorf("JSON denial: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}
