// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpadapter

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// TestLogEventCountry: a geo verdict's log line names the country and the
// requests its sampled event stands for; geo verdicts are events only when
// sampled.
func TestLogEventCountry(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	ru, _ := geo.ParseCountry("RU")
	r := &request.Request{Method: "GET", Headers: http.Header{}, Geo: request.Geo{Looked: true, Country: ru, Result: geo.ResultCountry}}
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonGeoDeny, SampledEvent: true, SampledCount: 3}
	LogEvent(context.Background(), logger, nil, r, "/", v)
	if out := buf.String(); !strings.Contains(out, `"country":"RU"`) || !strings.Contains(out, `"sampled_count":3`) {
		t.Errorf("log line: %s", out)
	}
	if !IsEvent(v) {
		t.Error("a sampled geo verdict isn't an event")
	}
	v.SampledEvent = false
	if IsEvent(v) {
		t.Error("an unsampled geo verdict is an event")
	}
}
