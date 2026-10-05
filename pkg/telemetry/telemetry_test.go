// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

type evaluator struct {
	res   rules.Result
	delay time.Duration
}

func (e evaluator) Evaluate(context.Context, *request.Request) (rules.Result, error) {
	time.Sleep(e.delay)
	return e.res, nil
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	b, _ := io.ReadAll(w.Body)
	return w.Code, string(b)
}

func TestMetricsRecordVerdicts(t *testing.T) {
	m := NewMetrics("proxy")
	p := pipeline.New(evaluator{res: rules.Result{Interrupted: true, Status: 403}}, pipeline.Config{
		Mode: pipeline.ModeBlock, Observer: m,
	})
	m.WatchPipeline(p)
	p.Check(context.Background(), &request.Request{})
	p.Check(context.Background(), &request.Request{})

	code, body := get(t, m.AdminHandler(nil), "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics returned %d", code)
	}
	for _, want := range []string{
		`inkwall_requests_total{action="deny",adapter="proxy",reason="rule"} 2`,
		`inkwall_check_duration_seconds_count{adapter="proxy"} 2`,
		`inkwall_evaluations_in_flight 0`,
		`inkwall_evaluation_slots `,
		`go_goroutines `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestMetricsCountShedRequests(t *testing.T) {
	m := NewMetrics("proxy")
	p := pipeline.New(evaluator{delay: 200 * time.Millisecond}, pipeline.Config{
		Timeout: 5 * time.Millisecond, MaxConcurrent: 1, Observer: m,
	})
	p.Check(context.Background(), &request.Request{}) // times out, keeps the slot
	p.Check(context.Background(), &request.Request{}) // shed

	_, body := get(t, m.AdminHandler(nil), "/metrics")
	for _, want := range []string{
		`inkwall_requests_total{action="allow",adapter="proxy",reason="timeout"} 1`,
		`inkwall_requests_total{action="allow",adapter="proxy",reason="overload"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestHealthEndpoints(t *testing.T) {
	m := NewMetrics("proxy")
	ready := false
	h := m.AdminHandler(func() bool { return ready })

	if code, _ := get(t, h, "/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, h, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before ready = %d, want 503", code)
	}
	ready = true
	if code, _ := get(t, h, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz when ready = %d, want 200", code)
	}
}
