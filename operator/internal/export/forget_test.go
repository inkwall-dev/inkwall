// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"sync"
	"testing"
	"time"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// afterForget records any call for a sink after its Forget: it would bring
// a removed sink's series back.
type afterForget struct {
	*recorder
	mu        sync.Mutex
	forgotten map[string]bool
	late      []string
}

func (m *afterForget) check(sink, what string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.forgotten[sink] {
		m.late = append(m.late, what)
	}
}

func (m *afterForget) Forget(sink string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forgotten[sink] = true
}

func (m *afterForget) Exported(s string, n int)           { m.check(s, "Exported"); m.recorder.Exported(s, n) }
func (m *afterForget) Dropped(s, r string, n int)         { m.check(s, "Dropped"); m.recorder.Dropped(s, r, n) }
func (m *afterForget) Failed(s, k string)                 { m.check(s, "Failed"); m.recorder.Failed(s, k) }
func (m *afterForget) Duration(s string, _ time.Duration) { m.check(s, "Duration") }
func (m *afterForget) Succeeded(s string, _ time.Time)    { m.check(s, "Succeeded") }
func (m *afterForget) Pending(s string, _ uint64)         { m.check(s, "Pending") }

// A sink removed with requests in flight, and retrying: nothing counts for
// it after its metrics are forgotten.
func TestRemovedSinkCountsNothingAfterForget(t *testing.T) {
	sk := newSink(t)
	sk.answer = func(int) int { return 503 }
	var m *afterForget
	wrapMetrics = func(rec *recorder) Metrics {
		m = &afterForget{recorder: rec, forgotten: map[string]bool{}}
		return m
	}
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1, 10*time.Millisecond), func(s *wafv1alpha1.EventSink) {
		s.Batch.MaxInFlight = new(int32(4))
	})))
	wrapMetrics = nil
	h.exp.Add(batchOf(4, numbered("e")))
	h.waitFor("failures", func() bool { return h.rec.get(h.rec.failed, "a/"+kindServer) >= 4 })
	h.update(func(c *wafv1alpha1.InkwallConfig) { c.Spec.Events.Export = nil })
	h.waitFor("the sink removed", func() bool { return len(h.exp.Status()) == 0 })
	time.Sleep(200 * time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.forgotten["a"] || len(m.late) > 0 {
		t.Errorf("forgotten %t; calls after Forget: %v", m.forgotten["a"], m.late)
	}
}
