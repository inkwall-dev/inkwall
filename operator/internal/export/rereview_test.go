// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Lowering maxInFlight below the requests in flight: the sender waits for
// answers without spinning, sends the rest within the new limit, and the
// cursor ends past everything.
func TestLowerMaxInFlightWithRequestsInFlight(t *testing.T) {
	release := make(chan struct{})
	var inFlight, most atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		<-release
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// Two events a request, two in flight: three events make one request
	// sent and one half built, which maxDelay would send.
	h := start(t, "", config(jsonSink("a", srv.URL, batch(2, 200*time.Millisecond), func(s *wafv1alpha1.EventSink) {
		s.Batch.MaxInFlight = new(int32(2))
	})))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("the first request in flight", func() bool { return inFlight.Load() == 1 })
	// Now one in flight is the limit: the half-built request must wait,
	// with maxDelay passed, and the timer not fire on every pass.
	h.set(func(s *wafv1alpha1.EventSink) { s.Batch.MaxInFlight = new(int32(1)) })
	time.Sleep(250 * time.Millisecond)
	s := h.exp.sinks["a"].sender
	before := s.loops.Load()
	time.Sleep(300 * time.Millisecond)
	if n := s.loops.Load() - before; n > 100 {
		t.Errorf("%d loop passes in 300ms at the in-flight limit: it spins", n)
	}
	if n := inFlight.Load(); n != 1 {
		t.Errorf("%d requests in flight with maxInFlight 1", n)
	}
	close(release)
	h.waitFor("all 3 exported", func() bool { return h.rec.get(h.rec.exported, "a") == 3 })
	if m := most.Load(); m > 1 {
		t.Errorf("%d requests at once", m)
	}
	h.waitFor("the cursor past the batch", func() bool { return h.exp.buf.Load().acked("a") == position{seq: 2} })
}

// A request that can't be encoded is dropped as rejected after one more
// try: never retried without a wait.
func TestRequestThatCantBeEncodedIsDropped(t *testing.T) {
	var mismatches atomic.Int32
	oldHook, oldMarshal := payloadMismatch, marshalOTLP
	payloadMismatch = func(string) { mismatches.Add(1) }
	marshalOTLP = func(proto.Message) ([]byte, error) { return nil, errors.New("forced") }
	t.Cleanup(func() { payloadMismatch, marshalOTLP = oldHook, oldMarshal })
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	h := start(t, "", config(wafv1alpha1.EventSink{Name: "a", Insecure: true, OTLP: &wafv1alpha1.OTLPSink{Endpoint: srv.URL + "/v1/logs"},
		Batch: wafv1alpha1.ExportBatch{MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}}}))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("dropped as rejected", func() bool { return h.rec.get(h.rec.dropped, "a/"+DropRejected) == 3 })
	time.Sleep(50 * time.Millisecond)
	if n := mismatches.Load(); n != 2 {
		t.Errorf("%d refused payloads, want 2: the request and its one re-encoding", n)
	}
	if calls.Load() != 0 || h.rec.get(h.rec.exported, "a") != 0 {
		t.Errorf("%d calls, %d exported for a request that never encoded", calls.Load(), h.rec.get(h.rec.exported, "a"))
	}
	h.waitFor("the cursor past it", func() bool { return h.status("a").Pending == 0 })
}
