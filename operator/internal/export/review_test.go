// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// A payload a client can't send is a programming error: fail loudly.
func init() {
	payloadMismatch = func(what string) { panic("export: " + what) }
}

// anySink records each POST as it came: JSON lines or OTLP protobuf. It
// answers 503 until open.
type anySink struct {
	srv    *httptest.Server
	open   atomic.Bool
	mu     sync.Mutex
	bodies []recorded
}

type recorded struct {
	contentType string
	body        []byte
}

func newAnySink(t *testing.T) *anySink {
	t.Helper()
	s := &anySink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.open.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, _ := gzip.NewReader(r.Body)
			body = zr
		}
		raw, _ := io.ReadAll(body)
		s.mu.Lock()
		s.bodies = append(s.bodies, recorded{r.Header.Get("Content-Type"), raw})
		s.mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *anySink) got() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.bodies...)
}

// otlpEvents decodes OTLP bodies' records' event IDs and attribute keys.
func otlpRecords(t *testing.T, raw []byte) (ids []string, keys map[string]bool) {
	t.Helper()
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(raw, &req); err != nil {
		t.Fatalf("not OTLP: %v", err)
	}
	keys = map[string]bool{}
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, r := range sl.GetLogRecords() {
				for _, kv := range r.GetAttributes() {
					keys[kv.GetKey()] = true
					if kv.GetKey() == "inkwall.event_id" {
						ids = append(ids, kv.GetValue().GetStringValue())
					}
				}
			}
		}
	}
	return ids, keys
}

func (h *harness) set(mutate func(*wafv1alpha1.EventSink)) {
	h.t.Helper()
	h.update(func(c *wafv1alpha1.InkwallConfig) { mutate(&c.Spec.Events.Export.Sinks[0]) })
}

// toOTLPNarrowed changes a JSON sink to OTLP over HTTP, leaving out client
// IPs and taking only shop's policies.
func toOTLPNarrowed(url string) func(*wafv1alpha1.EventSink) {
	return func(s *wafv1alpha1.EventSink) {
		s.JSON, s.OTLP = nil, &wafv1alpha1.OTLPSink{Endpoint: url}
		s.Omit = []wafv1alpha1.ExportOmit{wafv1alpha1.OmitClientIP}
		s.Filter.PolicyNamespaces = []wafv1alpha1.NamespaceName{"shop"}
	}
}

func checkNarrowed(t *testing.T, got []recorded) {
	t.Helper()
	if len(got) == 0 {
		t.Fatal("nothing delivered")
	}
	var ids []string
	for _, r := range got {
		if r.contentType != "application/x-protobuf" {
			t.Fatalf("a request as %s after the sink became OTLP: %.200s", r.contentType, r.body)
		}
		got, keys := otlpRecords(t, r.body)
		if keys["client.address"] {
			t.Error("a client IP sent after omit: [ClientIP]")
		}
		ids = append(ids, got...)
	}
	// rateLimited's policy, payments/web, isn't in the bundle: it has no
	// policy, so a policyNamespaces sink never takes it.
	if strings.Join(ids, ",") != fullEvent().GetEventId() {
		t.Errorf("delivered %v, want only shop/web's %s", ids, fullEvent().GetEventId())
	}
}

// A request waiting for a retry when its sink changes is filtered and
// encoded again under the new configuration: format, omit and filters.
func TestChangedSinkReencodesRequestsInFlight(t *testing.T) {
	sk := newAnySink(t)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(10, 10*time.Millisecond))))
	h.exp.Add(&eventsv1.EventBatch{Events: []*eventsv1.SecurityEvent{fullEvent(), rateLimited()}})
	h.waitFor("a failure", func() bool { return h.rec.get(h.rec.failed, "a/"+kindServer) > 0 })
	h.set(toOTLPNarrowed(sk.srv.URL))
	time.Sleep(100 * time.Millisecond)
	sk.open.Store(true)
	h.waitFor("the request", func() bool { return h.status("a").Pending == 0 && len(sk.got()) > 0 })
	checkNarrowed(t, sk.got())
}

// A request half built when its sink changes is sent at once under the
// new configuration.
func TestChangedSinkReencodesAHalfBuiltRequest(t *testing.T) {
	sk := newAnySink(t)
	sk.open.Store(true)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1000, time.Minute))))
	h.exp.Add(&eventsv1.EventBatch{Events: []*eventsv1.SecurityEvent{fullEvent(), rateLimited()}})
	time.Sleep(100 * time.Millisecond)
	if len(sk.got()) != 0 {
		t.Fatal("sent before maxDelay")
	}
	h.set(toOTLPNarrowed(sk.srv.URL))
	h.waitFor("the request", func() bool { return len(sk.got()) > 0 && h.status("a").Pending == 0 })
	checkNarrowed(t, sk.got())
}

// From JSON to OTLP over gRPC with a request waiting: the Collector gets
// the events, never an empty request.
func TestChangedSinkJSONToGRPC(t *testing.T) {
	sk := newAnySink(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &logsServer{}
	srv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(10, 10*time.Millisecond))))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("a failure", func() bool { return h.rec.get(h.rec.failed, "a/"+kindServer) > 0 })
	h.set(func(s *wafv1alpha1.EventSink) {
		s.JSON, s.OTLP = nil, &wafv1alpha1.OTLPSink{Endpoint: "grpc://" + lis.Addr().String()}
	})
	h.waitFor("3 records over gRPC", func() bool { return ls.records() == 3 })
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, r := range ls.requests {
		if len(r.GetResourceLogs()) == 0 {
			t.Error("an empty ExportLogsServiceRequest")
		}
	}
}

// A sink whose configuration can't start, with a request half built,
// waits: it doesn't spin, and Stop doesn't wait for it.
func TestInvalidSinkDoesNotSpin(t *testing.T) {
	sk, _, ca := tlsSink(t)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1000, time.Minute), func(s *wafv1alpha1.EventSink) {
		s.Insecure = false
		s.HeadersSecretRef = &wafv1alpha1.LocalSecretReference{Name: "h"}
		s.TLS = &wafv1alpha1.SinkTLS{CASecretRef: &wafv1alpha1.LocalSecretReference{Name: "ca"}}
	})), secretObj("h", map[string]string{"Authorization": "Bearer t"}), secretObj("ca", map[string]string{"ca.crt": ca}))
	h.exp.Add(batchOf(3, numbered("e")))
	time.Sleep(50 * time.Millisecond)
	if err := h.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "h"}}); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the sink invalid", func() bool { return h.status("a").State == StateConfigInvalid })
	h.exp.FlushTimeout = 10 * time.Second
	s := h.exp.sinks["a"].sender
	before := s.loops.Load()
	time.Sleep(300 * time.Millisecond)
	// The test polls the configuration every 20 ms, each a pass or two; a
	// spin makes thousands.
	if n := s.loops.Load() - before; n > 100 {
		t.Errorf("%d loop passes in 300ms with the sink invalid: it spins", n)
	}
	t0 := time.Now()
	h.exp.Stop()
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("Stop took %v for a sink that can't send", d)
	}
}

// Requests answered out of order: the cursor moves only past a run of
// answered ones at the head.
func TestCursorWithThreeRequestsInFlight(t *testing.T) {
	gates := map[string]chan struct{}{"e000a0": make(chan struct{}), "e000b1": make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, _ := gzip.NewReader(r.Body)
		body, _ := io.ReadAll(zr)
		for id, g := range gates {
			if bytes.Contains(body, []byte(`"event_id":"`+id+`"`)) {
				<-g
			}
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	h := start(t, "", config(jsonSink("a", srv.URL, batch(1, time.Second), func(s *wafv1alpha1.EventSink) {
		s.Batch.MaxInFlight = new(int32(4))
	})))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("the third answered", func() bool { return h.rec.get(h.rec.exported, "a") == 1 })
	acked := func() position { return h.exp.buf.Load().acked("a") }
	if p := acked(); p != (position{seq: 1}) {
		t.Errorf("cursor %+v with the first two unanswered", p)
	}
	close(gates["e000b1"])
	h.waitFor("the second answered", func() bool { return h.rec.get(h.rec.exported, "a") == 2 })
	time.Sleep(30 * time.Millisecond)
	if p := acked(); p != (position{seq: 1}) {
		t.Errorf("cursor %+v with the first unanswered", p)
	}
	close(gates["e000a0"])
	h.waitFor("the cursor past all three", func() bool { return acked() == position{seq: 2} })
}

// Removing a sink with requests in flight stops it, and its status and
// metrics go.
func TestRemoveSinkWithRequestsInFlight(t *testing.T) {
	sk := newSink(t)
	sk.block = make(chan struct{})
	defer close(sk.block)
	other := newSink(t)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1, time.Second)), jsonSink("b", other.srv.URL, batch(1, time.Second))))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("b's events", func() bool { return len(other.events()) == 3 })
	h.update(func(c *wafv1alpha1.InkwallConfig) { c.Spec.Events.Export.Sinks = c.Spec.Events.Export.Sinks[1:] })
	h.waitFor("a gone", func() bool { return len(h.exp.Status()) == 1 && h.status("b").Name == "b" })
	h.exp.Add(batchOf(2, numbered("f")))
	h.waitFor("b goes on", func() bool { return len(other.events()) == 5 })
	h.waitFor("the buffer freed", func() bool { _, all := h.exp.buf.Load().bytes(); return all == 0 })
}

// gRPC RESOURCE_EXHAUSTED without RetryInfo on a request over 1 MiB:
// halved until it fits.
func TestGRPCResourceExhaustedSplits(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &sizeLimited{limit: 1 << 20}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(16 << 20))
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(wafv1alpha1.EventSink{
		Name: "otel", Insecure: true, OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpc://" + lis.Addr().String()},
		Batch: wafv1alpha1.ExportBatch{MaxEvents: new(int32(300)), MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}},
	}))
	h.exp.Add(batchOf(300, bigEvent))
	h.waitFor("300 records", func() bool { return h.rec.get(h.rec.exported, "otel") == 300 })
	if ls.refused.Load() == 0 {
		t.Error("no request was over the limit: the test proves nothing")
	}
}

// grpc-go's own refusal of a request over the server's limit reads like
// the client's error for an answer over its limit: it is split, never
// taken as sent.
func TestGRPCServerLimitSplits(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &logsServer{}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(1 << 20))
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(wafv1alpha1.EventSink{
		Name: "otel", Insecure: true, OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpc://" + lis.Addr().String()},
		Batch: wafv1alpha1.ExportBatch{MaxEvents: new(int32(300)), MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}},
	}))
	h.exp.Add(batchOf(300, bigEvent))
	h.waitFor("300 records at the server", func() bool { return ls.records() == 300 })
	ls.mu.Lock()
	n := len(ls.requests)
	ls.mu.Unlock()
	if n < 2 {
		t.Errorf("%d requests: not split", n)
	}
}

type sizeLimited struct {
	collogspb.UnimplementedLogsServiceServer
	limit   int
	refused atomic.Int32
}

func (s *sizeLimited) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if proto.Size(req) > s.limit {
		s.refused.Add(1)
		return nil, status.Error(codes.ResourceExhausted, "message too large")
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

// A response over the client's limit, after the server took the request,
// is a success: retrying it would send the events again.
func TestGRPCResponseOverLimitIsSent(t *testing.T) {
	old := maxGRPCResponse
	maxGRPCResponse = 1<<10 + 3
	t.Cleanup(func() { maxGRPCResponse = old })
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &bigAnswer{}
	srv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(wafv1alpha1.EventSink{
		Name: "otel", Insecure: true, OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpc://" + lis.Addr().String()},
		Batch: wafv1alpha1.ExportBatch{MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}},
	}))
	h.exp.Add(batchOf(2, numbered("e")))
	h.waitFor("exported", func() bool { return h.rec.get(h.rec.exported, "otel") == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := ls.calls.Load(); n != 1 {
		t.Errorf("%d calls: a request the server took was sent again", n)
	}
}

type bigAnswer struct {
	collogspb.UnimplementedLogsServiceServer
	calls atomic.Int32
}

func (s *bigAnswer) Export(context.Context, *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	s.calls.Add(1)
	return &collogspb.ExportLogsServiceResponse{PartialSuccess: &collogspb.ExportLogsPartialSuccess{ErrorMessage: strings.Repeat("x", 4<<10)}}, nil
}

// Header keys that are one header, whatever their case, are refused.
func TestHeaderKeysThatCollide(t *testing.T) {
	h := start(t, "", config(jsonSink("a", "https://x.example", func(s *wafv1alpha1.EventSink) {
		s.Insecure, s.HeadersSecretRef = false, &wafv1alpha1.LocalSecretReference{Name: "h"}
	})), secretObj("h", map[string]string{"Authorization": "a", "authorization": "b"}))
	h.waitFor("invalid", func() bool { return h.status("a").State == StateConfigInvalid })
	if m := h.status("a").Message; !strings.Contains(m, "are the same header") {
		t.Errorf("message %q", m)
	}
}

// An object written before the CRD's bound: only the first 4 sinks run.
func TestAtMostFourSinks(t *testing.T) {
	var sinks []wafv1alpha1.EventSink
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		sinks = append(sinks, jsonSink(n, "https://x.example"))
	}
	spec := &wafv1alpha1.ExportSpec{Sinks: sinks}
	if got := resolve(context.Background(), nil, ns, "uid", spec); len(got) != 4 {
		t.Errorf("%d sinks resolved", len(got))
	}
}
