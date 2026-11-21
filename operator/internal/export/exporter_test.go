// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

const ns = "inkwall-system"

// recorder counts what the exporter reports.
type recorder struct {
	mu       sync.Mutex
	exported map[string]int
	dropped  map[string]int // sink/reason
	failed   map[string]int // sink/kind
	waits    []time.Duration
}

func newRecorder() *recorder {
	return &recorder{exported: map[string]int{}, dropped: map[string]int{}, failed: map[string]int{}}
}

func (r *recorder) Exported(s string, n int)     { r.mu.Lock(); r.exported[s] += n; r.mu.Unlock() }
func (r *recorder) Dropped(s, w string, n int)   { r.mu.Lock(); r.dropped[s+"/"+w] += n; r.mu.Unlock() }
func (r *recorder) Failed(s, k string)           { r.mu.Lock(); r.failed[s+"/"+k]++; r.mu.Unlock() }
func (*recorder) Duration(string, time.Duration) {}
func (*recorder) Succeeded(string, time.Time)    {}
func (*recorder) Pending(string, uint64)         {}
func (*recorder) BufferBytes(int64)              {}
func (*recorder) Forget(string)                  {}
func (*recorder) Start(string)                   {}

func (r *recorder) get(m map[string]int, k string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return m[k]
}

// after records the waits before retries (the backoff, Retry-After, the
// slow retry of an auth failure), and shortens them a thousandfold.
func (r *recorder) after(d time.Duration) <-chan time.Time {
	r.mu.Lock()
	r.waits = append(r.waits, d)
	r.mu.Unlock()
	return time.After(d / 1000)
}

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wafv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func config(sinks ...wafv1alpha1.EventSink) *wafv1alpha1.InkwallConfig {
	return &wafv1alpha1.InkwallConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       wafv1alpha1.InkwallConfigSpec{Events: wafv1alpha1.EventsSpec{Export: &wafv1alpha1.ExportSpec{ClusterName: "kind", Sinks: sinks}}},
	}
}

type harness struct {
	t   *testing.T
	c   client.Client
	exp *Exporter
	rec *recorder
}

func start(t *testing.T, dir string, objs ...client.Object) *harness {
	t.Helper()
	allowLoopback(t)
	kube := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "6f1c0d2e-uid"}}
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(append(objs, kube)...).Build()
	rec := newRecorder()
	exp := &Exporter{
		Client: c, APIReader: c, Namespace: ns, Dir: dir, Poll: 20 * time.Millisecond, FlushTimeout: 2 * time.Second,
		HasPolicy: inBundle, Metrics: rec, Log: testr.New(t), after: rec.after,
	}
	if err := exp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exp.Stop)
	h := &harness{t: t, c: c, exp: exp, rec: rec}
	h.waitFor("the sinks to start", func() bool {
		cfg := &wafv1alpha1.InkwallConfig{}
		if c.Get(context.Background(), types.NamespacedName{Name: "default"}, cfg) != nil || cfg.Spec.Events.Export == nil {
			return true
		}
		return len(exp.Status()) == len(cfg.Spec.Events.Export.Sinks)
	})
	return h
}

func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *harness) update(mutate func(*wafv1alpha1.InkwallConfig)) {
	h.t.Helper()
	cfg := &wafv1alpha1.InkwallConfig{}
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: "default"}, cfg); err != nil {
		h.t.Fatal(err)
	}
	mutate(cfg)
	if err := h.c.Update(context.Background(), cfg); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) status(name string) SinkStatus {
	for _, s := range h.exp.Status() {
		if s.Name == name {
			return s
		}
	}
	return SinkStatus{}
}

// sink is a JSON intake that records each request's events.
type sink struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests [][]map[string]any
	headers  []http.Header
	// answer, when set, decides the status of a request with n events.
	answer func(n int) int
	block  chan struct{}
}

func newSink(t *testing.T) *sink {
	t.Helper()
	s := &sink{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sink) serve(w http.ResponseWriter, r *http.Request) {
	if s.block != nil {
		select {
		case <-s.block:
		case <-r.Context().Done():
			return
		}
	}
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		body = zr
	}
	raw, _ := io.ReadAll(body)
	var evs []map[string]any
	if r.Header.Get("Content-Type") == "application/json" {
		_ = json.Unmarshal(raw, &evs)
	} else {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var ev map[string]any
			_ = json.Unmarshal(sc.Bytes(), &ev)
			evs = append(evs, ev)
		}
	}
	code := 200
	if s.answer != nil {
		code = s.answer(len(evs))
	}
	if code == 200 {
		s.mu.Lock()
		s.requests = append(s.requests, evs)
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
	}
	w.WriteHeader(code)
}

func (s *sink) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, r := range s.requests {
		out = append(out, r...)
	}
	return out
}

func (s *sink) sizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for _, r := range s.requests {
		out = append(out, len(r))
	}
	return out
}

func jsonSink(name, url string, mutate ...func(*wafv1alpha1.EventSink)) wafv1alpha1.EventSink {
	s := wafv1alpha1.EventSink{Name: name, JSON: &wafv1alpha1.JSONSink{URL: url}, Insecure: true}
	for _, m := range mutate {
		m(&s)
	}
	return s
}

func batch(n int, delay time.Duration) func(*wafv1alpha1.EventSink) {
	return func(s *wafv1alpha1.EventSink) {
		s.Batch.MaxEvents = new(int32(n))
		s.Batch.MaxDelay = &metav1.Duration{Duration: delay}
	}
}

func TestExportBatchesBySizeAndDelay(t *testing.T) {
	sk := newSink(t)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(3, 150*time.Millisecond))))
	h.exp.Add(batchOf(7, numbered("e")))
	h.waitFor("7 events", func() bool { return len(sk.events()) == 7 })
	if got := sk.sizes(); len(got) != 3 || got[0] != 3 || got[1] != 3 || got[2] != 1 {
		t.Errorf("requests of %v, want 3, 3 and the last 1 after maxDelay", got)
	}
	ev := sk.events()[0]
	if ev["schema"] != SchemaName || ev["cluster"].(map[string]any)["id"] != "6f1c0d2e-uid" || ev["cluster"].(map[string]any)["name"] != "kind" {
		t.Errorf("event %v", ev)
	}
	h.waitFor("the cursor past them", func() bool { return h.status("a").Pending == 0 })
	if h.rec.get(h.rec.exported, "a") != 7 {
		t.Errorf("exported %d", h.rec.get(h.rec.exported, "a"))
	}
	if st := h.status("a"); st.State != StateExporting || !st.Plaintext {
		t.Errorf("status %+v", st)
	}
}

// Filtered events advance the cursor like sent ones; a policy the bundle
// doesn't have counts as none, so an engine can't reach a team's SIEM by
// naming its policy.
func TestExportFilters(t *testing.T) {
	denies, shop, all := newSink(t), newSink(t), newSink(t)
	h := start(t, "", config(
		jsonSink("denies", denies.srv.URL, batch(100, 100*time.Millisecond), func(s *wafv1alpha1.EventSink) {
			s.Filter.Actions = []wafv1alpha1.ExportAction{wafv1alpha1.ExportDeny}
		}),
		jsonSink("payments", shop.srv.URL, batch(100, 100*time.Millisecond), func(s *wafv1alpha1.EventSink) {
			s.Filter.PolicyNamespaces = []wafv1alpha1.NamespaceName{"payments", "shop"}
		}),
		jsonSink("all", all.srv.URL, batch(100, 100*time.Millisecond)),
	))
	h.exp.Add(&eventsv1.EventBatch{Events: []*eventsv1.SecurityEvent{fullEvent(), oldEvent(), rateLimited()}})
	h.waitFor("every sink", func() bool { return len(all.events()) == 3 && len(denies.events()) == 2 && len(shop.events()) == 1 })
	if got := shop.events()[0]["event_id"]; got != fullEvent().GetEventId() {
		t.Errorf("the namespace filter took %v, want only the event of shop/web (payments/web isn't in the bundle)", got)
	}
	for _, ev := range denies.events() {
		if ev["action"] != "deny" {
			t.Errorf("the Deny sink took %v", ev["action"])
		}
	}
	// Only Log events: nothing to send, and the cursor moves anyway.
	h.exp.Add(&eventsv1.EventBatch{Events: []*eventsv1.SecurityEvent{oldEvent(), oldEvent()}})
	h.waitFor("the filtered events passed", func() bool { return h.status("denies").Pending == 0 && h.status("payments").Pending == 0 })
	if len(denies.events()) != 2 {
		t.Errorf("the Deny sink took %d events", len(denies.events()))
	}
	h.waitFor("the batches freed", func() bool { _, all := h.exp.buf.Load().bytes(); return all == 0 })
}

// Requests may be answered out of order; the cursor moves only past a run
// of answered ones, in order.
func TestExportCursorOnlyPastAnsweredRequests(t *testing.T) {
	var first atomic.Bool
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		zr, _ := gzip.NewReader(bytes.NewReader(raw))
		body, _ := io.ReadAll(zr)
		if strings.Contains(string(body), `"event_id":"e000a0"`) && first.CompareAndSwap(false, true) {
			<-release
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	h := start(t, "", config(jsonSink("a", srv.URL, batch(1, time.Second), func(s *wafv1alpha1.EventSink) {
		s.Batch.MaxInFlight = new(int32(2))
	})))
	h.exp.Add(batchOf(2, numbered("e")))
	h.waitFor("the second answered", func() bool { return h.rec.get(h.rec.exported, "a") == 1 })
	time.Sleep(50 * time.Millisecond)
	if p := h.exp.buf.Load().acked("a"); p != (position{seq: 1}) {
		t.Errorf("cursor at %+v with the first request unanswered, want {1 0}", p)
	}
	close(release)
	h.waitFor("the cursor past both", func() bool { return h.exp.buf.Load().acked("a") == position{seq: 2} })
}

// 413: halved until it fits; a single event refused is dropped.
func TestExportHalvesOn413(t *testing.T) {
	sk := newSink(t)
	sk.answer = func(n int) int {
		if n > 2 {
			return http.StatusRequestEntityTooLarge
		}
		return 200
	}
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(7, 50*time.Millisecond))))
	h.exp.Add(batchOf(7, numbered("e")))
	h.waitFor("7 events in halves", func() bool { return len(sk.events()) == 7 })
	for _, n := range sk.sizes() {
		if n > 2 {
			t.Errorf("a request of %d events got through", n)
		}
	}
	sk.answer = func(int) int { return http.StatusRequestEntityTooLarge }
	h.exp.Add(batchOf(2, numbered("f")))
	h.waitFor("too large dropped", func() bool { return h.rec.get(h.rec.dropped, "a/"+DropTooLarge) == 2 })
}

func TestExportRetries(t *testing.T) {
	var calls atomic.Int32
	codes := []int{503, 429, 401, 500, 200}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := int(calls.Add(1)) - 1
		if i < len(codes) && codes[i] == 429 {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(codes[min(i, len(codes)-1)])
	}))
	defer srv.Close()
	h := start(t, "", config(jsonSink("a", srv.URL, batch(10, 50*time.Millisecond))))
	h.exp.Add(batchOf(3, numbered("e")))
	h.waitFor("the events through after four failures", func() bool { return h.rec.get(h.rec.exported, "a") == 3 })
	h.rec.mu.Lock()
	waits := append([]time.Duration(nil), h.rec.waits...)
	h.rec.mu.Unlock()
	// 503: backoff; 429: Retry-After; 401: the slowest pace; 500 (json): backoff.
	// Full jitter: the first under minBackoff, the auth failure's under
	// maxBackoff, Retry-After as given.
	if len(waits) < 4 || waits[0] > minBackoff || waits[0] < minBackoff/10 || waits[1] != 7*time.Second ||
		waits[2] > maxBackoff || waits[2] < minBackoff/10 || waits[3] > 8*minBackoff {
		t.Errorf("waits %v, want a jittered backoff under %v, 7s, a jittered wait under %v, a backoff", waits, minBackoff, maxBackoff)
	}
	for range 200 {
		if d := backoff(0); d > minBackoff || d < minBackoff/10 {
			t.Fatalf("backoff(0) = %v", d)
		}
		if d := backoff(10); d > maxBackoff {
			t.Fatalf("backoff(10) = %v", d)
		}
	}
	for _, k := range []string{"a/" + kindServer, "a/" + kindThrottled, "a/" + kindAuth} {
		if h.rec.get(h.rec.failed, k) == 0 {
			t.Errorf("no failure %s counted", k)
		}
	}
	if st := h.status("a"); st.State != StateExporting || st.LastSuccess.IsZero() {
		t.Errorf("status %+v", st)
	}
	// A 400 is refused for good.
	codes = nil
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) })
	h.exp.Add(batchOf(2, numbered("f")))
	h.waitFor("rejected", func() bool { return h.rec.get(h.rec.dropped, "a/"+DropRejected) == 2 })
}

// A sink that never answers doesn't slow Add: engines' streams never wait
// for a SIEM.
func TestAddNeverBlocks(t *testing.T) {
	sk := newSink(t)
	sk.block = make(chan struct{})
	defer close(sk.block)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1000, 100*time.Millisecond))))
	h.exp.MemoryBytes = 1 << 20
	b := batchOf(100, numbered("e"))
	var slowest time.Duration
	for range 2000 {
		t0 := time.Now()
		h.exp.Add(b)
		slowest = max(slowest, time.Since(t0))
	}
	if slowest > 100*time.Millisecond {
		t.Errorf("the slowest Add took %v", slowest)
	}
	if _, all := h.exp.buf.Load().bytes(); all > DefaultBufferBytes {
		t.Errorf("buffer at %d bytes, over its bound", all)
	}
	h.waitFor("drops counted", func() bool { return h.rec.get(h.rec.dropped, "a/"+DropBufferFull) > 0 })
}

// A request retried while the buffer drops its batch is abandoned and
// counted as dropped: retries last as long as the buffer holds the batch.
func TestExportAbandonsDroppedRequests(t *testing.T) {
	sk := newSink(t)
	sk.answer = func(int) int { return 503 }
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(10, 20*time.Millisecond))))
	size := batchSize(10)
	h.exp.buf.Load().mu.Lock()
	h.exp.buf.Load().memMax = 3 * size
	h.exp.buf.Load().mu.Unlock()
	h.exp.Add(batchOf(10, numbered("a")))
	h.waitFor("a failure", func() bool { return h.rec.get(h.rec.failed, "a/"+kindServer) > 0 })
	for range 8 {
		h.exp.Add(batchOf(10, numbered("b")))
	}
	h.waitFor("the abandoned request dropped", func() bool { return h.rec.get(h.rec.dropped, "a/"+DropBufferFull) >= 10 })
	if st := h.status("a"); st.State != StateDropping {
		t.Errorf("state %s, want Dropping (it hasn't failed for 5 minutes yet)", st.State)
	}
}

// Stop sends what is buffered at once, without waiting for maxDelay, and
// nothing is added after it.
func TestStopFlushes(t *testing.T) {
	sk := newSink(t)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1000, time.Minute))))
	h.exp.Add(batchOf(5, numbered("e")))
	time.Sleep(50 * time.Millisecond)
	if len(sk.events()) != 0 {
		t.Fatal("sent before maxDelay")
	}
	h.exp.Stop()
	if len(sk.events()) != 5 {
		t.Errorf("%d events sent by the flush, want 5", len(sk.events()))
	}
	h.exp.Add(batchOf(5, numbered("f")))
	if _, all := h.exp.buf.Load().bytes(); all != 0 {
		t.Error("Add took a batch after Stop")
	}
}

// The flush has a deadline; what is left stays on disk, and is sent after
// a restart.
func TestStopFlushDeadline(t *testing.T) {
	dir := t.TempDir()
	sk := newSink(t)
	sk.block = make(chan struct{})
	h := start(t, dir, config(jsonSink("a", sk.srv.URL, batch(1000, 10*time.Millisecond))))
	h.exp.FlushTimeout = 200 * time.Millisecond
	h.exp.Add(batchOf(5, numbered("e")))
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	h.exp.Stop()
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("Stop took %v with a flush deadline of 200ms", d)
	}
	close(sk.block)
	// Restarted: the unanswered request is sent again.
	h2 := start(t, dir, config(jsonSink("a", sk.srv.URL, batch(1000, 10*time.Millisecond))))
	h2.waitFor("the events resent after the restart", func() bool { return len(sk.events()) >= 5 })
}

func secretObj(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

// tlsSink is a JSON intake over TLS that counts its connections.
func tlsSink(t *testing.T) (*sink, *atomic.Int32, string) {
	t.Helper()
	s := &sink{}
	var conns atomic.Int32
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}))
	return s, &conns, ca
}

// Headers come from a Secret, and a changed one is used without a restart;
// a changed CA rebuilds the transport, so the next request makes a new TLS
// handshake.
func TestExportSecretsAndRotation(t *testing.T) {
	sk, conns, ca := tlsSink(t)
	tlsCfg := func(s *wafv1alpha1.EventSink) {
		s.Insecure = false
		s.HeadersSecretRef = &wafv1alpha1.LocalSecretReference{Name: "hec"}
		s.TLS = &wafv1alpha1.SinkTLS{CASecretRef: &wafv1alpha1.LocalSecretReference{Name: "ca"}}
	}
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1, 10*time.Millisecond), tlsCfg)),
		secretObj("hec", map[string]string{"Authorization": "Splunk token-1", "X-Splunk-Request-Channel": "c1"}),
		secretObj("ca", map[string]string{"ca.crt": ca}))
	h.exp.Add(batchOf(1, numbered("e")))
	h.waitFor("the first event", func() bool { return len(sk.events()) == 1 })
	if got := sk.headers[0].Get("Authorization"); got != "Splunk token-1" || sk.headers[0].Get("X-Splunk-Request-Channel") != "c1" {
		t.Errorf("Authorization %q", got)
	}
	if st := h.status("a"); st.Plaintext {
		t.Error("a TLS sink reported plaintext")
	}

	var hec corev1.Secret
	_ = h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "hec"}, &hec)
	hec.Data["Authorization"] = []byte("Splunk token-2")
	if err := h.c.Update(context.Background(), &hec); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	h.exp.Add(batchOf(1, numbered("f")))
	h.waitFor("the second event", func() bool { return len(sk.events()) == 2 })
	if got := sk.headers[1].Get("Authorization"); got != "Splunk token-2" {
		t.Errorf("Authorization %q after the rotation, want token-2", got)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("%d connections, want 1: a header change keeps the transport", n)
	}

	var caSecret corev1.Secret
	_ = h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "ca"}, &caSecret)
	caSecret.Data["ca.crt"] = []byte(ca + ca) // the same CA, twice: new material all the same
	if err := h.c.Update(context.Background(), &caSecret); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	h.exp.Add(batchOf(1, numbered("g")))
	h.waitFor("the third event", func() bool { return len(sk.events()) == 3 })
	if n := conns.Load(); n != 2 {
		t.Errorf("%d connections, want 2: a changed CA makes a new handshake", n)
	}
}

func TestExportConfigInvalid(t *testing.T) {
	sk := newSink(t)
	for _, tc := range []struct {
		name    string
		sink    wafv1alpha1.EventSink
		secrets []client.Object
		want    string
	}{
		{"missing Secret", jsonSink("a", "https://x.example", func(s *wafv1alpha1.EventSink) {
			s.Insecure, s.HeadersSecretRef = false, &wafv1alpha1.LocalSecretReference{Name: "nope"}
		}), nil, "the Secret nope doesn't exist"},
		{"refused header", jsonSink("a", "https://x.example", func(s *wafv1alpha1.EventSink) {
			s.Insecure, s.HeadersSecretRef = false, &wafv1alpha1.LocalSecretReference{Name: "h"}
		}), []client.Object{secretObj("h", map[string]string{"Host": "evil", "Authorization": "Bearer hunter2"})}, `header "Host" refused`},
		{"CA not PEM", jsonSink("a", "https://x.example", func(s *wafv1alpha1.EventSink) {
			s.Insecure, s.TLS = false, &wafv1alpha1.SinkTLS{CASecretRef: &wafv1alpha1.LocalSecretReference{Name: "ca"}}
		}), []client.Object{secretObj("ca", map[string]string{"ca.crt": "nope"})}, "holds no PEM certificate"},
		{"client certificate without key", jsonSink("a", "https://x.example", func(s *wafv1alpha1.EventSink) {
			s.Insecure, s.TLS = false, &wafv1alpha1.SinkTLS{ClientCertificateSecretRef: &wafv1alpha1.LocalSecretReference{Name: "cc"}}
		}), []client.Object{secretObj("cc", map[string]string{"tls.crt": "x"})}, "doesn't hold a client certificate"},
		{"URL Secret with user info", wafv1alpha1.EventSink{Name: "a", JSON: &wafv1alpha1.JSONSink{URLSecretRef: &wafv1alpha1.SecretKeyReference{Name: "u", Key: "url"}}},
			[]client.Object{secretObj("u", map[string]string{"url": "https://user:hunter2@x.example/in"})}, "isn't an https:// or http:// URL"},
		{"URL Secret plaintext, even with insecure", wafv1alpha1.EventSink{Name: "a", Insecure: true, JSON: &wafv1alpha1.JSONSink{URLSecretRef: &wafv1alpha1.SecretKeyReference{Name: "u", Key: "url"}}},
			[]client.Object{secretObj("u", map[string]string{"url": sk.srv.URL + "/hunter2"})}, "is plaintext (http://)"},
		{"URL Secret without the key", wafv1alpha1.EventSink{Name: "a", JSON: &wafv1alpha1.JSONSink{URLSecretRef: &wafv1alpha1.SecretKeyReference{Name: "u", Key: "url"}}},
			[]client.Object{secretObj("u", map[string]string{"other": "x"})}, "has no key url"},
		{"gRPC without a port", wafv1alpha1.EventSink{Name: "a", OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpcs://collector"}}, nil, "needs a port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := start(t, "", append(tc.secrets, config(tc.sink))...)
			h.waitFor("the state", func() bool { return h.status("a").State == StateConfigInvalid })
			st := h.status("a")
			if !strings.Contains(st.Message, tc.want) || strings.Contains(st.Message, "hunter2") {
				t.Errorf("message %q, want %q and no secret", st.Message, tc.want)
			}
		})
	}
}

// The URL from a Secret is used, and a sink that can't start leaves the
// others alone.
func TestExportURLSecret(t *testing.T) {
	sk, _, ca := tlsSink(t)
	h := start(t, "", config(
		wafv1alpha1.EventSink{Name: "sumo", JSON: &wafv1alpha1.JSONSink{URLSecretRef: &wafv1alpha1.SecretKeyReference{Name: "u", Key: "url"}, Framing: wafv1alpha1.JSONArray},
			TLS:   &wafv1alpha1.SinkTLS{CASecretRef: &wafv1alpha1.LocalSecretReference{Name: "ca"}},
			Batch: wafv1alpha1.ExportBatch{MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}}},
		jsonSink("broken", "http://x", func(s *wafv1alpha1.EventSink) { s.TLS = nil; s.Insecure = false }),
	), secretObj("u", map[string]string{"url": sk.srv.URL + "/receiver/v1/http/TOKEN\n"}), secretObj("ca", map[string]string{"ca.crt": ca}))
	h.exp.Add(batchOf(2, numbered("e")))
	h.waitFor("the events", func() bool { return len(sk.events()) == 2 })
	if st := h.status("broken"); st.State != StateConfigInvalid {
		t.Errorf("broken: %+v", st)
	}
}

func TestExportAddressRefused(t *testing.T) {
	h := start(t, "", config(jsonSink("a", "http://169.254.169.254/latest/meta-data/", batch(1, 10*time.Millisecond))))
	h.exp.Add(batchOf(1, numbered("e")))
	h.waitFor("refused", func() bool { return h.status("a").State == StateAddressRefused })
	if m := h.status("a").Message; !strings.Contains(m, "link-local") || strings.Contains(m, "169.254") {
		t.Errorf("message %q", m)
	}
}

// Removing every sink stops the export and empties the buffer.
func TestExportSinksRemoved(t *testing.T) {
	sk := newSink(t)
	sk.block = make(chan struct{})
	defer close(sk.block)
	h := start(t, "", config(jsonSink("a", sk.srv.URL, batch(1, 10*time.Millisecond))))
	h.exp.Add(batchOf(3, numbered("e")))
	h.update(func(c *wafv1alpha1.InkwallConfig) { c.Spec.Events.Export = nil })
	h.waitFor("no sinks", func() bool { return len(h.exp.Status()) == 0 })
	h.exp.Add(batchOf(3, numbered("f")))
	if _, all := h.exp.buf.Load().bytes(); all != 0 {
		t.Errorf("%d bytes buffered without sinks", all)
	}
}

// logsServer is an OTLP/gRPC receiver.
type logsServer struct {
	collogspb.UnimplementedLogsServiceServer
	mu       sync.Mutex
	requests []*collogspb.ExportLogsServiceRequest
	md       []metadata.MD
}

func (s *logsServer) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	s.md = append(s.md, md)
	return &collogspb.ExportLogsServiceResponse{PartialSuccess: &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: 1}}, nil
}

func (s *logsServer) records() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		for _, rl := range r.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				n += len(sl.GetLogRecords())
			}
		}
	}
	return n
}

func TestExportOTLPgRPC(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &logsServer{}
	srv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(wafv1alpha1.EventSink{
		Name: "otel", Insecure: true, OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpc://" + lis.Addr().String()},
		Batch: wafv1alpha1.ExportBatch{MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}},
	}))
	h.exp.Add(&eventsv1.EventBatch{Events: []*eventsv1.SecurityEvent{fullEvent(), oldEvent(), rateLimited()}})
	h.waitFor("3 records", func() bool { return ls.records() == 3 })
	h.waitFor("partial success counted", func() bool {
		return h.rec.get(h.rec.exported, "otel") == 2 && h.rec.get(h.rec.dropped, "otel/"+DropRejected) == 1
	})
}

// selfSigned is a certificate for 127.0.0.1, and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sink"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"sink.example"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Over gRPC, the headers are metadata, lower-cased.
func TestExportOTLPgRPCHeaders(t *testing.T) {
	cert, ca := selfSigned(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ls := &logsServer{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	collogspb.RegisterLogsServiceServer(srv, ls)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	h := start(t, "", config(wafv1alpha1.EventSink{
		Name: "otel", OTLP: &wafv1alpha1.OTLPSink{Endpoint: "grpcs://" + lis.Addr().String()},
		HeadersSecretRef: &wafv1alpha1.LocalSecretReference{Name: "h"},
		TLS:              &wafv1alpha1.SinkTLS{CASecretRef: &wafv1alpha1.LocalSecretReference{Name: "ca"}},
		Batch:            wafv1alpha1.ExportBatch{MaxDelay: &metav1.Duration{Duration: 10 * time.Millisecond}},
	}), secretObj("h", map[string]string{"Authorization": "Bearer t", "DD-API-KEY": "k"}), secretObj("ca", map[string]string{"ca.crt": ca}))
	h.exp.Add(batchOf(2, numbered("e")))
	h.waitFor("2 records", func() bool { return ls.records() == 2 })
	ls.mu.Lock()
	md := ls.md[0]
	ls.mu.Unlock()
	if got := md.Get("authorization"); len(got) != 1 || got[0] != "Bearer t" || md.Get("dd-api-key")[0] != "k" {
		t.Errorf("metadata %v", md)
	}
}

func TestCheckHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		grpc bool
		ok   bool
	}{
		{"Authorization", false, true}, {"DD-API-KEY", true, true}, {"X-Splunk-Request-Channel", false, true},
		{"Host", false, false}, {"content-type", false, false}, {"Content-Length", true, false}, {"Content-Encoding", false, false},
		{"Transfer-Encoding", false, false}, {"Connection", false, false}, {"TE", false, false}, {"Trailer", false, false},
		{"Upgrade", false, false}, {"Proxy-Authorization", false, false}, {"proxy-anything", true, false},
		{"grpc-timeout", true, false}, {"grpc-timeout", false, true}, {"x-token-bin", true, false}, {"x-token-bin", false, true},
		{"bad header", false, false}, {"", false, false}, {"a:b", true, false},
	} {
		if err := checkHeader(tc.name, tc.grpc); (err == nil) != tc.ok {
			t.Errorf("%q (gRPC %t): %v, want ok %t", tc.name, tc.grpc, err, tc.ok)
		}
	}
}
