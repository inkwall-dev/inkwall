// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func batchOf(dropped uint64, ids ...string) *eventsv1.EventBatch {
	b := &eventsv1.EventBatch{Dropped: dropped}
	for _, id := range ids {
		b.Events = append(b.Events, &eventsv1.SecurityEvent{EventId: id})
	}
	return b
}

func queuedIDs(q *queue) []string {
	var ids []string
	for _, b := range q.after(0) {
		for _, ev := range b.batch.GetEvents() {
			ids = append(ids, ev.GetEventId())
		}
	}
	return ids
}

func TestQueueOnDisk(t *testing.T) {
	dir := t.TempDir()
	q, err := openQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := q.add(batchOf(0, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	q.ack(1)
	if got := queuedIDs(q); !slices.Equal(got, []string{"1", "2"}) {
		t.Fatalf("after ack(1): %v", got)
	}

	// A restarted operator resends what wasn't acknowledged, in the same
	// buffer, and continues its sequence.
	again, err := openQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if again.id != q.id {
		t.Errorf("buffer ID %s after a restart, want %s", again.id, q.id)
	}
	if got := queuedIDs(again); !slices.Equal(got, []string{"1", "2"}) {
		t.Fatalf("after a restart: %v", got)
	}
	if err := again.add(batchOf(0, "3")); err != nil {
		t.Fatal(err)
	}
	if b := again.after(0); b[len(b)-1].seq != 4 {
		t.Errorf("next sequence %d, want 4", b[len(b)-1].seq)
	}
	if got := again.after(3); len(got) != 1 || got[0].seq != 4 {
		t.Errorf("after(3) = %v", got)
	}

	// A new disk is a new buffer.
	other, err := openQueue(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if other.id == q.id || len(other.after(0)) != 0 {
		t.Errorf("a new directory: id %s, %d batches", other.id, len(other.after(0)))
	}
}

func TestQueueTornFile(t *testing.T) {
	dir := t.TempDir()
	q, err := openQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_ = q.add(batchOf(0, "a"))
	_ = q.add(batchOf(0, "b"))
	if err := os.WriteFile(filepath.Join(dir, batchName(1)), []byte{0xff, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := openQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got := queuedIDs(again); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("after a torn file: %v", got)
	}
	_ = again.add(batchOf(0, "c"))
	if last := again.after(0); last[len(last)-1].batch.GetDropped() != 1 {
		t.Errorf("the next batch says %d dropped, want 1 (the torn batch)", last[len(last)-1].batch.GetDropped())
	}
}

func TestQueueBound(t *testing.T) {
	// IDs the size of a ULID, so a dropped count changes a batch's size
	// little.
	id := func(n string) string { return fmt.Sprintf("%026s", n) }
	one, _ := proto.Marshal(batchOf(0, id("x")))
	// Room for two one-event batches (dropped counts make them grow).
	q, err := openQueue("", int64(2*len(one)+8))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"1", "2", "3", "4"} {
		if err := q.add(batchOf(0, id(n))); err != nil {
			t.Fatal(err)
		}
	}
	got := q.after(0)
	if ids := queuedIDs(q); !slices.Equal(ids, []string{id("3"), id("4")}) {
		t.Fatalf("kept %v, want the newest: 3, 4", ids)
	}
	// The drops are counted: 1 and 2 are gone, the engine's own drops add.
	var dropped uint64
	for _, b := range got {
		dropped += b.batch.GetDropped()
	}
	if dropped != 2 {
		t.Errorf("dropped %d, want 2", dropped)
	}

	// A batch larger than the whole buffer is dropped, and counted next.
	big := batchOf(5)
	for i := range 100 {
		big.Events = append(big.Events, &eventsv1.SecurityEvent{EventId: fmt.Sprint("big", i)})
	}
	_ = q.add(big)
	q.ack(^uint64(0))
	_ = q.add(batchOf(0, "5"))
	if b := q.after(0); len(b) != 1 || b[0].batch.GetDropped() != 105 {
		t.Fatalf("after an oversized batch: %v", b)
	}
}

func TestQueueGauge(t *testing.T) {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_buffered"})
	dir := t.TempDir()
	q, _ := openQueue(dir, 1<<20)
	_ = q.add(batchOf(0, "a", "b"))
	// Untracked until track; then it says what is already there.
	if v := testutil.ToFloat64(g); v != 0 {
		t.Fatalf("untracked gauge %v", v)
	}
	q.track(g)
	expect := func(when string, want float64) {
		t.Helper()
		if v := testutil.ToFloat64(g); v != want {
			t.Errorf("%s: gauge %v, want %v", when, v, want)
		}
	}
	expect("tracked", 2)
	_ = q.add(batchOf(4, "c"))
	expect("add", 3)
	q.ack(1)
	expect("ack", 1)
	q.clear()
	expect("clear", 0)

	// A restarted operator counts what it loads.
	_ = q.add(batchOf(0, "d", "e"))
	again, _ := openQueue(dir, 1<<20)
	again.track(g)
	expect("reopened", 2)

	// Dropping the oldest leaves the newest counted; an oversized batch
	// adds nothing.
	id := func(n string) string { return fmt.Sprintf("%026s", n) }
	one, _ := proto.Marshal(batchOf(0, id("x")))
	small, _ := openQueue("", int64(len(one)+8))
	small.track(g)
	_ = small.add(batchOf(0, id("1")))
	_ = small.add(batchOf(0, id("2")))
	expect("full", 1)
	big := batchOf(0)
	for i := range 10 {
		big.Events = append(big.Events, &eventsv1.SecurityEvent{EventId: fmt.Sprint("big", i)})
	}
	_ = small.add(big)
	expect("oversized", 1)
}

func TestQueueClear(t *testing.T) {
	dir := t.TempDir()
	q, _ := openQueue(dir, 1<<20)
	_ = q.add(batchOf(3, "1"))
	q.clear()
	if q.events() != 0 || len(q.after(0)) != 0 {
		t.Fatal("not cleared")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if _, ok := batchSeq(e.Name()); ok {
			t.Errorf("%s left on disk", e.Name())
		}
	}
	// Cleared drops aren't reported: nothing was promised.
	_ = q.add(batchOf(0, "2"))
	if q.after(0)[0].batch.GetDropped() != 0 {
		t.Error("dropped carried over a clear")
	}
}

// forwarderEnv is a connected cluster (enrolled by its leader) with a
// forwarder on a replica.
func forwarderEnv(t *testing.T, accept bool) (*env, *Forwarder) {
	t.Helper()
	e := connectedEnv(t, accept)
	return e, startForwarder(t, e, t.TempDir())
}

// connectedEnv is a cluster its leader enrolled and connected.
func connectedEnv(t *testing.T, accept bool) *env {
	t.Helper()
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.cp.SetAcceptEvents(accept)
	e.run(t)
	e.waitReason(t, ReasonConnected)
	return e
}

// startForwarder runs a replica's forwarder with its buffer in dir.
func startForwarder(t *testing.T, e *env, dir string) *Forwarder {
	t.Helper()
	f := &Forwarder{
		Client: e.client, Namespace: ns, Replica: "op-1", OperatorVersion: "0.2.0-test", CAFile: e.conn.CAFile,
		Dir: dir, Poll: 50 * time.Millisecond, Refused: 50 * time.Millisecond,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, StatsInterval: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

func TestForwarderSendsEvents(t *testing.T) {
	e, f := forwarderEnv(t, true)
	waitFor(t, "the events stream", func() bool { return f.accepts.Load() })
	f.Add(batchOf(2, "a", "b"))
	f.Add(batchOf(0, "c"))
	// The control plane doesn't take request counts: none are sent.
	f.AddStats([]*eventsv1.PolicyStats{{Policy: "shop/site", Allowed: 1}})
	waitFor(t, "three events", func() bool { return e.cp.Stats().Events == 3 })
	time.Sleep(3 * f.StatsInterval)
	if n := e.cp.Stats().StatsUploads; n != 0 {
		t.Errorf("%d request count uploads, none accepted", n)
	}
	if st := e.cp.Stats(); st.EventsDropped != 2 {
		t.Errorf("dropped %d, want 2", st.EventsDropped)
	}
	// Acknowledged: freed from the buffer.
	waitFor(t, "the acks", func() bool { return f.q.Load().events() == 0 })
	var roles []string
	for _, h := range e.cp.Stats().Hellos {
		roles = append(roles, h.GetRole().String())
	}
	if !slices.Contains(roles, "STREAM_ROLE_EVENTS") {
		t.Errorf("Hellos %v, want an events stream", roles)
	}
}

// A batch over the contract's message limit is uploaded in parts.
func TestForwarderLargeBatch(t *testing.T) {
	e, f := forwarderEnv(t, true)
	waitFor(t, "the events stream", func() bool { return f.accepts.Load() })
	long := strings.Repeat("x", 4096)
	src := events.Source{EngineID: strings.Repeat("e", 253), PodNamespace: strings.Repeat("n", 63), PodName: strings.Repeat("p", 253)}
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, Policy: long}
	for i := range 64 {
		v.Matches = append(v.Matches, rules.Match{RuleID: 900000 + i, Variable: "ARGS:" + long, Value: long})
	}
	req := &request.Request{ID: long, Method: long, Host: long, Headers: http.Header{"User-Agent": {long}}}
	const n = 2000
	b := &eventsv1.EventBatch{Dropped: 1}
	for range n {
		b.Events = append(b.Events, events.New(src, req, "/"+long, v, time.Now()))
	}
	if size := proto.Size(b); size <= maxMessage {
		t.Fatalf("the batch is %d bytes, want over %d", size, maxMessage)
	}
	f.Add(b)
	waitFor(t, "every event", func() bool { return e.cp.Stats().Events == n })
	if st := e.cp.Stats(); st.EventsDropped != 1 {
		t.Errorf("dropped %d, want 1", st.EventsDropped)
	}
	waitFor(t, "the acks", func() bool { return f.q.Load().events() == 0 })
}

func TestForwarderResendsAfterReconnect(t *testing.T) {
	e, f := forwarderEnv(t, true)
	waitFor(t, "the events stream", func() bool { return f.accepts.Load() })
	// The control plane is down: events wait in the buffer.
	e.cp.FailConnect(fmt.Errorf("down"))
	f.Add(batchOf(0, "a"))
	f.Add(batchOf(0, "b"))
	e.cp.FailConnect(nil)
	waitFor(t, "both events after the outage", func() bool { return e.cp.Stats().Events >= 2 })
	waitFor(t, "the acks", func() bool { return f.q.Load().events() == 0 })
}

func TestForwarderOutage(t *testing.T) {
	e := connectedEnv(t, true)
	// The control plane goes down with a batch on disk, and the operator
	// restarts: the stream can't come up, and the buffer grows.
	e.cp.FailConnect(fmt.Errorf("down"))
	dir := t.TempDir()
	q, err := openQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_ = q.add(batchOf(0, "a"))
	f := startForwarder(t, e, dir)
	// The gauge is set before the queue is published.
	waitFor(t, "the queue", func() bool { return f.q.Load() != nil })
	if v := testutil.ToFloat64(eventsBuffered); v != 1 {
		t.Errorf("buffered %v from disk, want 1", v)
	}
	f.Add(batchOf(0, "b", "c"))
	if v := testutil.ToFloat64(eventsBuffered); v != 3 {
		t.Errorf("buffered %v during the outage, want 3", v)
	}
	// Long enough for the backoff to reach its bound several times over.
	time.Sleep(10 * f.MaxBackoff)
	if n := e.cp.Stats().Events; n != 0 {
		t.Fatalf("%d events during the outage", n)
	}

	// Back: the backlog drains within the bound, not the leader's.
	e.cp.FailConnect(nil)
	back := time.Now()
	waitFor(t, "the backlog", func() bool { return e.cp.Stats().Events == 3 })
	if d := time.Since(back); d > f.MaxBackoff+time.Second {
		t.Errorf("events arrived %v after the outage, want within about %v", d, f.MaxBackoff)
	}
	waitFor(t, "the gauge after the acks", func() bool { return testutil.ToFloat64(eventsBuffered) == 0 })
}

func TestForwarderDefaults(t *testing.T) {
	var f Forwarder
	f.defaults()
	var c Connector
	c.defaults()
	if f.MaxBackoff != 10*time.Second || f.MaxBackoff >= c.MaxBackoff {
		t.Errorf("events stream backoff bound %v, want 10 s, below the leader's %v", f.MaxBackoff, c.MaxBackoff)
	}
}

func TestForwarderNotAccepted(t *testing.T) {
	e, f := forwarderEnv(t, false)
	// The stream is refused once Welcome says so; nothing is buffered.
	waitFor(t, "a Welcome", func() bool {
		for _, h := range e.cp.Stats().Hellos {
			if h.GetRole().String() == "STREAM_ROLE_EVENTS" {
				return true
			}
		}
		return false
	})
	f.Add(batchOf(0, "a"))
	if q := f.q.Load(); q != nil && q.events() != 0 {
		t.Fatalf("%d events buffered while not accepted", q.events())
	}
	// Once accepted, events flow.
	e.cp.SetAcceptEvents(true)
	waitFor(t, "acceptance", func() bool { return f.accepts.Load() })
	f.Add(batchOf(0, "b"))
	waitFor(t, "the event", func() bool { return e.cp.Stats().Events == 1 })
}

func TestForwarderStandalone(t *testing.T) {
	f := &Forwarder{Client: newEnv(t, wafv1alpha1.ModeStandalone, "").client, Namespace: ns, Dir: t.TempDir(), Poll: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the queue", func() bool { return f.q.Load() != nil })
	time.Sleep(60 * time.Millisecond)
	f.Add(batchOf(0, "a"))
	if n := f.q.Load().events(); n != 0 {
		t.Errorf("Standalone buffered %d events", n)
	}
}

// Request counts go to a control plane that takes them, even without
// events: per policy, summed over the engines, cumulative, so a new stream
// sends them again without counting them twice.
func TestForwarderSendsRequestStats(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.cp.SetAcceptRequestStats(true)
	e.run(t)
	e.waitReason(t, ReasonConnected)
	f := startForwarder(t, e, t.TempDir())

	latency := func(n uint64) []uint64 { return []uint64{n, 0} }
	// Two engines' reports.
	f.AddStats([]*eventsv1.PolicyStats{{Policy: "shop/site", Allowed: 2, Denied: 1, LatencyCounts: latency(3), LatencySum: 0.3}})
	f.AddStats([]*eventsv1.PolicyStats{
		{Policy: "shop/site", Allowed: 1, LatencyCounts: latency(1), LatencySum: 0.1},
		{Policy: "shop/api", Detected: 4},
	})
	sent := func(policy string, allowed, denied, detected, timed uint64) func() bool {
		return func() bool {
			p := e.cp.RequestStats()[policy]
			var n uint64
			for _, c := range p.GetLatencyCounts() {
				n += c
			}
			return p.GetAllowed() == allowed && p.GetDenied() == denied && p.GetDetected() == detected && n == timed
		}
	}
	waitFor(t, "shop/site's counts", sent("shop/site", 3, 1, 0, 4))
	waitFor(t, "shop/api's counts", sent("shop/api", 0, 0, 4, 0))
	f.AddStats([]*eventsv1.PolicyStats{{Policy: "shop/site", Denied: 1, LatencyCounts: latency(1)}})
	waitFor(t, "the new counts", sent("shop/site", 3, 2, 0, 5))

	// Events aren't accepted: none are buffered.
	f.Add(batchOf(0, "a"))
	if q := f.q.Load(); q != nil && q.events() != 0 {
		t.Errorf("%d events buffered while not accepted", q.events())
	}
	// A new stream sends every policy again, with the same totals.
	uploads := e.cp.Stats().StatsUploads
	e.cp.FailConnect(fmt.Errorf("down"))
	time.Sleep(3 * f.StatsInterval)
	e.cp.FailConnect(nil)
	waitFor(t, "uploads on a new stream", func() bool { return e.cp.Stats().StatsUploads > uploads })
	if !sent("shop/site", 3, 2, 0, 5)() || !sent("shop/api", 0, 0, 4, 0)() {
		t.Errorf("counts after a reconnect: %v", e.cp.RequestStats())
	}
	var events int
	for _, h := range e.cp.Stats().Hellos {
		if h.GetRole().String() == "STREAM_ROLE_EVENTS" {
			events++
			if !slices.Contains(h.GetCapabilities(), statsCapability) {
				t.Errorf("capabilities %v", h.GetCapabilities())
			}
		}
	}
	if events < 2 {
		t.Errorf("%d events streams, want a new one after the outage", events)
	}
}

func TestRequestStatsUpload(t *testing.T) {
	var r requestStats
	if r.upload(true) != nil {
		t.Fatal("an upload with nothing counted")
	}
	r.add([]*eventsv1.PolicyStats{{Policy: "b", Allowed: 1}, {Policy: "a", Denied: 1}})
	up := r.upload(false)
	if p := up.GetStats().GetPolicies(); len(p) != 2 || p[0].GetPolicy() != "a" || up.GetSince() == nil ||
		len(up.GetStats().GetLatencyBounds()) == 0 {
		t.Fatalf("first upload: %v", up)
	}
	r.add([]*eventsv1.PolicyStats{{Policy: "b", Allowed: 2}})
	if p := r.upload(false).GetStats().GetPolicies(); len(p) != 1 || p[0].GetAllowed() != 3 {
		t.Errorf("changed only: %v", p)
	}
	if r.upload(false) != nil {
		t.Error("an upload with nothing changed")
	}
	if p := r.upload(true).GetStats().GetPolicies(); len(p) != 2 {
		t.Errorf("all: %v", p)
	}
}
