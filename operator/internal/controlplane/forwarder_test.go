// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
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
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.cp.SetAcceptEvents(accept)
	e.run(t)
	e.waitReason(t, ReasonConnected)
	f := &Forwarder{
		Client: e.client, Namespace: ns, Replica: "op-1", OperatorVersion: "0.2.0-test", CAFile: e.conn.CAFile,
		Dir: t.TempDir(), Poll: 50 * time.Millisecond, Refused: 50 * time.Millisecond,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return e, f
}

func TestForwarderSendsEvents(t *testing.T) {
	e, f := forwarderEnv(t, true)
	waitFor(t, "the events stream", func() bool { return f.accepts.Load() })
	f.Add(batchOf(2, "a", "b"))
	f.Add(batchOf(0, "c"))
	waitFor(t, "three events", func() bool { return e.cp.Stats().Events == 3 })
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
