// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

func newTestBuffer(t *testing.T, dir string, mem, disk int64) *buffer {
	t.Helper()
	b, err := openBuffer(dir, mem, disk)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func batchSize(n int) int64 {
	raw, _ := proto.Marshal(batchOf(n, numbered("s")))
	return int64(len(raw))
}

// takeAll takes every batch sink can, decoding the ones on disk.
func takeAll(t *testing.T, b *buffer, sink string) []taken {
	t.Helper()
	var out []taken
	for {
		tk, ok, _ := b.take(sink)
		if !ok {
			return out
		}
		if tk.raw == nil {
			raw, ok := b.readBatch(tk.seq)
			if !ok {
				t.Fatalf("batch %d is on disk only and can't be read", tk.seq)
			}
			tk.raw = raw
		}
		out = append(out, tk)
	}
}

func TestBufferNoSinksKeepsNothing(t *testing.T) {
	b := newTestBuffer(t, "", 1<<20, 1<<20)
	b.setSinks(nil)
	b.add(batchOf(3, numbered("a")))
	if _, all := b.bytes(); all != 0 {
		t.Errorf("%d bytes held with no sinks", all)
	}
}

// A new sink starts at the end; a removed one frees what only it waited
// for; a changed one keeps its cursor (it is the same name).
func TestBufferCursorsFollowSinks(t *testing.T) {
	b := newTestBuffer(t, "", 1<<20, 1<<20)
	b.setSinks([]string{"a"})
	b.add(batchOf(2, numbered("x")))
	b.setSinks([]string{"a", "b"})
	if got := len(takeAll(t, b, "b")); got != 0 {
		t.Errorf("a new sink took %d batches of the backlog", got)
	}
	if p := b.pending("a"); p != 2 {
		t.Errorf("a: %d pending, want 2", p)
	}
	b.add(batchOf(3, numbered("y")))
	if p := b.pending("b"); p != 3 {
		t.Errorf("b: %d pending, want 3", p)
	}
	// Renamed: a removal and a new sink; the batch only a waited for goes.
	b.setSinks([]string{"b", "c"})
	if b.pending("c") != 0 || len(b.batches) != 1 {
		t.Errorf("after renaming a to c: c pending %d, %d batches held, want 0 and 1", b.pending("c"), len(b.batches))
	}
	b.setSinks([]string{"b", "c"}) // changed: same names, same cursors
	if b.pending("b") != 3 {
		t.Errorf("b lost its cursor: %d pending", b.pending("b"))
	}
}

// Cursors are (batch, event): a commit inside a batch keeps the batch, and
// pending counts events.
func TestBufferCursorInsideBatch(t *testing.T) {
	b := newTestBuffer(t, "", 1<<20, 1<<20)
	b.setSinks([]string{"a", "b"})
	b.add(batchOf(5, numbered("x")))
	b.add(batchOf(5, numbered("y")))
	b.commit("a", position{seq: 1, idx: 3})
	if p := b.pending("a"); p != 7 {
		t.Errorf("a: %d pending, want 7", p)
	}
	b.commit("b", position{seq: 2, idx: 0})
	if len(b.batches) != 2 {
		t.Errorf("%d batches held, want 2: a is inside the first", len(b.batches))
	}
	b.commit("a", position{seq: 2, idx: 1})
	if len(b.batches) != 1 || b.batches[0].seq != 2 {
		t.Errorf("batches %v, want only the second", b.batches)
	}
	// A commit never moves a cursor back.
	b.commit("a", position{seq: 1, idx: 0})
	if p := b.pending("a"); p != 4 {
		t.Errorf("a: %d pending after an older commit, want 4", p)
	}
}

// A slow sink loses its own events, not a healthy one's: the healthy one
// sent them already.
func TestBufferSlowSinkLosesOnlyItsOwn(t *testing.T) {
	size := batchSize(10)
	b := newTestBuffer(t, "", 4*size, 4*size)
	b.setSinks([]string{"fast", "slow"})
	for range 10 {
		b.add(batchOf(10, numbered("x")))
		for _, tk := range takeAll(t, b, "fast") {
			b.commit("fast", position{seq: tk.seq + 1})
		}
	}
	if d := b.takeDropped("fast"); d != 0 {
		t.Errorf("the fast sink dropped %d", d)
	}
	if d := b.takeDropped("slow"); d != 60 {
		t.Errorf("the slow sink dropped %d, want 60 (6 batches of 10 past the bound of 4)", d)
	}
	if mem, all := b.bytes(); mem > 4*size || all > 4*size {
		t.Errorf("buffer %d/%d bytes, over the bound %d", mem, all, 4*size)
	}
	// Taken events are with the sender: a drop doesn't count them.
	tk := takeAll(t, b, "slow")
	if len(tk) != 4 {
		t.Fatalf("slow took %d batches, want 4", len(tk))
	}
	b.add(batchOf(10, numbered("y")))
	if d := b.takeDropped("slow"); d != 0 {
		t.Errorf("dropped %d events the sender holds", d)
	}
}

// With a directory: the newest batches in memory, every one on disk, read
// back from disk once they leave memory; the oldest dropped at the disk
// bound.
func TestBufferMemoryAndDiskBounds(t *testing.T) {
	dir := t.TempDir()
	size := batchSize(10)
	// On disk, each batch counts as its file in whole blocks.
	onDisk := (size + batchHeader + diskBlock - 1) / diskBlock * diskBlock
	b := newTestBuffer(t, dir, 2*size, 6*onDisk)
	b.setSinks([]string{"a"})
	for range 8 {
		b.add(batchOf(10, numbered("x")))
		b.writeRound()
	}
	mem, all := b.bytes()
	if mem > 2*size || all > 6*onDisk || all < 5*onDisk {
		t.Errorf("memory %d (bound %d), all %d (bound %d)", mem, 2*size, all, 6*onDisk)
	}
	if d := b.takeDropped("a"); d != 20 {
		t.Errorf("dropped %d, want the 2 oldest batches' 20", d)
	}
	got := takeAll(t, b, "a")
	if len(got) != 6 || got[0].seq != 3 {
		t.Fatalf("took %d batches from %d, want 6 from 3", len(got), got[0].seq)
	}
	for _, tk := range got {
		var bt eventsv1.EventBatch
		if err := proto.Unmarshal(tk.raw, &bt); err != nil || len(bt.Events) != 10 {
			t.Errorf("batch %d: %d events, %v", tk.seq, len(bt.Events), err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"+batchSuffix))
	if len(files) != 6 {
		t.Errorf("%d batch files, want 6: the dropped ones' removed", len(files))
	}
}

// Without a directory, the memory bound is the whole buffer.
func TestBufferMemoryOnlyDropsOldest(t *testing.T) {
	size := batchSize(5)
	b := newTestBuffer(t, "", 3*size, 100*size)
	b.setSinks([]string{"a"})
	for range 5 {
		b.add(batchOf(5, numbered("x")))
	}
	if _, all := b.bytes(); all > 3*size {
		t.Errorf("%d bytes, over %d", all, 3*size)
	}
	if got := takeAll(t, b, "a"); len(got) != 3 || got[0].seq != 3 {
		t.Errorf("took %d from %d, want 3 from 3", len(got), got[0].seq)
	}
}

// A restart resends from the persisted cursors, not the whole buffer.
func TestBufferReloads(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<20, 1<<20)
	b.setSinks([]string{"a", "b"})
	for range 3 {
		b.add(batchOf(4, numbered("x")))
	}
	b.commit("a", position{seq: 2, idx: 1})
	b.commit("b", position{seq: 4})
	b.writeRound()

	re := newTestBuffer(t, dir, 1<<20, 1<<20)
	re.setSinks([]string{"a", "b"})
	if p := re.pending("a"); p != 7 {
		t.Errorf("a: %d pending after a restart, want 7", p)
	}
	if p := re.pending("b"); p != 0 {
		t.Errorf("b: %d pending, want 0", p)
	}
	tk := takeAll(t, re, "a")
	if len(tk) != 2 || tk[0].seq != 2 || tk[0].from != 1 {
		t.Errorf("a took %+v, want batches 2 (from event 1) and 3", tk)
	}
	if !tk[0].observed.Equal(b.batches[0].observed) {
		t.Errorf("observed %v, want %v kept across the restart", tk[0].observed, b.batches[0].observed)
	}
	re.add(batchOf(1, numbered("y")))
	if re.batches[len(re.batches)-1].seq != 5 { // one past the highest cursor, b's at 4
		t.Errorf("new batch numbered %d, want 5", re.batches[len(re.batches)-1].seq)
	}
	// A sink gone from the configuration frees its cursor file.
	re.setSinks([]string{"b"})
	re.writeRound()
	if _, err := os.Stat(filepath.Join(dir, cursorPrefix+"a")); !os.IsNotExist(err) {
		t.Errorf("the removed sink's cursor file: %v", err)
	}
}

// A torn batch file is dropped, at load (no header) or when read (a cut
// body): never an error, never a stuck sink.
func TestBufferTornFiles(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<20, 1<<20)
	b.setSinks([]string{"a"})
	for range 3 {
		b.add(batchOf(4, numbered("x")))
	}
	b.writeRound()
	if err := os.WriteFile(filepath.Join(dir, batchName(1)), []byte("IW"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, batchName(2)))
	if err := os.WriteFile(filepath.Join(dir, batchName(2)), raw[:len(raw)-7], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, batchName(9)+tmpSuffix), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	re := newTestBuffer(t, dir, 1<<20, 1<<20)
	re.setSinks([]string{"a"})
	if len(re.batches) != 2 || re.batches[0].seq != 2 {
		t.Fatalf("loaded %d batches, want 2 and 3", len(re.batches))
	}
	if _, err := os.Stat(filepath.Join(dir, batchName(9)+tmpSuffix)); !os.IsNotExist(err) {
		t.Error("a torn temporary file stayed")
	}
	s := newSender("a", re, nil, noMetrics{}, &sinkState{})
	tk, _, _ := re.take("a")
	if h := s.load(tk); h != nil {
		t.Errorf("a cut batch decoded to %d events", len(h.events))
	}
	tk, _, _ = re.take("a")
	if h := s.load(tk); h == nil || len(h.events) != 4 {
		t.Error("the batch after the torn one is lost")
	}
}

// A sender may send a batch still in memory, but its cursor file stops at
// the last batch on disk; after a crash, new batches never take a number a
// cursor has passed.
func TestBufferCrashBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<20, 1<<20)
	b.setSinks([]string{"a"})
	b.add(batchOf(2, numbered("x")))
	b.writeRound()
	b.add(batchOf(2, numbered("y"))) // batch 2, in memory only
	b.commit("a", position{seq: 3})  // the sink sent it already
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.persist(root) // the cursors, but not the batch: then the crash
	_ = root.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, cursorPrefix+"a"))
	if p, _ := parsePosition(string(raw)); p != (position{seq: 2}) {
		t.Errorf("cursor file %q, want 2 0: not past the batch on disk", strings.TrimSpace(string(raw)))
	}
	re := newTestBuffer(t, dir, 1<<20, 1<<20)
	re.setSinks([]string{"a"})
	re.add(batchOf(1, numbered("z")))
	if seq := re.batches[len(re.batches)-1].seq; seq < 2 {
		t.Errorf("new batch numbered %d, below the cursor", seq)
	}
	if p := re.pending("a"); p != 1 {
		t.Errorf("%d pending after the crash, want the new batch's 1", p)
	}
	// And a cursor ahead of every batch on disk (persisted, then its
	// batches freed) still numbers new batches past it.
	if err := os.WriteFile(filepath.Join(dir, cursorPrefix+"b"), []byte("40 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	re2 := newTestBuffer(t, dir, 1<<20, 1<<20)
	if re2.next <= 40 {
		t.Errorf("next %d, want past the cursor at 40", re2.next)
	}
}

// A buffer whose directory fails goes on in memory.
func TestBufferDiskFailure(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<20, 1<<20)
	var failed error
	b.onDiskError = func(err error) { failed = err }
	b.setSinks([]string{"a"})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil { // a file where the directory was
		t.Fatal(err)
	}
	b.add(batchOf(2, numbered("x")))
	b.writeRound()
	if failed == nil || b.diskOK {
		t.Fatal("no disk failure reported")
	}
	if got := takeAll(t, b, "a"); len(got) != 1 {
		t.Errorf("took %d batches after the failure, want 1 from memory", len(got))
	}
}
