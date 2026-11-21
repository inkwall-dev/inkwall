// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The memory bound drops only batches that hold memory: with the writer
// behind, the oldest batch in memory goes, not the backlog on disk; the
// sinks skip the gap and count it.
func TestBufferMemoryBoundWithLaggingWriter(t *testing.T) {
	dir := t.TempDir()
	size := batchSize(10)
	b := newTestBuffer(t, dir, 3*size, 100*size)
	b.setSinks([]string{"a"})
	for range 3 {
		b.add(batchOf(10, numbered("x")))
	}
	b.writeRound() // 1-3 on disk
	for range 4 {
		b.add(batchOf(10, numbered("y"))) // 4-7, the writer lagging
	}
	if mem, _ := b.bytes(); mem > 3*size {
		t.Errorf("memory %d over its bound %d", mem, 3*size)
	}
	if p := b.pending("a"); p != 60 {
		t.Errorf("pending %d, want 60 with the gap", p)
	}
	got := takeDroppedAndSeqs(t, b, "a")
	if got.dropped != 10 || !slices.Equal(got.seqs, []uint64{1, 2, 3, 5, 6, 7}) {
		t.Errorf("dropped %d, took %v: want 1-3 kept on disk and the oldest in memory, 4, dropped", got.dropped, got.seqs)
	}
	// The gap isn't written: no file for the dropped batch.
	b.writeRound()
	if _, err := os.Stat(filepath.Join(dir, batchName(4))); !os.IsNotExist(err) {
		t.Errorf("the dropped batch's file: %v", err)
	}
	// Committed past it all, everything goes.
	b.commit("a", position{seq: 8})
	if _, all := b.bytes(); all != 0 || b.pending("a") != 0 {
		t.Errorf("%d bytes, %d pending after the last commit", all, b.pending("a"))
	}
}

// A failed disk: what is on disk stays readable, and the memory bound
// drops only batches in memory.
func TestBufferMemoryBoundAfterDiskFailure(t *testing.T) {
	dir := t.TempDir()
	size := batchSize(10)
	b := newTestBuffer(t, dir, 2*size, 100*size)
	b.setSinks([]string{"a"})
	for range 4 {
		b.add(batchOf(10, numbered("x")))
		b.writeRound()
	}
	b.diskFailed(os.ErrPermission)
	for range 4 {
		b.add(batchOf(10, numbered("y"))) // 5-8, in memory only
	}
	if mem, _ := b.bytes(); mem > 2*size {
		t.Errorf("memory %d over its bound %d", mem, 2*size)
	}
	got := takeDroppedAndSeqs(t, b, "a")
	if !slices.Equal(got.seqs, []uint64{1, 2, 3, 4, 7, 8}) || got.dropped != 20 {
		t.Errorf("took %v, dropped %d: want 1-4 from disk, 7-8 from memory, and 5-6 dropped", got.seqs, got.dropped)
	}
}

// The disk bound counts each batch file in whole 4 KiB blocks, as the
// kubelet measures the emptyDir: many small batches can't pass its
// sizeLimit while their bytes stay under the bound.
func TestBufferDiskBoundCountsBlocks(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<20, 40*diskBlock)
	b.setSinks([]string{"a"})
	for range 100 {
		b.add(batchOf(1, numbered("x"))) // a few hundred bytes each
	}
	b.writeRound()
	files, _ := filepath.Glob(filepath.Join(dir, "*"+batchSuffix))
	var blocks int64
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		blocks += (st.Size() + diskBlock - 1) / diskBlock
	}
	if len(files) != 40 || blocks*diskBlock > 40*diskBlock {
		t.Errorf("%d files, %d blocks: want 40, within the bound of 40 blocks", len(files), blocks)
	}
	if _, all := b.bytes(); all != 40*diskBlock {
		t.Errorf("counted %d bytes, want 40 blocks", all)
	}
	// In memory, a batch counts as its bytes.
	m := newTestBuffer(t, "", 1<<20, 1<<20)
	m.setSinks([]string{"a"})
	m.add(batchOf(1, numbered("x")))
	if _, all := m.bytes(); all != batchSize(1) {
		t.Errorf("in memory, %d bytes for a batch of %d", all, batchSize(1))
	}
}

type tookAll struct {
	seqs    []uint64
	dropped uint64
}

func takeDroppedAndSeqs(t *testing.T, b *buffer, sink string) tookAll {
	t.Helper()
	var out tookAll
	for _, tk := range takeAll(t, b, sink) {
		out.seqs = append(out.seqs, tk.seq)
	}
	out.dropped = b.takeDropped(sink)
	return out
}
