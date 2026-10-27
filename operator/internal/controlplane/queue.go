// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// queue is a replica's buffer of event batches for the control plane
// (0002 §5.3): at least once, bounded, dropping the oldest when full, and
// on disk when it has a directory, so a restarted operator resends what
// wasn't acknowledged. Each batch is a file named by its sequence; the
// buffer's random ID is in a file of its own, so a new disk (a new
// buffer) never looks like an old one.
type queue struct {
	dir      string // "" keeps the batches in memory only
	maxBytes int64

	mu      sync.Mutex
	id      string
	next    uint64 // the sequence of the next batch
	batches []queued
	bytes   int64
	// dropped counts the events dropped since the last batch, carried by
	// the next one.
	dropped uint64
	changed chan struct{}
}

type queued struct {
	seq   uint64
	size  int64
	batch *eventsv1.EventBatch
}

const (
	bufferIDFile = "buffer-id"
	batchSuffix  = ".batch"
)

// openQueue loads the batches in dir, or starts a new buffer.
func openQueue(dir string, maxBytes int64) (*queue, error) {
	q := &queue{dir: dir, maxBytes: maxBytes, next: 1, changed: make(chan struct{}, 1)}
	if dir == "" {
		q.id = newBufferID()
		return q, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("events buffer: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("events buffer: %w", err)
	}
	defer func() { _ = root.Close() }()
	id, err := root.ReadFile(bufferIDFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// A new buffer: whatever is left there belongs to no buffer.
		if err := q.clearFiles(root); err != nil {
			return nil, err
		}
		q.id = newBufferID()
		if err := root.WriteFile(bufferIDFile, []byte(q.id), 0o600); err != nil {
			return nil, fmt.Errorf("events buffer: %w", err)
		}
		return q, nil
	case err != nil:
		return nil, fmt.Errorf("events buffer: %w", err)
	}
	q.id = strings.TrimSpace(string(id))
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("events buffer: %w", err)
	}
	for _, e := range entries {
		seq, ok := batchSeq(e.Name())
		if !ok {
			continue
		}
		raw, err := root.ReadFile(e.Name())
		var b eventsv1.EventBatch
		if err == nil {
			err = proto.Unmarshal(raw, &b)
		}
		if err != nil {
			// A torn write: the batch is lost, and said so.
			_ = root.Remove(e.Name())
			q.dropped++
			continue
		}
		q.batches = append(q.batches, queued{seq: seq, size: int64(len(raw)), batch: &b})
		q.bytes += int64(len(raw))
		q.next = max(q.next, seq+1)
	}
	slices.SortFunc(q.batches, func(a, b queued) int { return compare(a.seq, b.seq) })
	return q, nil
}

func compare(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func batchSeq(name string) (uint64, bool) {
	s, ok := strings.CutSuffix(name, batchSuffix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func batchName(seq uint64) string { return fmt.Sprintf("%020d%s", seq, batchSuffix) }

func newBufferID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// add queues the events of an engine's batch, with what the engine and the
// queue dropped, dropping the oldest batches when over the bound.
func (q *queue) add(in *eventsv1.EventBatch) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := &eventsv1.EventBatch{Events: in.GetEvents(), Dropped: in.GetDropped() + q.dropped}
	raw, err := proto.Marshal(b)
	if err != nil {
		return err
	}
	size := int64(len(raw))
	if size > q.maxBytes {
		// Larger than the whole buffer: dropped, and counted.
		q.dropped = b.Dropped + uint64(len(b.Events))
		return nil
	}
	for len(q.batches) > 0 && q.bytes+size > q.maxBytes {
		old := q.batches[0]
		q.batches = q.batches[1:]
		q.bytes -= old.size
		// Its own dropped count goes on, with its events.
		b.Dropped += uint64(len(old.batch.GetEvents())) + old.batch.GetDropped()
		q.remove(old.seq)
	}
	if b.Dropped != in.GetDropped()+q.dropped {
		if raw, err = proto.Marshal(b); err != nil {
			return err
		}
		size = int64(len(raw))
	}
	seq := q.next
	if q.dir != "" {
		if err := q.write(seq, raw); err != nil {
			// Not on disk: keep the count, lose the events.
			q.dropped = b.Dropped + uint64(len(b.Events))
			return err
		}
	}
	q.next++
	q.dropped = 0
	q.batches = append(q.batches, queued{seq: seq, size: size, batch: b})
	q.bytes += size
	select {
	case q.changed <- struct{}{}:
	default:
	}
	return nil
}

func (q *queue) write(seq uint64, raw []byte) error {
	root, err := os.OpenRoot(q.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tmp := batchName(seq) + ".tmp"
	if err := root.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return root.Rename(tmp, batchName(seq))
}

func (q *queue) remove(seq uint64) {
	if q.dir == "" {
		return
	}
	if root, err := os.OpenRoot(q.dir); err == nil {
		_ = root.Remove(batchName(seq))
		_ = root.Close()
	}
}

func (q *queue) clearFiles(root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return fmt.Errorf("events buffer: %w", err)
	}
	for _, e := range entries {
		if _, ok := batchSeq(e.Name()); ok || strings.HasSuffix(e.Name(), ".tmp") {
			_ = root.Remove(e.Name())
		}
	}
	return nil
}

// after returns the batches after seq, in order, to send.
func (q *queue) after(seq uint64) []queued {
	q.mu.Lock()
	defer q.mu.Unlock()
	i, _ := slices.BinarySearchFunc(q.batches, seq+1, func(b queued, s uint64) int { return compare(b.seq, s) })
	return slices.Clone(q.batches[i:])
}

// ack frees the batches up to seq.
func (q *queue) ack(seq uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, b := range q.batches {
		if b.seq > seq {
			break
		}
		q.bytes -= b.size
		q.remove(b.seq)
		n++
	}
	q.batches = q.batches[n:]
}

// clear drops everything, when the control plane stops accepting events.
func (q *queue) clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, b := range q.batches {
		q.remove(b.seq)
	}
	q.batches, q.bytes, q.dropped = nil, 0, 0
}

// events counts the events waiting.
func (q *queue) events() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	var n uint64
	for _, b := range q.batches {
		n += uint64(len(b.batch.GetEvents()))
	}
	return n
}
