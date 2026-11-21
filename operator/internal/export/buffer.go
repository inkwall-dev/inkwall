// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// The export buffer (design 0010 §2.4): one per replica, shared by every
// sink. A log of batches, each held as its encoded protobuf, with a cursor
// per sink; a batch is freed once every sink has passed it, and when the
// buffer is full the oldest is dropped, counted as buffer_full by each sink
// that hadn't reached it.
//
// Two bounds: the newest batches are kept in memory, up to memMax; every
// batch is on disk, up to diskMax, when the buffer has a directory. Disk
// writes, removals and cursor files happen on the writer's goroutine, at
// most a second after Add, so a slow disk never slows an engine's stream.

// position is a place in the log: event idx of batch seq. Everything
// before it is passed: the batches before seq, and the events before idx.
type position struct {
	seq uint64
	idx int
}

func (p position) less(q position) bool {
	return p.seq < q.seq || p.seq == q.seq && p.idx < q.idx
}

func maxPos(p, q position) position {
	if p.less(q) {
		return q
	}
	return p
}

// stored is one batch.
type stored struct {
	seq uint64
	// raw is the batch's protobuf; nil when on disk only.
	raw      []byte
	size     int64
	events   int
	observed time.Time
	// before counts the events of the log before this batch, since the
	// buffer opened: pending counts are differences.
	before uint64
}

// sinkCursor is a sink's place in the log.
type sinkCursor struct {
	// acked: what the sink's answered requests cover, in order. Batches
	// before every sink's acked are freed.
	acked position
	// read: what the sender has taken (it holds the events between acked
	// and read in its requests). A dropped batch counts only the events
	// after read.
	read position
	// dropped counts the events dropped for a full buffer, for the sender
	// to take.
	dropped uint64
	// persisted is what the cursor file holds; "" name in removed.
	persisted position
	// hasFile: the cursor's file exists.
	hasFile bool
}

const (
	bufferIDFile  = "buffer-id"
	batchSuffix   = ".batch"
	cursorPrefix  = "cursor-"
	tmpSuffix     = ".tmp"
	batchMagic    = "IWX1"
	batchHeader   = 16 // magic, observed (unix ns), events
	writeInterval = time.Second
)

// buffer is the shared log.
type buffer struct {
	dir             string // "": memory only
	memMax, diskMax int64

	mu      sync.Mutex
	batches []*stored
	// memIdx: batches[memIdx:] are in memory (with a directory, the older
	// ones are on disk only).
	memIdx              int
	next                uint64
	memBytes, allBytes  int64
	events, totalEvents uint64 // events held; events ever added (and loaded)
	cursors             map[string]*sinkCursor
	// midDropped counts the events of the batches dropped from the middle
	// of the log (dropAt); gaps lists those still ahead of the oldest
	// batch, gapBase the count before them.
	midDropped, gapBase uint64
	gaps                []gap
	// configured: the sinks are known (setSinks ran). Before, batches are
	// kept for the cursors loaded from disk.
	configured bool
	changed    chan struct{}

	// The writer's state. written: the highest batch on disk (or given up
	// on); removeBelow: files of batches below it go; removedCursors:
	// cursor files to remove.
	diskOK         bool
	written        uint64
	removeBelow    uint64
	removedThrough uint64
	removedCursors []string
	wake           chan struct{}
	writerDone     chan struct{}
	stop           chan struct{}
	stopOnce       sync.Once
	// onDiskError reports the writer's first failure: the buffer goes on in
	// memory.
	onDiskError func(error)
	now         func() time.Time
}

// openBuffer loads what dir holds (a batch file per batch, a cursor file
// per sink), or starts an empty buffer; "" keeps everything in memory.
func openBuffer(dir string, memMax, diskMax int64) (*buffer, error) {
	b := &buffer{
		dir: dir, memMax: memMax, diskMax: diskMax, next: 1,
		cursors: map[string]*sinkCursor{}, changed: make(chan struct{}),
		wake: make(chan struct{}, 1), writerDone: make(chan struct{}), stop: make(chan struct{}),
		now: time.Now,
	}
	if dir == "" {
		return b, nil
	}
	if err := b.load(); err != nil {
		return nil, err
	}
	b.diskOK = true
	return b, nil
}

func (b *buffer) load() error {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return fmt.Errorf("export buffer: %w", err)
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return fmt.Errorf("export buffer: %w", err)
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return fmt.Errorf("export buffer: %w", err)
	}
	if _, err := root.Stat(bufferIDFile); errors.Is(err, fs.ErrNotExist) {
		// A new buffer: whatever is left there belongs to no buffer.
		for _, e := range entries {
			if n := e.Name(); strings.HasSuffix(n, batchSuffix) || strings.HasSuffix(n, tmpSuffix) || strings.HasPrefix(n, cursorPrefix) {
				_ = root.Remove(n)
			}
		}
		return root.WriteFile(bufferIDFile, []byte(newBufferID()), 0o600)
	} else if err != nil {
		return fmt.Errorf("export buffer: %w", err)
	}
	var highest uint64
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, tmpSuffix):
			// A write a crash interrupted.
			_ = root.Remove(name)
		case strings.HasSuffix(name, batchSuffix):
			seq, ok := batchSeq(name)
			if !ok {
				continue
			}
			s, err := readHeader(root, name)
			if err != nil {
				// A torn file: its events are lost.
				_ = root.Remove(name)
				continue
			}
			s.seq = seq
			b.batches = append(b.batches, s)
			highest = max(highest, seq)
		case strings.HasPrefix(name, cursorPrefix):
			sink := strings.TrimPrefix(name, cursorPrefix)
			raw, err := root.ReadFile(name)
			p, ok := parsePosition(string(raw))
			if err != nil || !ok {
				_ = root.Remove(name)
				continue
			}
			b.cursors[sink] = &sinkCursor{acked: p, read: p, persisted: p, hasFile: true}
			highest = max(highest, p.seq)
		}
	}
	slices.SortFunc(b.batches, func(x, y *stored) int { return cmp.Compare(x.seq, y.seq) })
	for _, s := range b.batches {
		s.before = b.totalEvents
		b.totalEvents += count(s.events)
		b.events += count(s.events)
		b.allBytes += b.footprint(s.size)
	}
	b.memIdx = len(b.batches)
	// A new batch never takes a number a cursor has passed.
	b.next = highest + 1
	b.written = b.next - 1
	b.removeBelow = b.next
	if len(b.batches) > 0 {
		b.removeBelow = b.batches[0].seq
	}
	b.removedThrough = b.removeBelow - 1
	return nil
}

func readHeader(root *os.Root, name string) (*stored, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var h [batchHeader]byte
	if _, err := io.ReadFull(f, h[:]); err != nil {
		return nil, err
	}
	if string(h[:4]) != batchMagic {
		return nil, errors.New("not a batch")
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[12:])
	if st.Size() <= batchHeader || n == 0 {
		return nil, errors.New("empty batch")
	}
	return &stored{
		size:     st.Size() - batchHeader,
		events:   int(n),
		observed: time.Unix(0, int64(binary.BigEndian.Uint64(h[4:12]))), // #nosec G115 -- a time we wrote
	}, nil
}

func batchSeq(name string) (uint64, bool) {
	s, ok := strings.CutSuffix(name, batchSuffix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n > 0
}

func batchName(seq uint64) string { return fmt.Sprintf("%020d%s", seq, batchSuffix) }

func parsePosition(s string) (position, bool) {
	a, c, ok := strings.Cut(strings.TrimSpace(s), " ")
	if !ok {
		return position{}, false
	}
	seq, err1 := strconv.ParseUint(a, 10, 64)
	idx, err2 := strconv.Atoi(c)
	if err1 != nil || err2 != nil || idx < 0 || seq == 0 {
		return position{}, false
	}
	return position{seq, idx}, true
}

func newBufferID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// end is the position past the last batch.
func (b *buffer) end() position { return position{seq: b.next} }

// setSinks makes names the sinks: a new one starts at the end, a removed
// one frees its cursor and what only it was waiting for. With none, the
// buffer empties and Add keeps nothing.
func (b *buffer) setSinks(names []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
		if _, ok := b.cursors[n]; !ok {
			b.cursors[n] = &sinkCursor{acked: b.end(), read: b.end()}
		}
	}
	for n, c := range b.cursors {
		if !keep[n] {
			delete(b.cursors, n)
			if c.hasFile {
				b.removedCursors = append(b.removedCursors, n)
			}
		}
	}
	b.configured = true
	b.free()
	b.signal()
}

// add appends an engine's batch. It never blocks on the disk or on a
// sink; over a bound, the oldest batches go.
func (b *buffer) add(in *eventsv1.EventBatch) {
	if len(in.GetEvents()) == 0 {
		return
	}
	b.mu.Lock()
	idle := b.configured && len(b.cursors) == 0
	b.mu.Unlock()
	if idle {
		return
	}
	// Encoded outside the lock: the events are read only.
	raw, err := proto.Marshal(&eventsv1.EventBatch{Events: in.GetEvents()})
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(in.GetEvents())
	size := int64(len(raw))
	if size > b.memMax {
		// Larger than the memory bound: dropped for every sink.
		for _, c := range b.cursors {
			c.dropped += count(n)
		}
		b.signal()
		return
	}
	s := &stored{seq: b.next, raw: raw, size: size, events: n, observed: b.now(), before: b.totalEvents}
	b.next++
	b.batches = append(b.batches, s)
	b.memBytes += size
	b.allBytes += b.footprint(size)
	b.events += count(n)
	b.totalEvents += count(n)
	b.enforce()
	b.signal()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// enforce drops or evicts, with b.mu held, until both bounds hold.
func (b *buffer) enforce() {
	limit := b.memMax
	if b.dir != "" {
		limit = b.diskMax
	}
	for b.allBytes > limit && len(b.batches) > 0 {
		b.dropFront()
	}
	for b.memBytes > b.memMax && len(b.batches) > 0 {
		if b.memIdx < len(b.batches) {
			s := b.batches[b.memIdx]
			if b.dir != "" && s.seq <= b.written {
				// On disk already (also if the disk failed since: it stays
				// readable): memory keeps the newest.
				s.raw = nil
				b.memBytes -= s.size
				b.memIdx++
				continue
			}
		}
		if b.memIdx >= len(b.batches) {
			return
		}
		// Not on disk (no directory, the disk failed, or the writer is a
		// whole memory bound behind): the oldest batch in memory goes. The
		// batches on disk only hold no memory: only the disk bound drops
		// them.
		b.dropAt(b.memIdx)
	}
}

// dropAt drops batch i for a full buffer: the oldest, or the oldest in
// memory, which leaves a gap the cursors skip (take looks for the next
// batch after a position).
func (b *buffer) dropAt(i int) {
	if i == 0 {
		b.dropFront()
		return
	}
	s := b.batches[i]
	past := position{seq: s.seq + 1}
	for _, c := range b.cursors {
		// A cursor before the batch loses its events when it gets there:
		// they are counted now. One inside it skips the rest.
		if c.read.less(past) {
			lost := s.events
			if c.read.seq == s.seq {
				lost -= c.read.idx
				c.read = past
			}
			c.dropped += count(lost)
		}
		if c.acked.seq == s.seq {
			c.acked = past
		}
	}
	b.batches = slices.Delete(b.batches, i, i+1)
	if s.raw != nil {
		b.memBytes -= s.size
	}
	b.allBytes -= b.footprint(s.size)
	b.events -= count(s.events)
	b.midDropped += count(s.events)
	b.gaps = append(b.gaps, gap{seq: s.seq, cum: b.midDropped})
}

// gap is a batch dropped from the middle of the log; cum counts the events
// of every such batch up to it, for pending.
type gap struct {
	seq uint64
	cum uint64
}

// droppedBefore counts the events of the gaps before seq, with b.mu held.
func (b *buffer) droppedBefore(seq uint64) uint64 {
	i, _ := slices.BinarySearchFunc(b.gaps, seq, func(g gap, s uint64) int { return cmp.Compare(g.seq, s) })
	if i == 0 {
		return b.gapBase
	}
	return b.gaps[i-1].cum
}

// dropFront drops the oldest batch for a full buffer.
func (b *buffer) dropFront() {
	s := b.batches[0]
	past := position{seq: s.seq + 1}
	for _, c := range b.cursors {
		if c.read.less(past) {
			lost := s.events
			if c.read.seq == s.seq {
				lost -= c.read.idx
			}
			c.dropped += count(lost)
			c.read = past
		}
		c.acked = maxPos(c.acked, past)
	}
	b.popFront()
}

// popFront removes the oldest batch, with b.mu held.
func (b *buffer) popFront() {
	s := b.batches[0]
	b.batches[0] = nil
	b.batches = b.batches[1:]
	if b.memIdx > 0 {
		b.memIdx--
	}
	if s.raw != nil {
		b.memBytes -= s.size
	}
	b.allBytes -= b.footprint(s.size)
	b.events -= count(s.events)
	b.removeBelow = s.seq + 1
	// Gaps behind the oldest batch count for no cursor any more.
	for len(b.gaps) > 0 && b.gaps[0].seq < s.seq {
		b.gapBase = b.gaps[0].cum
		b.gaps = b.gaps[1:]
	}
}

// free removes the batches every sink has passed, with b.mu held.
func (b *buffer) free() {
	if !b.configured {
		return
	}
	for len(b.batches) > 0 {
		s := b.batches[0]
		for _, c := range b.cursors {
			if c.acked.seq <= s.seq {
				return
			}
		}
		b.popFront()
	}
	if len(b.batches) == 0 {
		b.removeBelow = b.next
	}
}

// signal wakes the senders, with b.mu held.
func (b *buffer) signal() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// changedCh is closed when the buffer changes next.
func (b *buffer) changedCh() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.changed
}

// taken is a batch a sender took.
type taken struct {
	seq      uint64
	from     int // the first event the sink hasn't taken
	raw      []byte
	events   int
	observed time.Time
}

// take hands sink the next batch after what it took, and a channel closed
// when there is more. ok is false when it has taken everything; a batch on
// disk only comes without raw (readBatch reads it).
func (b *buffer) take(sink string) (t taken, ok bool, changed <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cursors[sink]
	if c == nil {
		return taken{}, false, b.changed
	}
	i, _ := slices.BinarySearchFunc(b.batches, c.read.seq, func(s *stored, seq uint64) int { return cmp.Compare(s.seq, seq) })
	for ; i < len(b.batches); i++ {
		s := b.batches[i]
		from := 0
		if s.seq == c.read.seq {
			from = c.read.idx
		}
		c.read = position{seq: s.seq + 1}
		if from >= s.events {
			continue
		}
		return taken{seq: s.seq, from: from, raw: s.raw, events: s.events, observed: s.observed}, true, b.changed
	}
	return taken{}, false, b.changed
}

// readBatch reads a batch that is on disk only. ok is false when it is
// gone (dropped meanwhile) or torn.
func (b *buffer) readBatch(seq uint64) ([]byte, bool) {
	if b.dir == "" {
		return nil, false
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return nil, false
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(batchName(seq))
	if err != nil || len(raw) <= batchHeader || string(raw[:4]) != batchMagic {
		return nil, false
	}
	return raw[batchHeader:], true
}

// commit moves sink's cursor to p, once its requests up to p are answered,
// and frees what every sink has passed. The writer persists it.
func (b *buffer) commit(sink string, p position) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cursors[sink]
	if c == nil {
		return
	}
	// Past a batch's last event is the next batch: the batch can go.
	if i, ok := slices.BinarySearchFunc(b.batches, p.seq, func(s *stored, seq uint64) int { return cmp.Compare(s.seq, seq) }); ok && p.idx >= b.batches[i].events {
		p = position{seq: p.seq + 1}
	}
	c.acked = maxPos(c.acked, p)
	c.read = maxPos(c.read, c.acked)
	b.free()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// acked is sink's cursor.
func (b *buffer) acked(sink string) position {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.cursors[sink]; c != nil {
		return c.acked
	}
	return b.end()
}

// takeDropped returns and resets the events dropped for sink for a full
// buffer.
func (b *buffer) takeDropped(sink string) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cursors[sink]
	if c == nil {
		return 0
	}
	n := c.dropped
	c.dropped = 0
	return n
}

// pending counts the events sink hasn't had answered.
func (b *buffer) pending(sink string) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cursors[sink]
	if c == nil || len(b.batches) == 0 {
		return 0
	}
	i, found := slices.BinarySearchFunc(b.batches, c.acked.seq, func(s *stored, seq uint64) int { return cmp.Compare(s.seq, seq) })
	if i == len(b.batches) {
		return 0
	}
	at := b.batches[i].before
	if found {
		at += count(min(c.acked.idx, b.batches[i].events))
	}
	// Less the events of the batches dropped from the middle since.
	return b.totalEvents - at - (b.midDropped - b.droppedBefore(b.batches[i].seq))
}

// bytes is the buffer's size: every batch, in memory or on disk.
func (b *buffer) bytes() (memory, all int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.memBytes, b.allBytes
}

// run is the writer: batch files, removals and cursor files, until close.
func (b *buffer) run() {
	defer close(b.writerDone)
	if b.dir == "" {
		<-b.stop
		return
	}
	tick := time.NewTicker(writeInterval)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			b.writeRound()
			return
		case <-b.wake:
		case <-tick.C:
		}
		b.writeRound()
	}
}

// close stops the writer once it has written what it holds.
func (b *buffer) close() {
	b.stopOnce.Do(func() { close(b.stop) })
	<-b.writerDone
}

type toWrite struct {
	seq      uint64
	raw      []byte
	events   int
	observed time.Time
}

// writeRound writes the batches not on disk yet, then removes the files
// of dropped and freed batches, then writes the cursors that moved: never
// past a batch that isn't on disk.
func (b *buffer) writeRound() {
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		b.diskFailed(err)
		return
	}
	defer func() { _ = root.Close() }()
	b.writeBatches(root)
	b.persist(root)
}

// writeBatches writes the batches not on disk yet, in order.
func (b *buffer) writeBatches(root *os.Root) {
	b.mu.Lock()
	var pending []toWrite
	if b.diskOK {
		i, _ := slices.BinarySearchFunc(b.batches, b.written+1, func(s *stored, seq uint64) int { return cmp.Compare(s.seq, seq) })
		for _, s := range b.batches[i:] {
			pending = append(pending, toWrite{s.seq, s.raw, s.events, s.observed})
		}
	}
	b.mu.Unlock()
	var last uint64
	for _, w := range pending {
		if err := writeFile(root, batchName(w.seq), batchFile(w)); err != nil {
			b.diskFailed(err)
			break
		}
		last = w.seq
	}
	b.mu.Lock()
	if last > b.written {
		b.written = last
	}
	// A batch dropped from memory while it was written leaves a file no
	// batch owns: remove it. (Those below the oldest go with removeBelow.)
	var orphans []uint64
	for _, w := range pending {
		if w.seq > last || w.seq < b.removeBelow {
			continue
		}
		if _, ok := slices.BinarySearchFunc(b.batches, w.seq, func(s *stored, seq uint64) int { return cmp.Compare(s.seq, seq) }); !ok {
			orphans = append(orphans, w.seq)
		}
	}
	b.mu.Unlock()
	for _, seq := range orphans {
		_ = root.Remove(batchName(seq))
	}
}

// persist removes the files of dropped and freed batches and of removed
// sinks, and writes the cursors that moved, each capped at the last batch
// on disk.
func (b *buffer) persist(root *os.Root) {
	b.mu.Lock()
	below, from, written := b.removeBelow, b.removedThrough+1, b.written
	if below > 0 && below-1 > b.removedThrough {
		b.removedThrough = below - 1
	}
	removed := b.removedCursors
	b.removedCursors = nil
	type cursorWrite struct {
		name string
		p    position
	}
	var cursors []cursorWrite
	if b.diskOK {
		limit := position{seq: b.written + 1}
		for name, c := range b.cursors {
			p := c.acked
			if limit.less(p) {
				p = limit
			}
			if !c.hasFile || p != c.persisted {
				cursors = append(cursors, cursorWrite{name, p})
			}
		}
	}
	b.mu.Unlock()

	// Only batches up to written ever had a file.
	for s := from; s < below && s <= written; s++ {
		_ = root.Remove(batchName(s))
	}
	for _, n := range removed {
		_ = root.Remove(cursorPrefix + n)
	}
	for _, cw := range cursors {
		if err := writeFile(root, cursorPrefix+cw.name, fmt.Appendf(nil, "%d %d\n", cw.p.seq, cw.p.idx)); err != nil {
			b.diskFailed(err)
			return
		}
		b.mu.Lock()
		if c := b.cursors[cw.name]; c != nil {
			c.persisted, c.hasFile = cw.p, true
		}
		b.mu.Unlock()
	}
}

func batchFile(w toWrite) []byte {
	out := make([]byte, batchHeader, batchHeader+len(w.raw))
	copy(out, batchMagic)
	binary.BigEndian.PutUint64(out[4:12], uint64(w.observed.UnixNano())) // #nosec G115 -- a time after 1970
	binary.BigEndian.PutUint32(out[12:], uint32(min(w.events, 1<<31)))   // #nosec G115 -- capped
	return append(out, w.raw...)
}

// diskBlock is the unit a file takes on disk: the kubelet measures an
// emptyDir's use in blocks, so a small file counts as a whole one.
const diskBlock = 4 << 10

// footprint is what a batch of size bytes counts toward the bounds: with a
// directory, its file rounded up to whole blocks, so the disk bound holds
// as the kubelet measures the emptyDir (its sizeLimit); in memory, its size.
func (b *buffer) footprint(size int64) int64 {
	if b.dir == "" {
		return size
	}
	return (size + batchHeader + diskBlock - 1) / diskBlock * diskBlock
}

// count is n as a count: never below 0.
func count(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n) // #nosec G115 -- not negative
}

// asInt is a count as an int, capped.
func asInt(n uint64) int {
	if n > 1<<31-1 {
		return 1<<31 - 1
	}
	return int(n) // #nosec G115 -- capped
}

func writeFile(root *os.Root, name string, data []byte) error {
	tmp := name + tmpSuffix
	if err := root.WriteFile(tmp, data, 0o600); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return root.Rename(tmp, name)
}

// diskFailed puts the buffer in memory for the rest of the process: the
// batches on disk stay readable, new ones stay in memory, up to memMax.
func (b *buffer) diskFailed(err error) {
	b.mu.Lock()
	was := b.diskOK
	b.diskOK = false
	b.enforce()
	b.mu.Unlock()
	if was && b.onDiskError != nil {
		b.onDiskError(err)
	}
}
