// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/binary"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// droppedSize is the most EventBatch.dropped takes encoded: its tag and a
// 64-bit varint.
const droppedSize = 1 + binary.MaxVarintLen64

// Split cuts batch into batches of at most maxBytes encoded each, in order,
// so each fits a message limit. The first carries batch's dropped count. An
// event over maxBytes on its own (not one New makes) is left out and counted
// as dropped.
func Split(batch *eventsv1.EventBatch, maxBytes int) []*eventsv1.EventBatch {
	if proto.Size(batch) <= maxBytes {
		return []*eventsv1.EventBatch{batch}
	}
	limit := maxBytes - droppedSize
	var out []*eventsv1.EventBatch
	cur := &eventsv1.EventBatch{Dropped: batch.GetDropped()}
	size := 0
	for _, ev := range batch.GetEvents() {
		n := protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(ev))
		if n > limit {
			cur.Dropped++
			continue
		}
		if size+n > limit {
			out = append(out, cur)
			cur, size = &eventsv1.EventBatch{}, 0
		}
		cur.Events = append(cur.Events, ev)
		size += n
	}
	if len(cur.GetEvents()) > 0 || cur.GetDropped() > 0 || len(out) == 0 {
		out = append(out, cur)
	}
	return out
}
