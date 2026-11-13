// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package streams

import (
	"slices"
	"testing"
)

// FuzzSSEEvents fuzzes the splitters (#323): whatever the stream and
// wherever it is cut into chunks, the events are the same as from the
// stream in one piece, no event's data is over the limit, and the bytes
// held for the event in progress stay bounded.
func FuzzSSEEvents(f *testing.F) {
	f.Add([]byte("data: a\n\ndata: b\r\ndata: c\r\n\r\n: x\n\n"), uint16(3), uint8(16), false)
	f.Add([]byte("data:"+string(make([]byte, 40))+"\n\ndata: y\n\n"), uint16(10), uint8(8), false)
	f.Add(slices.Concat(frame(false, message("hello")), frame(true, gz(message("z")))), uint16(7), uint8(32), true)
	f.Add([]byte{0, 0, 0, 0, 200, 1, 2}, uint16(2), uint8(4), true)
	f.Fuzz(func(t *testing.T, stream []byte, cut uint16, max uint8, grpc bool) {
		kind, limit := SSE, int64(max)+1
		if grpc {
			kind = GRPC
		}
		whole := New(kind, limit, "gzip")
		want := append(whole.Write(stream), whole.Close()...)

		split := int(cut) % (len(stream) + 1)
		s := New(kind, limit, "gzip")
		got := s.Write(stream[:split])
		if s.Pending() > limit+grpcOrSSESlack {
			t.Fatalf("%d bytes held, limit %d", s.Pending(), limit)
		}
		got = append(got, s.Write(stream[split:])...)
		if s.Pending() > limit+grpcOrSSESlack {
			t.Fatalf("%d bytes held, limit %d", s.Pending(), limit)
		}
		got = append(got, s.Close()...)
		if len(got) != len(want) {
			t.Fatalf("split at %d: %d events, whole: %d", split, len(got), len(want))
		}
		for i := range got {
			if got[i].End != want[i].End || got[i].End > int64(len(stream)) || i > 0 && got[i].End < got[i-1].End {
				t.Fatalf("split at %d, event %d: ends at %d, whole: %d (stream %d bytes)", split, i, got[i].End, want[i].End, len(stream))
			}
			if string(got[i].Data) != string(want[i].Data) || got[i].Truncated != want[i].Truncated {
				t.Fatalf("split at %d, event %d: %q %v, whole: %q %v", split, i, got[i].Data, got[i].Truncated, want[i].Data, want[i].Truncated)
			}
			if int64(len(got[i].Data)) > limit {
				t.Fatalf("event %d: %d bytes, limit %d", i, len(got[i].Data), limit)
			}
		}
	})
}

// grpcOrSSESlack is what Pending may exceed the limit by: a gRPC message's
// prefix, or the line ending after the last data byte checked.
const grpcOrSSESlack = 5
