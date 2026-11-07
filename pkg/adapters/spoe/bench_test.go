// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// allowAll allows every request without rules: the benchmarks measure the
// adapter alone.
type allowAll struct{}

func (allowAll) Check(context.Context, *request.Request) pipeline.Verdict {
	return pipeline.Verdict{Action: pipeline.ActionAllow}
}

func (allowAll) BodyLimit(_ *request.Request, limit int64) int64 { return limit }

// BenchmarkSPOE (#369): the agent's work on a NOTIFY frame HAProxy 3.2
// sent, apart from the rules: reading the frame, decoding its message into
// a request, and encoding the ACK with the verdict.
func BenchmarkSPOE(b *testing.B) {
	raw := readFixture(b, "notify-get.bin")
	s, err := New(allowAll{}, Config{MaxBodyBytes: 64 << 10, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		b.Fatal(err)
	}
	peer := netip.MustParseAddr("127.0.0.1")
	b.Run("read_frame", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(raw)))
		buf := make([]byte, 0, 16<<10)
		for b.Loop() {
			if _, _, err := readFrame(bytes.NewReader(raw), buf, 16380, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	f := fixtureFrame(b, "notify-get.bin")
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, _, err := s.toRequest(f.payload, 16380); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("notify_ack", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ack := newFrame(frameAck, f.streamID, f.frameID)
			s.answer(context.Background(), ack, f.payload, 16380, peer)
			if len(ack.finish()) == 0 {
				b.Fatal("empty ACK")
			}
		}
	})
}
