// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package websocket

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// maskedFrame is a client's frame: masked, with a 16-bit length when
// needed.
func maskedFrame(fin bool, op byte, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= finBit
	}
	f := []byte{b0}
	if n := len(payload); n < 126 {
		f = append(f, maskBit|byte(n))
	} else {
		f = append(f, maskBit|126, byte(n>>8), byte(n))
	}
	key := [4]byte{1, 2, 3, 4}
	f = append(f, key[:]...)
	p := append([]byte(nil), payload...)
	Mask(key, 0, p)
	return append(f, p...)
}

// BenchmarkWebSocketFrame (#369): reading a client's frames as the
// standalone proxy does with --websocket-messages: header, unmasking, and
// keeping the payload up to the limit.
func BenchmarkWebSocketFrame(b *testing.B) {
	chat := []byte(`{"type":"message","room":"general","text":"hello, how is everyone today?"}`)
	cases := []struct {
		name   string
		frames []byte
		n      int // frames in it
	}{
		{"text_small", maskedFrame(true, OpText, chat), 1},
		{"text_4k", maskedFrame(true, OpText, []byte(strings.Repeat("x", 4<<10))), 1},
		{"fragmented_3", append(append(maskedFrame(false, OpText, chat), maskedFrame(false, OpContinuation, chat)...), maskedFrame(true, OpContinuation, chat)...), 3},
		{"truncated_64k", maskedFrame(true, OpBinary, make([]byte, 60<<10)), 1},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.frames)))
			src := bytes.NewReader(c.frames)
			br := bufio.NewReaderSize(src, 4096)
			buf := make([]byte, 32<<10)
			for b.Loop() {
				src.Reset(c.frames)
				br.Reset(src)
				r := NewReader(br, 16<<10)
				for range c.n {
					f, err := r.Next()
					if err != nil {
						b.Fatal(err)
					}
					for f.Truncated && r.Pending() > 0 {
						if _, err := r.ReadRest(buf); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}
