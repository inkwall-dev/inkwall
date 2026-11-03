// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package websocket

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzReader: a client's bytes are the attacker's. Reading them never
// panics; the frames' raw bytes, with the rest of each truncated frame, are
// exactly the bytes read; no message keeps more than the limit; and a
// frame is returned only if it keeps the protocol's rules.
func FuzzReader(f *testing.F) {
	f.Add([]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}, uint16(16))
	f.Add(append(frame(false, OpText, []byte("Hel"), key), append(frame(true, OpPing, nil, key), frame(true, OpContinuation, []byte("lo"), key)...)...), uint16(2))
	f.Add(frame(true, OpBinary, bytes.Repeat([]byte{0}, 300), key), uint16(100))
	f.Add(CloseFrame(ClosePolicyViolation, "bye", key), uint16(0))
	f.Fuzz(func(t *testing.T, in []byte, limit uint16) {
		r := reader(in, int64(limit))
		var raw []byte
		var kept int
		open := false
		for {
			fr, err := r.Next()
			if err != nil {
				var we *Error
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.As(err, &we) {
					t.Fatalf("error %v", err)
				}
				break
			}
			if fr.Control() {
				if !fr.Fin || len(fr.Payload) > maxControlPayload || fr.Truncated {
					t.Fatalf("control frame %+v", fr)
				}
			} else {
				if (fr.Opcode == OpContinuation) != open {
					t.Fatalf("opcode %d with a message open: %v", fr.Opcode, open)
				}
				if fr.Opcode != OpContinuation {
					kept = 0
				}
				kept += len(fr.Payload)
				if kept > int(limit) {
					t.Fatalf("kept %d bytes of a message, limit %d", kept, limit)
				}
				open = !fr.Fin
			}
			raw = append(raw, fr.Raw...)
			rest, err := io.ReadAll(readerFunc(r.ReadRest))
			raw = append(raw, rest...)
			if err != nil {
				break
			}
		}
		if !bytes.HasPrefix(in, raw) {
			t.Fatalf("raw bytes aren't the input's prefix")
		}
	})
}

// FuzzTracker: whatever a server sends, Split always makes progress and
// never reports more bytes than it was given.
func FuzzTracker(f *testing.F) {
	f.Add(frame(true, OpText, []byte("hello"), nil), uint8(3))
	f.Add([]byte{0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint8(1))
	f.Fuzz(func(t *testing.T, in []byte, chunk uint8) {
		var tr Tracker
		c := int(chunk) + 1
		for len(in) > 0 {
			b := in[:min(c, len(in))]
			n := tr.Split(b)
			if n <= 0 || n > len(b) {
				t.Fatalf("Split(%d bytes) = %d", len(b), n)
			}
			in = in[n:]
		}
	})
}
