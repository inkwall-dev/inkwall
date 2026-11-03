// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// frame builds a client frame: masked with key unless key is nil.
func frame(fin bool, op byte, payload []byte, key *[4]byte) []byte {
	b0 := op
	if fin {
		b0 |= finBit
	}
	f := []byte{b0}
	var m byte
	if key != nil {
		m = maskBit
	}
	switch n := len(payload); {
	case n < 126:
		f = append(f, m|byte(n))
	case n <= 0xffff:
		f = append(f, m|126, byte(n>>8), byte(n))
	default:
		f = append(f, m|127)
		f = binary.BigEndian.AppendUint64(f, uint64(n))
	}
	p := append([]byte(nil), payload...)
	if key != nil {
		f = append(f, key[:]...)
		Mask(*key, 0, p)
	}
	return append(f, p...)
}

var key = &[4]byte{0x37, 0xfa, 0x21, 0x3d}

func reader(b []byte, limit int64) *Reader {
	return NewReader(bufio.NewReader(bytes.NewReader(b)), limit)
}

// TestRFCExample: RFC 6455 §5.7, "a single-frame masked text message".
func TestRFCExample(t *testing.T) {
	raw := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	r := reader(raw, 1024)
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Fin || f.Opcode != OpText || string(f.Payload) != "Hello" || !bytes.Equal(f.Raw, raw) || f.Truncated {
		t.Fatalf("frame %+v", f)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last frame: %v, want EOF", err)
	}
}

// TestFragments: a message in fragments, a ping between them (RFC 6455
// §5.4), and lengths in 16 and 64 bits.
func TestFragments(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 70000)
	var in []byte
	in = append(in, frame(false, OpText, []byte("Hel"), key)...)
	in = append(in, frame(true, OpPing, []byte("ping"), key)...)
	in = append(in, frame(true, OpContinuation, []byte("lo"), key)...)
	in = append(in, frame(true, OpBinary, big[:300], key)...)
	in = append(in, frame(true, OpBinary, big, key)...)
	r := reader(in, 1<<20)
	want := []struct {
		fin     bool
		op      byte
		payload string
	}{
		{false, OpText, "Hel"}, {true, OpPing, "ping"}, {true, OpContinuation, "lo"},
		{true, OpBinary, string(big[:300])}, {true, OpBinary, string(big)},
	}
	var raw []byte
	for i, w := range want {
		f, err := r.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.Fin != w.fin || f.Opcode != w.op || string(f.Payload) != w.payload {
			t.Fatalf("frame %d: fin %v op %d payload %d bytes", i, f.Fin, f.Opcode, len(f.Payload))
		}
		raw = append(raw, f.Raw...)
	}
	if !bytes.Equal(raw, in) {
		t.Fatal("the raw frames aren't the input")
	}
}

func TestProtocolErrors(t *testing.T) {
	long := func(n uint16) []byte { // a 16-bit length
		return append([]byte{0x82, maskBit | 126, byte(n >> 8), byte(n)}, make([]byte, 4+int(n))...)
	}
	tests := []struct {
		name string
		in   []byte
	}{
		{"unmasked", frame(true, OpText, []byte("x"), nil)},
		{"rsv1 (permessage-deflate)", func() []byte { f := frame(true, OpText, []byte("x"), key); f[0] |= 0x40; return f }()},
		{"unknown opcode", frame(true, 0x3, nil, key)},
		{"control over 125 bytes", frame(true, OpPing, make([]byte, 126), key)},
		{"fragmented control", frame(false, OpPing, nil, key)},
		{"continuation without a message", frame(true, OpContinuation, []byte("x"), key)},
		{"new message inside one", append(frame(false, OpText, []byte("a"), key), frame(true, OpText, []byte("b"), key)...)},
		{"16-bit length under 126", long(100)},
		{"64-bit length under 65536", append([]byte{0x82, maskBit | 127, 0, 0, 0, 0, 0, 0, 1, 0}, make([]byte, 4+256)...)},
		{"64-bit length with the top bit", []byte{0x82, maskBit | 127, 0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := reader(tt.in, 1024)
			var err error
			for err == nil {
				_, err = r.Next()
			}
			var we *Error
			if !errors.As(err, &we) || we.Code != CloseProtocolError {
				t.Fatalf("got %v, want a protocol error", err)
			}
		})
	}
}

func TestCut(t *testing.T) {
	full := frame(true, OpText, []byte("Hello"), key)
	for i := 1; i < len(full); i++ {
		r := reader(full[:i], 1024)
		if _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("cut at %d: %v, want unexpected EOF", i, err)
		}
	}
}

// TestLimit: past the limit, a message's payload isn't kept: the rest of
// a frame is read raw, and the next message has the whole limit again.
func TestLimit(t *testing.T) {
	var in []byte
	in = append(in, frame(false, OpText, []byte("Hello"), key)...)
	in = append(in, frame(true, OpContinuation, []byte(" world"), key)...)
	in = append(in, frame(true, OpText, []byte("abcd"), key)...)
	r := reader(in, 3)

	f, err := r.Next()
	if err != nil || !f.Truncated || string(f.Payload) != "Hel" || r.Pending() != 2 {
		t.Fatalf("first frame %+v, %v, pending %d", f, err, r.Pending())
	}
	if _, err := r.Next(); err == nil {
		t.Fatal("Next with the rest of a frame unread")
	}
	raw := append([]byte(nil), f.Raw...)
	rest, err := io.ReadAll(readerFunc(r.ReadRest))
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, rest...)
	f, err = r.Next()
	if err != nil || !f.Truncated || len(f.Payload) != 0 || r.Pending() != 6 {
		t.Fatalf("continuation %+v, %v, pending %d", f, err, r.Pending())
	}
	raw = append(raw, f.Raw...)
	rest, _ = io.ReadAll(readerFunc(r.ReadRest))
	raw = append(raw, rest...)
	f, err = r.Next()
	if err != nil || !f.Truncated || string(f.Payload) != "abc" {
		t.Fatalf("next message %+v, %v", f, err)
	}
	raw = append(raw, f.Raw...)
	rest, _ = io.ReadAll(readerFunc(r.ReadRest))
	raw = append(raw, rest...)
	if !bytes.Equal(raw, in) {
		t.Fatal("the raw bytes aren't the input")
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

func TestCloseFrame(t *testing.T) {
	f, err := reader(CloseFrame(ClosePolicyViolation, "policy violation", key), 1024).Next()
	if err != nil || f.Opcode != OpClose || binary.BigEndian.Uint16(f.Payload) != ClosePolicyViolation || string(f.Payload[2:]) != "policy violation" {
		t.Fatalf("masked close %+v, %v", f, err)
	}
	server := CloseFrame(CloseMessageTooBig, strings.Repeat("x", 200), nil)
	if server[0] != 0x88 || server[1] != 125 || len(server) != 127 || binary.BigEndian.Uint16(server[2:]) != CloseMessageTooBig {
		t.Fatalf("server close % x", server[:4])
	}
}

// TestTracker: the boundaries between a server's frames, however its bytes
// are split.
func TestTracker(t *testing.T) {
	frames := [][]byte{
		frame(true, OpText, []byte("hello"), nil),
		frame(true, OpBinary, nil, nil),
		frame(true, OpBinary, make([]byte, 300), nil),
		frame(true, OpText, make([]byte, 70000), nil),
		frame(true, OpPong, []byte("p"), key), // masked: still framed
	}
	var stream []byte
	ends := map[int]bool{}
	for _, f := range frames {
		stream = append(stream, f...)
		ends[len(stream)] = true
	}
	for _, chunk := range []int{1, 2, 3, 7, 64, 1000, len(stream)} {
		var tr Tracker
		pos := 0
		for pos < len(stream) {
			b := stream[pos:min(pos+chunk, len(stream))]
			for len(b) > 0 {
				n := tr.Split(b)
				pos += n
				b = b[n:]
				if tr.AtBoundary() != ends[pos] {
					t.Fatalf("chunk %d: at %d boundary %v, want %v", chunk, pos, tr.AtBoundary(), ends[pos])
				}
			}
		}
	}
}
