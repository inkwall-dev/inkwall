// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package websocket reads the frames of a WebSocket connection (RFC 6455
// §5), so that the engine's reverse proxy can inspect a client's messages
// before it forwards them (#276).
//
// A Reader reads what a client sends: every frame masked, no extension
// (the proxy removes Sec-WebSocket-Extensions from the handshake, so
// permessage-deflate is never negotiated and a frame with an RSV bit is an
// error), control frames whole and at most 125 bytes, interleaved with the
// fragments of a message. It returns each frame as it came, raw, so that it
// can be forwarded unchanged, with the payload unmasked. A Tracker follows
// what a server sends, to find the boundaries between its frames.
package websocket

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Opcodes (RFC 6455 §5.2).
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xa
)

// Close codes (RFC 6455 §7.4.1).
const (
	CloseProtocolError    = 1002
	CloseUnsupportedData  = 1003
	CloseInvalidPayload   = 1007
	ClosePolicyViolation  = 1008
	CloseMessageTooBig    = 1009
	maxControlPayload     = 125
	maxFrameHeaderLength  = 14
	finBit, maskBit, rsvs = 0x80, 0x80, 0x70
)

// Error is a frame that breaks the protocol, and the close code that
// answers it.
type Error struct {
	Code   int
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("websocket: %s (close %d)", e.Reason, e.Code) }

func protocolError(format string, args ...any) error {
	return &Error{Code: CloseProtocolError, Reason: fmt.Sprintf(format, args...)}
}

// Frame is one frame a client sent.
type Frame struct {
	Fin    bool
	Opcode byte
	// Raw is the frame as it came: header, masking key and masked payload.
	Raw []byte
	// Payload is the unmasked payload, or as much of it as fits the
	// Reader's limit for its message (Truncated).
	Payload []byte
	// Truncated: the message is over the limit, and Raw and Payload end
	// where it was reached. The rest of the frame is still to be read, raw,
	// with ReadRest.
	Truncated bool
}

// Control reports whether f is a control frame (close, ping, pong).
func (f *Frame) Control() bool { return f.Opcode&0x8 != 0 }

// Reader reads a client's frames.
type Reader struct {
	r *bufio.Reader
	// limit bounds the payload kept of one data message.
	limit int64
	// inMessage: a fragmented data message is open; kept is how much of
	// its payload was kept.
	inMessage bool
	kept      int64
	// pending is what is left to read, raw, of a truncated frame.
	pending uint64
}

// NewReader returns a Reader of the frames on r, keeping at most limit
// payload bytes of each data message (the frames past it are returned
// raw, with Truncated set).
func NewReader(r *bufio.Reader, limit int64) *Reader {
	return &Reader{r: r, limit: limit}
}

// Next reads the next frame. It returns an *Error for a frame that breaks
// the protocol, io.EOF when the connection ends between frames, and
// io.ErrUnexpectedEOF when it ends inside one.
func (r *Reader) Next() (*Frame, error) {
	if r.pending > 0 {
		return nil, errors.New("websocket: the rest of a truncated frame is unread")
	}
	var head [maxFrameHeaderLength]byte
	if _, err := io.ReadFull(r.r, head[:2]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	f := &Frame{Fin: head[0]&finBit != 0, Opcode: head[0] & 0x0f}
	if head[0]&rsvs != 0 {
		return nil, protocolError("reserved bits set without an extension")
	}
	switch f.Opcode {
	case OpContinuation, OpText, OpBinary, OpClose, OpPing, OpPong:
	default:
		return nil, protocolError("unknown opcode %#x", f.Opcode)
	}
	if head[1]&maskBit == 0 {
		return nil, protocolError("unmasked frame from a client")
	}
	n := 2
	length := uint64(head[1] & 0x7f)
	switch length {
	case 126:
		if err := readFull(r.r, head[n:n+2]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(head[n:]))
		n += 2
		if length < 126 {
			return nil, protocolError("length not in its shortest form")
		}
	case 127:
		if err := readFull(r.r, head[n:n+8]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(head[n:])
		n += 8
		if length>>63 != 0 {
			return nil, protocolError("length with its most significant bit set")
		}
		if length <= 0xffff {
			return nil, protocolError("length not in its shortest form")
		}
	}
	if err := readFull(r.r, head[n:n+4]); err != nil {
		return nil, err
	}
	var key [4]byte
	copy(key[:], head[n:n+4])
	n += 4

	if f.Control() {
		if !f.Fin {
			return nil, protocolError("fragmented control frame")
		}
		if length > maxControlPayload {
			return nil, protocolError("control frame over 125 bytes")
		}
	} else {
		switch {
		case f.Opcode == OpContinuation && !r.inMessage:
			return nil, protocolError("continuation frame without a message")
		case f.Opcode != OpContinuation && r.inMessage:
			return nil, protocolError("new message inside a fragmented one")
		}
		if f.Opcode != OpContinuation {
			r.kept = 0
		}
		r.inMessage = !f.Fin
	}

	// A control frame is always kept whole (at most 125 bytes); a data
	// frame up to the message's limit, then only forwarded.
	keep := length
	if !f.Control() {
		room := uint64(max(r.limit-r.kept, 0))
		if keep > room {
			keep = room
			f.Truncated = true
		}
		r.kept += int64(keep) // #nosec G115 -- keep <= limit
	}
	f.Raw = make([]byte, n+int(keep)) // #nosec G115 -- keep <= limit or 125
	copy(f.Raw, head[:n])
	if err := readFull(r.r, f.Raw[n:]); err != nil {
		return nil, err
	}
	f.Payload = make([]byte, keep)
	copy(f.Payload, f.Raw[n:])
	Mask(key, 0, f.Payload)
	r.pending = length - keep
	return f, nil
}

// Pending returns how many raw bytes of a truncated frame are left to read.
func (r *Reader) Pending() uint64 { return r.pending }

// ReadRest reads raw bytes of the rest of a truncated frame into b; io.EOF
// once there are none.
func (r *Reader) ReadRest(b []byte) (int, error) {
	if r.pending == 0 {
		return 0, io.EOF
	}
	if uint64(len(b)) > r.pending {
		b = b[:r.pending]
	}
	n, err := r.r.Read(b)
	r.pending -= uint64(n) // #nosec G115 -- n >= 0
	if errors.Is(err, io.EOF) && r.pending > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func readFull(r io.Reader, b []byte) error {
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

// Mask XORs b with key, starting at offset pos in the payload: masking and
// unmasking are the same operation.
func Mask(key [4]byte, pos int, b []byte) {
	for i := range b {
		b[i] ^= key[(pos+i)&3]
	}
}

// CloseFrame returns a close frame with code and reason (at most 123
// bytes), masked with key when key isn't nil (a client's frame), unmasked
// otherwise (a server's).
func CloseFrame(code int, reason string, key *[4]byte) []byte {
	if len(reason) > maxControlPayload-2 {
		reason = reason[:maxControlPayload-2]
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, uint16(code)) // #nosec G115 -- close codes fit
	copy(payload[2:], reason)
	f := []byte{finBit | OpClose, byte(len(payload))} // #nosec G115 -- at most 125
	if key != nil {
		f[1] |= maskBit
		f = append(f, key[:]...)
		Mask(*key, 0, payload)
	}
	return append(f, payload...)
}

// Tracker follows a server's frames as their bytes pass, to tell when the
// stream is between two frames, where a frame of the proxy's own can go.
type Tracker struct {
	head    []byte // the current frame's header, while incomplete
	payload uint64 // payload bytes left in the current frame
}

// AtBoundary reports whether the bytes seen so far end with a whole frame.
func (t *Tracker) AtBoundary() bool { return len(t.head) == 0 && t.payload == 0 }

// Split returns how many bytes of b complete the current frame (all of b
// when it doesn't), and records them as seen.
func (t *Tracker) Split(b []byte) int {
	n := 0
	for n < len(b) {
		if t.payload > 0 {
			take := min(uint64(len(b)-n), t.payload)
			t.payload -= take
			n += int(take) // #nosec G115 -- at most len(b)
			if t.payload == 0 {
				return n
			}
			continue
		}
		t.head = append(t.head, b[n])
		n++
		need, ok := headerLength(t.head)
		if !ok || len(t.head) < need {
			continue
		}
		t.payload = payloadLength(t.head)
		t.head = t.head[:0]
		if t.payload == 0 {
			return n
		}
	}
	return n
}

// headerLength returns the length of the header that starts h, once h
// holds enough of it to tell.
func headerLength(h []byte) (int, bool) {
	if len(h) < 2 {
		return 0, false
	}
	n := 2
	switch h[1] & 0x7f {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	if h[1]&maskBit != 0 {
		n += 4
	}
	return n, true
}

func payloadLength(h []byte) uint64 {
	switch l := h[1] & 0x7f; l {
	case 126:
		return uint64(binary.BigEndian.Uint16(h[2:]))
	case 127:
		return binary.BigEndian.Uint64(h[2:])
	default:
		return uint64(l)
	}
}
