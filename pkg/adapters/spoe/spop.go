// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

// This file encodes and decodes SPOP, HAProxy's Stream Processing Offload
// Protocol (doc/SPOE.txt, section 3): frames, variable-length integers,
// typed data, key/value lists, messages and actions.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// Frame types.
const (
	frameHAProxyHello      = 1
	frameHAProxyDisconnect = 2
	frameNotify            = 3
	frameAgentHello        = 101
	frameAgentDisconnect   = 102
	frameAck               = 103
)

// Frame flags. Fragmentation is gone from SPOP: every frame carries FIN.
const (
	flagFin   = 1
	flagAbort = 2
)

// Status codes of a DISCONNECT frame.
const (
	statusNormal          = 0
	statusIO              = 1
	statusTimeout         = 2
	statusTooBig          = 3
	statusInvalid         = 4
	statusNoVersion       = 5
	statusNoFrameSize     = 6
	statusNoCapabilities  = 7
	statusBadVersion      = 8
	statusBadFrameSize    = 9
	statusFragmentation   = 10
	statusInterlaced      = 11
	statusUnknownFrameID  = 12
	statusResourceAlloc   = 13
	statusUnknown         = 99
	minFrameSize          = 256
	frameLengthFieldBytes = 4
)

// Data types of TYPED-DATA (the low 4 bits of its first byte).
const (
	typeNull   = 0
	typeBool   = 1
	typeInt32  = 2
	typeUint32 = 3
	typeInt64  = 4
	typeUint64 = 5
	typeIPv4   = 6
	typeIPv6   = 7
	typeString = 8
	typeBinary = 9
)

// Action types and variable scopes of an ACK frame.
const (
	actionSetVar   = 1
	actionUnsetVar = 2

	scopeProcess     = 0
	scopeSession     = 1
	scopeTransaction = 2
	scopeRequest     = 3
	scopeResponse    = 4
)

var (
	errTruncated = errors.New("truncated")
	errVarint    = errors.New("varint overflows 64 bits")
)

// frameTooBigError reports a frame over the negotiated maximum size.
type frameTooBigError struct{ size, max uint32 }

func (e frameTooBigError) Error() string {
	return fmt.Sprintf("frame of %d bytes, over the maximum of %d", e.size, e.max)
}

// appendVarint appends v in the encoding of HAProxy's peers protocol: below
// 240 a single byte; otherwise a first byte with the 4 low bits of v - 240
// and 0xF0, then 7 bits per byte, the high bit set on all but the last.
func appendVarint(dst []byte, v uint64) []byte {
	if v < 240 {
		return append(dst, byte(v))
	}
	dst = append(dst, byte(v&0xff)|240)
	v = (v - 240) >> 4
	for v >= 128 {
		dst = append(dst, byte(v&0x7f)|128)
		v = (v - 128) >> 7
	}
	return append(dst, byte(v))
}

// readVarint decodes a varint at the start of b and returns it and its
// length.
func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errTruncated
	}
	v := uint64(b[0])
	if v < 240 {
		return v, 1, nil
	}
	shift := uint(4)
	for i := 1; ; i++ {
		if i >= len(b) {
			return 0, 0, errTruncated
		}
		// Ten bytes carry 4 + 9*7 = 67 bits: past that, or once a byte's
		// bits would be shifted out, the value can't be a uint64.
		if shift > 63 {
			return 0, 0, errVarint
		}
		c := uint64(b[i])
		if c<<shift>>shift != c {
			return 0, 0, errVarint
		}
		next := v + c<<shift
		if next < v {
			return 0, 0, errVarint
		}
		v = next
		shift += 7
		if c < 128 {
			return v, i + 1, nil
		}
	}
}

// decoder reads SPOP values from a payload.
type decoder struct {
	b []byte
}

func (d *decoder) empty() bool { return len(d.b) == 0 }

func (d *decoder) byte() (byte, error) {
	if len(d.b) == 0 {
		return 0, errTruncated
	}
	c := d.b[0]
	d.b = d.b[1:]
	return c, nil
}

func (d *decoder) varint() (uint64, error) {
	v, n, err := readVarint(d.b)
	if err != nil {
		return 0, err
	}
	d.b = d.b[n:]
	return v, nil
}

// bytes reads a length-prefixed byte string. It aliases the payload.
func (d *decoder) bytes() ([]byte, error) {
	n, err := d.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.b)) {
		return nil, errTruncated
	}
	s := d.b[:n:n]
	d.b = d.b[n:]
	return s, nil
}

// value is one TYPED-DATA.
type value struct {
	typ byte
	b   bool
	// u holds the integer types, as their bits.
	u    uint64
	ip   netip.Addr
	data []byte
}

func (v value) String() string {
	switch v.typ {
	case typeString, typeBinary:
		return string(v.data)
	}
	return ""
}

// value reads one TYPED-DATA.
func (d *decoder) value() (value, error) {
	c, err := d.byte()
	if err != nil {
		return value{}, err
	}
	v := value{typ: c & 0x0f}
	switch v.typ {
	case typeNull:
	case typeBool:
		v.b = c&0x10 != 0
	case typeInt32, typeUint32, typeInt64, typeUint64:
		v.u, err = d.varint()
	case typeIPv4:
		if len(d.b) < 4 {
			return value{}, errTruncated
		}
		v.ip = netip.AddrFrom4([4]byte(d.b[:4]))
		d.b = d.b[4:]
	case typeIPv6:
		if len(d.b) < 16 {
			return value{}, errTruncated
		}
		v.ip = netip.AddrFrom16([16]byte(d.b[:16]))
		d.b = d.b[16:]
	case typeString, typeBinary:
		v.data, err = d.bytes()
	default:
		return value{}, fmt.Errorf("unknown data type %d", v.typ)
	}
	return v, err
}

// kv is one entry of a KV-LIST: a name (an untyped string) and a typed
// value.
type kv struct {
	name string
	val  value
}

// kvList reads a KV-LIST up to the end of the payload.
func (d *decoder) kvList() ([]kv, error) {
	var list []kv
	for !d.empty() {
		name, err := d.bytes()
		if err != nil {
			return nil, err
		}
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		list = append(list, kv{name: string(name), val: v})
	}
	return list, nil
}

// message is one SPOE message of a NOTIFY frame. Its arguments alias the
// frame's payload.
type message struct {
	name string
	args []kv
}

// messages reads a LIST-OF-MESSAGES up to the end of the payload.
func (d *decoder) messages() ([]message, error) {
	var list []message
	for !d.empty() {
		name, err := d.bytes()
		if err != nil {
			return nil, err
		}
		n, err := d.byte()
		if err != nil {
			return nil, err
		}
		m := message{name: string(name), args: make([]kv, 0, n)}
		for range n {
			argName, err := d.bytes()
			if err != nil {
				return nil, err
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			m.args = append(m.args, kv{name: string(argName), val: v})
		}
		list = append(list, m)
	}
	return list, nil
}

// frame is one decoded frame. Its payload aliases the buffer it was read
// into.
type frame struct {
	typ      byte
	flags    uint32
	streamID uint64
	frameID  uint64
	payload  []byte
}

// parseFrame decodes a frame without its length prefix.
func parseFrame(b []byte) (frame, error) {
	if len(b) < 1+4 {
		return frame{}, errTruncated
	}
	f := frame{typ: b[0], flags: binary.BigEndian.Uint32(b[1:5])}
	d := decoder{b: b[5:]}
	var err error
	if f.streamID, err = d.varint(); err != nil {
		return frame{}, fmt.Errorf("stream-id: %w", err)
	}
	if f.frameID, err = d.varint(); err != nil {
		return frame{}, fmt.Errorf("frame-id: %w", err)
	}
	f.payload = d.b
	return f, nil
}

// readFrame reads one frame, at most maxSize bytes long without its length
// prefix, into buf (grown as needed). started, if not nil, is called once
// the length prefix is in: the frame has begun, and its rest must follow.
func readFrame(r io.Reader, buf []byte, maxSize uint32, started func()) (frame, []byte, error) {
	var prefix [frameLengthFieldBytes]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return frame{}, buf, err
	}
	if started != nil {
		started()
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size > maxSize {
		return frame{}, buf, frameTooBigError{size: size, max: maxSize}
	}
	if cap(buf) < int(size) {
		buf = make([]byte, size)
	}
	buf = buf[:size]
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return frame{}, buf, err
	}
	f, err := parseFrame(buf)
	return f, buf, err
}

// encoder builds a frame, length prefix included.
type encoder struct {
	b []byte
}

// newFrame starts a frame with FIN set.
func newFrame(typ byte, streamID, frameID uint64) *encoder {
	e := &encoder{b: make([]byte, frameLengthFieldBytes, 64)}
	e.b = append(e.b, typ)
	e.b = binary.BigEndian.AppendUint32(e.b, flagFin)
	e.b = appendVarint(e.b, streamID)
	e.b = appendVarint(e.b, frameID)
	return e
}

func (e *encoder) bytes(s string) {
	e.b = appendVarint(e.b, uint64(len(s)))
	e.b = append(e.b, s...)
}

func (e *encoder) str(s string) {
	e.b = append(e.b, typeString)
	e.bytes(s)
}

func (e *encoder) uint32(v uint32) {
	e.b = append(e.b, typeUint32)
	e.b = appendVarint(e.b, uint64(v))
}

func (e *encoder) int32(v int32) {
	e.b = append(e.b, typeInt32)
	// HAProxy reads a signed integer's varint as the bits of an int64.
	e.b = appendVarint(e.b, uint64(int64(v))) // #nosec G115 -- two's complement, as HAProxy encodes it
}

// kvString and kvUint32 add KV-LIST entries.
func (e *encoder) kvString(name, v string) {
	e.bytes(name)
	e.str(v)
}

func (e *encoder) kvUint32(name string, v uint32) {
	e.bytes(name)
	e.uint32(v)
}

// setVar adds a set-var action in the transaction scope.
func (e *encoder) setVar(name string, set func(*encoder)) {
	e.b = append(e.b, actionSetVar, 3, scopeTransaction)
	e.bytes(name)
	set(e)
}

// finish writes the length prefix and returns the frame.
func (e *encoder) finish() []byte {
	// #nosec G115 -- frames are bounded by the negotiated maximum size
	binary.BigEndian.PutUint32(e.b[:frameLengthFieldBytes], uint32(len(e.b)-frameLengthFieldBytes))
	return e.b
}
