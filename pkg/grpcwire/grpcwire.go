// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcwire reads gRPC request messages without their schema: it
// splits a body into gRPC messages and finds the text in each protobuf
// message, for rules to inspect.
//
// Protobuf's wire format doesn't say which length-delimited fields are
// strings, bytes or nested messages. A field whose bytes are a whole
// protobuf message is read as one (its fields get their own names); a
// field whose bytes are printable UTF-8 is text. Some bytes are both, and
// give both. Numbers, binary bytes and anything that fails to parse give
// nothing.
package grpcwire

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// FrameHeader is a gRPC message's prefix: a compressed flag (0 or 1) and
// the message length, 4 bytes big-endian.
const FrameHeader = 5

// Message is one gRPC message of a body.
type Message struct {
	// Compressed: the message is compressed with the call's grpc-encoding.
	Compressed bool
	// Data is the message, or as much of it as the body holds.
	Data []byte
	// Cut: the body ends inside the message.
	Cut bool
}

// Messages splits body into gRPC messages. ok is false when body isn't a
// sequence of messages: a bad flag, or a body that ends inside a prefix or
// a message while it is not truncated.
func Messages(body []byte, truncated bool) (msgs []Message, ok bool) {
	for len(body) > 0 {
		if len(body) < FrameHeader {
			return msgs, truncated
		}
		if body[0] > 1 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(body[1:FrameHeader]))
		m := Message{Compressed: body[0] == 1}
		body = body[FrameHeader:]
		if n > uint64(len(body)) {
			if !truncated {
				return nil, false
			}
			m.Data, m.Cut = body, true
			return append(msgs, m), true
		}
		m.Data = body[:n]
		body = body[n:]
		msgs = append(msgs, m)
	}
	return msgs, true
}

// Field is text found in a message: Name is the path of field numbers
// from the message, dot-separated ("2.1": field 1 of the message in
// field 2).
type Field struct {
	Name  string
	Value string
}

// Limits bound the work on one body.
type Limits struct {
	// Depth is how deep nested messages are read.
	Depth int
	// Fields is how many text fields are returned.
	Fields int
}

// DefaultLimits are those the pipeline uses.
var DefaultLimits = Limits{Depth: 16, Fields: 1024}

// Strings returns the text fields of a protobuf message, appended to out,
// and reports whether the message parsed whole and stayed within lim.
// A message that doesn't parse gives what was found before the error.
func Strings(msg []byte, lim Limits, out []Field) ([]Field, bool) {
	w := walker{lim: lim, out: out}
	ok := w.message(msg, "", 0)
	return w.out, ok && !w.over
}

type walker struct {
	lim  Limits
	out  []Field
	over bool
}

// message walks msg, a message at depth whose fields are named under
// prefix. It reports whether msg is a valid message.
func (w *walker) message(msg []byte, prefix string, depth int) bool {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return false
		}
		msg = msg[n:]
		if typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, msg)
			if n < 0 {
				return false
			}
			msg = msg[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(msg)
		if n < 0 {
			return false
		}
		msg = msg[n:]
		name := strconv.Itoa(int(num))
		if prefix != "" {
			name = prefix + "." + name
		}
		w.field(v, name, depth)
	}
	return true
}

// field reads the bytes of a length-delimited field: as text, and as a
// nested message.
func (w *walker) field(v []byte, name string, depth int) {
	if text(v) {
		if len(w.out) >= w.lim.Fields {
			w.over = true
			return
		}
		w.out = append(w.out, Field{Name: name, Value: string(v)})
	}
	if len(v) == 0 {
		return
	}
	if depth+1 > w.lim.Depth {
		w.over = true
		return
	}
	// Parse first, so a field that isn't a message adds nothing.
	if valid(v) {
		w.message(v, name, depth+1)
	}
}

// valid reports whether v parses as a protobuf message, one level deep.
func valid(v []byte) bool {
	for len(v) > 0 {
		_, _, n := protowire.ConsumeField(v)
		if n < 0 {
			return false
		}
		v = v[n:]
	}
	return true
}

// Gunzip decompresses a message compressed with grpc-encoding gzip, up
// to limit bytes. ok is false when data isn't gzip, or decompresses to
// more than limit bytes: then out is what fit.
func Gunzip(data []byte, limit int64) (out []byte, ok bool) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	out, err = io.ReadAll(io.LimitReader(zr, limit+1))
	if int64(len(out)) > limit {
		return out[:limit], false
	}
	return out, err == nil
}

// text reports whether v is printable UTF-8: no control characters but
// tab, newline and carriage return.
func text(v []byte) bool {
	if len(v) == 0 || !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
