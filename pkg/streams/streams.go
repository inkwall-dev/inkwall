// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package streams splits streamed responses into the events that are
// inspected one by one (#323, docs/design/0006 §2): a Server-Sent Events
// stream into its events, a gRPC server stream into its messages. A
// Splitter is fed the stream as it comes, in any chunks, and says how many
// of the bytes written belong to an event not complete yet, which an
// adapter in block mode holds until it is inspected. Those are bounded:
// an event longer than the limit is returned cut once the limit is
// reached, and the rest of it isn't held.
package streams

import (
	"bytes"
	"encoding/binary"
	"mime"
	"strings"

	"github.com/inkwall-dev/inkwall/pkg/grpcwire"
)

// Kind is a kind of streamed response.
type Kind int

const (
	// None is a response that isn't a stream this package splits.
	None Kind = iota
	// SSE is Server-Sent Events (text/event-stream).
	SSE
	// GRPC is a gRPC response (application/grpc, application/grpc+proto):
	// length-prefixed messages.
	GRPC
)

func (k Kind) String() string {
	switch k {
	case SSE:
		return "sse"
	case GRPC:
		return "grpc"
	}
	return "none"
}

// KindOf returns the kind of a response with this Content-Type. gRPC-Web
// isn't split: its text form is base64, and its trailers are framed in
// the body.
func KindOf(contentType string) Kind {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return None
	}
	switch media {
	case "text/event-stream":
		return SSE
	case "application/grpc", "application/grpc+proto":
		return GRPC
	}
	return None
}

// Event is one event of a stream, as it is inspected.
type Event struct {
	// Data is the event's text: an SSE event's data lines, joined by
	// newlines; a gRPC message's text fields, joined by newlines.
	Data []byte
	// Truncated: the event was longer than the limit, or couldn't be read
	// whole (a message compressed in an encoding the engine can't read, a
	// stream that isn't framed as gRPC): Data is what was read, and the
	// rest went uninspected.
	Truncated bool
	// End is the offset in the stream (the bytes written to the Splitter)
	// where the event ends: the bytes before it can go out once the event
	// and those before it are allowed.
	End int64
}

// grpcLimits bound the reading of one message's text.
var grpcLimits = grpcwire.Limits{Depth: 16, Fields: 1024}

// Splitter splits one stream into events.
type Splitter struct {
	kind     Kind
	max      int64
	encoding string
	// pending: bytes written that belong to the event in progress;
	// written: all the bytes written.
	pending, written int64
	// skip: the event in progress was returned cut; its rest isn't held.
	skip bool

	// SSE: the line in progress, the data of the event in progress, and
	// whether the last byte was a CR (a CRLF's LF ends no second line).
	line    []byte
	data    []byte
	hasData bool
	lastCR  bool
	// skipLine: the line in progress, while skipping, isn't blank.
	skipLine bool

	// gRPC: the message prefix in progress, the message's length, what
	// was read of it, and how much of it is left to skip; broken: the
	// stream isn't framed as gRPC, and nothing more is inspected.
	header     []byte
	length     int64
	msg        []byte
	compressed bool
	skipLeft   int64
	broken     bool
}

// New returns a Splitter for a stream of kind, whose events are inspected
// up to max bytes each; encoding is a gRPC stream's grpc-encoding.
func New(kind Kind, max int64, encoding string) *Splitter {
	return &Splitter{kind: kind, max: max, encoding: strings.ToLower(strings.TrimSpace(encoding))}
}

// Pending returns how many bytes at the end of what was written belong to
// an event not returned yet.
func (s *Splitter) Pending() int64 { return s.pending }

// Write adds the next part of the stream and returns the events it
// completes.
func (s *Splitter) Write(p []byte) []Event {
	if s.kind == GRPC {
		return s.writeGRPC(p)
	}
	return s.writeSSE(p)
}

// Close ends the stream, and returns the event it ended inside, if any:
// inspected as it is (an SSE client drops it; it still went out).
func (s *Splitter) Close() []Event {
	var out []Event
	switch s.kind {
	case SSE:
		if !s.skip {
			if len(s.line) > 0 {
				s.field(s.line)
			}
			if s.hasData {
				out = append(out, Event{Data: trimLastNewline(s.data)})
			}
		}
		s.line, s.data, s.hasData = nil, nil, false
	case GRPC:
		if !s.broken && !s.skip && (len(s.header) > 0 || s.msg != nil) {
			out = append(out, s.grpcEvent(true))
		}
		s.header, s.msg = nil, nil
	}
	for i := range out {
		out[i].End = s.written
	}
	s.pending, s.skip = 0, false
	return out
}

func (s *Splitter) writeSSE(p []byte) []Event {
	var out []Event
	for _, c := range p {
		s.written++
		if !s.skip {
			s.pending++
		}
		if s.lastCR && c == '\n' {
			s.lastCR = false
			continue
		}
		s.lastCR = false
		if c == '\r' || c == '\n' {
			s.lastCR = c == '\r'
			if ev, ok := s.endLine(); ok {
				ev.End = s.written
				out = append(out, ev)
			}
			continue
		}
		if s.skip {
			s.skipLine = true
			continue
		}
		s.line = append(s.line, c)
		if s.pending > s.max {
			// Too long: inspect what was read, and let the rest pass.
			data := s.data
			if v, ok := dataValue(s.line); ok {
				data = append(data, v...)
			}
			out = append(out, Event{Data: data[:min(int64(len(data)), s.max)], Truncated: true, End: s.written})
			s.skip, s.skipLine, s.pending = true, true, 0
			s.line, s.data, s.hasData = s.line[:0], nil, false
		}
	}
	return out
}

// endLine handles the end of a line: a blank one ends the event.
func (s *Splitter) endLine() (Event, bool) {
	line := s.line
	s.line = s.line[:0]
	if s.skip {
		if !s.skipLine {
			// The blank line that ends the event that was too long.
			s.skip, s.pending = false, 0
		}
		s.skipLine = false
		return Event{}, false
	}
	if len(line) > 0 {
		s.field(line)
		return Event{}, false
	}
	s.pending = 0
	if !s.hasData {
		return Event{}, false
	}
	ev := Event{Data: trimLastNewline(s.data)}
	s.data, s.hasData = nil, false
	return ev, true
}

// field reads a line of an event: only data lines are inspected.
func (s *Splitter) field(line []byte) {
	if v, ok := dataValue(line); ok {
		s.data = append(append(s.data, v...), '\n')
		s.hasData = true
	}
}

// dataValue returns the value of a data line ("data: v", "data:v", or
// "data" alone, empty).
func dataValue(line []byte) ([]byte, bool) {
	name, value, _ := bytes.Cut(line, []byte(":"))
	if string(name) != "data" {
		return nil, false
	}
	return bytes.TrimPrefix(value, []byte(" ")), true
}

func trimLastNewline(b []byte) []byte {
	return bytes.TrimSuffix(b, []byte("\n"))
}

func (s *Splitter) writeGRPC(p []byte) []Event {
	var out []Event
	for len(p) > 0 && !s.broken {
		if s.skipLeft > 0 {
			n := min(s.skipLeft, int64(len(p)))
			s.skipLeft -= n
			p = p[n:]
			s.written += n
			if s.skipLeft == 0 {
				s.skip = false
			}
			continue
		}
		if len(s.header) < grpcwire.FrameHeader {
			n := min(grpcwire.FrameHeader-len(s.header), len(p))
			s.header = append(s.header, p[:n]...)
			s.pending += int64(n)
			s.written += int64(n)
			p = p[n:]
			if len(s.header) < grpcwire.FrameHeader {
				break
			}
			if s.header[0] > 1 {
				// Not gRPC framing: inspected no further.
				out = append(out, Event{Truncated: true, End: s.written})
				s.broken, s.pending, s.header = true, 0, nil
				break
			}
			s.compressed = s.header[0] == 1
			s.length = int64(binary.BigEndian.Uint32(s.header[1:]))
			s.msg = make([]byte, 0, min(s.length, s.max))
		}
		want := min(s.length, s.max) - int64(len(s.msg))
		n := min(want, int64(len(p)))
		s.msg = append(s.msg, p[:n]...)
		s.pending += n
		s.written += n
		p = p[n:]
		if int64(len(s.msg)) < min(s.length, s.max) {
			break
		}
		cut := s.length > s.max
		ev := s.grpcEvent(cut)
		ev.End = s.written
		out = append(out, ev)
		if cut {
			s.skipLeft, s.skip = s.length-s.max, true
		}
		s.header, s.msg, s.pending = s.header[:0], nil, 0
	}
	if s.broken {
		// The rest isn't read, but it is part of the stream.
		s.written += int64(len(p))
		s.pending = 0
	}
	return out
}

// grpcEvent returns the message read: its text fields, joined by
// newlines. cut: the message wasn't read whole.
func (s *Splitter) grpcEvent(cut bool) Event {
	data := s.msg
	if s.compressed {
		if s.encoding != "gzip" || cut {
			return Event{Truncated: true}
		}
		out, whole := grpcwire.Gunzip(data, s.max)
		if !whole {
			cut = true
		}
		data = out
	}
	fields, whole := grpcwire.Strings(data, grpcLimits, nil)
	var text []byte
	for i, f := range fields {
		if i > 0 {
			text = append(text, '\n')
		}
		text = append(text, f.Value...)
	}
	return Event{Data: text[:min(int64(len(text)), s.max)], Truncated: cut || !whole && len(data) > 0}
}
