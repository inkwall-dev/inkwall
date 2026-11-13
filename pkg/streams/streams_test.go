// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package streams

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestKindOf(t *testing.T) {
	for ct, want := range map[string]Kind{
		"text/event-stream":                SSE,
		"text/event-stream; charset=utf-8": SSE,
		"application/grpc":                 GRPC,
		"application/grpc+proto":           GRPC,
		"application/grpc-web":             None,
		"application/grpc-web-text":        None,
		"text/html":                        None,
		"":                                 None,
		"application/json; stream=true":    None,
		"Text/Event-Stream":                SSE,
	} {
		if got := KindOf(ct); got != want {
			t.Errorf("KindOf(%q) = %v, want %v", ct, got, want)
		}
	}
}

func datas(events []Event) []string {
	var out []string
	for _, e := range events {
		s := string(e.Data)
		if e.Truncated {
			s += "…"
		}
		out = append(out, s)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Server-Sent Events: each event is its data lines, joined by newlines,
// whatever line endings and chunks; other fields and comments aren't
// inspected; a blank line ends an event.
func TestSSE(t *testing.T) {
	stream := ": keep-alive\n\n" +
		"event: token\ndata: hello\n\n" +
		"data: line one\r\ndata:line two\r\n\r\n" +
		"id: 7\rdata: cr only\r\r" +
		"data: {\"msg\": \"You have an error in your SQL syntax\"}\n\n" +
		"retry: 100\n\n"
	want := []string{"hello", "line one\nline two", "cr only", `{"msg": "You have an error in your SQL syntax"}`}
	// Whole, and split at every byte boundary.
	for split := 0; split <= len(stream); split++ {
		s := New(SSE, 1<<10, "")
		got := datas(s.Write([]byte(stream[:split])))
		got = append(got, datas(s.Write([]byte(stream[split:])))...)
		got = append(got, datas(s.Close())...)
		if !equal(got, want) {
			t.Fatalf("split at %d: %q, want %q", split, got, want)
		}
		if p := s.Pending(); p != 0 {
			t.Fatalf("split at %d: %d bytes pending after the last event", split, p)
		}
	}
}

// Pending is the bytes of the event in progress, which block mode holds;
// past the limit an event is returned cut, and the rest of it isn't held.
func TestSSEPendingAndLimit(t *testing.T) {
	s := New(SSE, 16, "")
	if ev := s.Write([]byte("data: abc")); len(ev) != 0 || s.Pending() != 9 {
		t.Fatalf("partial event: %q, pending %d", datas(ev), s.Pending())
	}
	if ev := s.Write([]byte("\n\n")); !equal(datas(ev), []string{"abc"}) || s.Pending() != 0 || ev[0].End != 11 {
		t.Fatalf("ended: %q, pending %d", datas(ev), s.Pending())
	}
	long := "data: " + strings.Repeat("x", 40) + "\n"
	ev := s.Write([]byte(long))
	if len(ev) != 1 || !ev[0].Truncated || len(ev[0].Data) > 16 || s.Pending() != 0 {
		t.Fatalf("a long event: %q, pending %d", datas(ev), s.Pending())
	}
	// The rest of the long event passes, unheld and uninspected, up to its
	// end; the next is inspected again.
	if ev := s.Write([]byte("data: more of it\n\ndata: next\n\n")); !equal(datas(ev), []string{"next"}) {
		t.Fatalf("after a long event: %q", datas(ev))
	}
	// A stream that ends inside an event: inspected at the close.
	s = New(SSE, 1<<10, "")
	s.Write([]byte("data: last words"))
	if ev := s.Close(); !equal(datas(ev), []string{"last words"}) {
		t.Fatalf("close: %q", datas(ev))
	}
}

func frame(compressed bool, msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	if compressed {
		b[0] = 1
	}
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

func message(fields ...string) []byte {
	var m []byte
	for i, f := range fields {
		m = protowire.AppendTag(m, protowire.Number(i+1), protowire.BytesType)
		m = protowire.AppendString(m, f)
	}
	return m
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

// gRPC server streams: each message is one event, its text fields joined
// by newlines, whatever the chunks; gzip-compressed messages are read with
// grpc-encoding gzip, others are uninspected (cut).
func TestGRPC(t *testing.T) {
	stream := slicesConcat(
		frame(false, message("hello", "world")),
		frame(false, nil),
		frame(true, gz(message("You have an error in your SQL syntax"))),
		frame(false, message("bye")),
	)
	want := []string{"hello\nworld", "", "You have an error in your SQL syntax", "bye"}
	for split := 0; split <= len(stream); split++ {
		s := New(GRPC, 1<<10, "gzip")
		got := datas(s.Write(stream[:split]))
		got = append(got, datas(s.Write(stream[split:]))...)
		got = append(got, datas(s.Close())...)
		if !equal(got, want) {
			t.Fatalf("split at %d: %q, want %q", split, got, want)
		}
		if s.Pending() != 0 {
			t.Fatalf("split at %d: %d pending", split, s.Pending())
		}
	}
	// Compressed with another encoding: uninspected, so cut.
	s := New(GRPC, 1<<10, "zstd")
	if ev := s.Write(frame(true, []byte("whatever"))); len(ev) != 1 || !ev[0].Truncated {
		t.Errorf("zstd message: %q", datas(ev))
	}
	// Over the limit: cut once the limit is read, the rest not held.
	s = New(GRPC, 8, "")
	ev := s.Write(frame(false, message(strings.Repeat("y", 30)))[:20])
	if len(ev) != 1 || !ev[0].Truncated || s.Pending() != 0 {
		t.Errorf("long message: %q, pending %d", datas(ev), s.Pending())
	}
	// Not gRPC framing (a flag over 1): one cut event, then nothing held.
	s = New(GRPC, 1<<10, "")
	if ev := s.Write([]byte{7, 0, 0, 0, 1, 'x', 'y'}); len(ev) != 1 || !ev[0].Truncated || s.Pending() != 0 {
		t.Errorf("bad framing: %q, pending %d", datas(ev), s.Pending())
	}
	if ev := s.Write(frame(false, message("later"))); len(ev) != 0 || s.Pending() != 0 {
		t.Errorf("after bad framing: %q", datas(ev))
	}
}

func slicesConcat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}
