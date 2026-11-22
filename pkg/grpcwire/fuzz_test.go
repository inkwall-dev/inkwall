// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

// FuzzMessages checks the reading of a client's body: the messages cover
// the body, and the text found in them is valid UTF-8 read from the body, within
// the limits.
func FuzzMessages(f *testing.F) {
	f.Add([]byte(frame(0, string(pb(1, "world", 2, pb(1, "in"))))), false)
	f.Add([]byte(frame(1, "x")+frame(0, "\x0a\x02ab")), true)
	f.Add([]byte(frame(0, string(group(1, pb(2, "in", 3, group(4, pb(1, "deeper"))))))), false)
	f.Fuzz(func(t *testing.T, body []byte, truncated bool) {
		msgs, ok := Messages(body, truncated)
		if !ok {
			return
		}
		size := 0
		for i, m := range msgs {
			size += FrameHeader + len(m.Data)
			if m.Cut && (i != len(msgs)-1 || !truncated) {
				t.Fatalf("message %d of %d cut (truncated %v)", i, len(msgs), truncated)
			}
			lim := Limits{Depth: 8, Fields: 64}
			fields, _ := Strings(m.Data, lim, nil)
			if len(fields) > lim.Fields {
				t.Fatalf("%d fields over the limit", len(fields))
			}
			for _, fd := range fields {
				// A field's text is its bytes, or as long: a byte that
				// isn't UTF-8 or a control character becomes a space.
				if fd.Value == "" || !utf8.ValidString(fd.Value) || len(fd.Value) > len(m.Data) {
					t.Fatalf("field %q = %q, not text from %q", fd.Name, fd.Value, m.Data)
				}
				if n := bytes.Count([]byte(fd.Name), []byte(".")); n >= lim.Depth {
					t.Fatalf("field %q deeper than %d", fd.Name, lim.Depth)
				}
			}
		}
		if size > len(body) || (!truncated && size != len(body)) {
			t.Fatalf("messages of %d bytes, body %d (truncated %v)", size, len(body), truncated)
		}
	})
}
