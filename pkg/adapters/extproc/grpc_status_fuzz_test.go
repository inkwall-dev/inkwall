// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"net/url"
	"testing"
)

// FuzzGRPCStatusEvent fuzzes the decoding of a gRPC status message
// (#317): any value gives an event within the limit, cut only when the
// decoded text is longer; a value gRPC's encoder made (percent-encoding,
// as url.PathEscape does for these bytes) decodes back to its text.
func FuzzGRPCStatusEvent(f *testing.F) {
	f.Add("You%20have%20an%20error%20in%20your%20SQL%20syntax", uint8(64))
	f.Add("%zz%4", uint8(2))
	f.Add("", uint8(0))
	f.Fuzz(func(t *testing.T, msg string, limit uint8) {
		ev := grpcStatusEvent(msg, int64(limit))
		if len(ev.Data) > int(limit) {
			t.Fatalf("%d bytes, limit %d", len(ev.Data), limit)
		}
		if len(ev.Data) > len(msg) {
			t.Fatalf("decoded %q longer than %q", ev.Data, msg)
		}
		whole := grpcStatusEvent(msg, 1<<20)
		if ev.Truncated != (len(whole.Data) > int(limit)) || !bytes.HasPrefix(whole.Data, ev.Data) {
			t.Fatalf("cut %v: %q of %q, limit %d", ev.Truncated, ev.Data, whole.Data, limit)
		}
		enc := url.PathEscape(msg)
		if got := grpcStatusEvent(enc, 1<<20); string(got.Data) != msg {
			t.Fatalf("%q encoded as %q decodes to %q", msg, enc, got.Data)
		}
	})
}
