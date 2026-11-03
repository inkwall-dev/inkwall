// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/http/httpguts"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
)

const fuzzMaxBody = 16

// FuzzSPOE decodes arbitrary bytes as a frame, as the agent reads them from
// HAProxy, and a NOTIFY payload as the request it describes. Nothing
// panics, and a request the agent accepts is one it can inspect: a method
// token, an origin-form URI, a valid authority kept out of the headers, at
// most the body limit of the body, and a body counted complete only when
// it is all there: as long as its Content-Length, or, without one, from a
// frame well under half the maximum size.
func FuzzSPOE(f *testing.F) {
	files, err := filepath.Glob(filepath.Join("testdata", "frames", "*.bin"))
	if err != nil {
		f.Fatal(err)
	}
	for _, file := range files {
		b, err := os.ReadFile(file) // #nosec G304 -- test fixtures
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, uint16(16380))
	}
	f.Add(notifyFrame(1, 1, argString(ArgMethod, "POST"), argString(ArgPath, "/a?b"),
		argBinary(ArgHeaders, hdrs("host", "a", "transfer-encoding", "chunked")), argBinary(ArgBody, []byte("x=1"))), uint16(4096))
	f.Fuzz(func(t *testing.T, b []byte, maxFrame uint16) {
		fr, _, err := readFrame(bytes.NewReader(b), nil, 1<<20, nil)
		if err != nil {
			return
		}
		d := decoder{b: fr.payload}
		_, _ = d.kvList()
		srv, err := New(&inspector{}, Config{MaxBodyBytes: fuzzMaxBody})
		if err != nil {
			t.Fatal(err)
		}
		req, path, err := srv.toRequest(fr.payload, uint32(maxFrame))
		if err != nil {
			return
		}
		a, err := readArgs(fr.payload)
		if err != nil {
			t.Fatalf("request accepted from unreadable arguments: %v", err)
		}
		if !httpadapter.IsToken(req.Method) || req.Method != a.method {
			t.Fatalf("method %q", req.Method)
		}
		if req.RawURI != a.path || (req.RawURI != "*" && !strings.HasPrefix(req.RawURI, "/")) || strings.Contains(req.RawURI, "#") {
			t.Fatalf("URI %q", req.RawURI)
		}
		if p, err := httpadapter.URIPath(req.RawURI); err != nil || p != path {
			t.Fatalf("path %q for %q: %v", path, req.RawURI, err)
		}
		if !httpguts.ValidHostHeader(req.Host) || req.Headers.Get("Host") != "" {
			t.Fatalf("host %q, Host header %q", req.Host, req.Headers.Get("Host"))
		}
		if len(req.Body) > fuzzMaxBody {
			t.Fatalf("inspected %d body bytes, over the limit", len(req.Body))
		}
		if !bytes.HasPrefix(a.body, req.Body) {
			t.Fatal("inspected a body HAProxy didn't send")
		}
		if req.BodyTruncated || len(a.body) == 0 && !a.hasBody {
			return
		}
		// Taken as complete: all of it, and all there.
		if len(req.Body) != len(a.body) {
			t.Fatalf("inspected %d of %d body bytes as complete", len(req.Body), len(a.body))
		}
		if cl := req.Headers.Get("Content-Length"); cl != "" && req.Headers.Get("Transfer-Encoding") == "" {
			if n, err := strconv.Atoi(cl); err != nil || n != len(a.body) {
				t.Fatalf("body of %d bytes complete with Content-Length %q", len(a.body), cl)
			}
		} else if len(a.body) > 0 && !uncut(len(fr.payload), len(req.Headers), len(req.Host), uint32(maxFrame)) {
			t.Fatalf("body of %d bytes without Content-Length complete in a full frame", len(a.body))
		}
	})
}

// FuzzVarint decodes arbitrary bytes as a varint: a value decoded encodes
// back to the same bytes.
func FuzzVarint(f *testing.F) {
	for _, v := range []uint64{0, 239, 240, 2287, 2288, 16380, 1 << 32, 1<<64 - 1} {
		f.Add(appendVarint(nil, v))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, n, err := readVarint(b)
		if err != nil {
			return
		}
		if enc := appendVarint(nil, v); !bytes.Equal(enc, b[:n]) {
			t.Fatalf("% x decodes to %d, which encodes to % x", b[:n], v, enc)
		}
	})
}
