// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The varint sizes of SPOE.txt §3.1: each range starts a byte longer.
func TestVarint(t *testing.T) {
	for _, c := range []struct {
		v    uint64
		size int
	}{
		{0, 1}, {239, 1}, {240, 2}, {2287, 2}, {2288, 3}, {264431, 3}, {264432, 4},
		{33818863, 4}, {33818864, 5}, {4328786159, 5}, {4328786160, 6},
		{math.MaxUint32, 5}, {math.MaxInt64, 10}, {math.MaxUint64, 10},
	} {
		b := appendVarint(nil, c.v)
		if len(b) != c.size {
			t.Errorf("%d encodes in %d bytes, want %d", c.v, len(b), c.size)
		}
		got, n, err := readVarint(append(b, 0xff))
		if err != nil || got != c.v || n != len(b) {
			t.Errorf("%d: decoded %d in %d bytes, %v", c.v, got, n, err)
		}
	}
}

// HAProxy's max-frame-size, 16380 (tune.bufsize - 4), as it encodes it.
func TestVarintFromHAProxy(t *testing.T) {
	v, n, err := readVarint([]byte{0xfc, 0xf0, 0x06})
	if err != nil || v != 16380 || n != 3 {
		t.Fatalf("decoded %d in %d bytes, %v", v, n, err)
	}
}

func TestVarintErrors(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":     nil,
		"truncated": {0xf0},
		"no end":    {0xf0, 0x80, 0x80},
		"overflow":  bytes.Repeat([]byte{0xff}, 12),
		// Ten bytes whose last carries bits past the 64th.
		"too high": append(append([]byte{0xff}, bytes.Repeat([]byte{0xff}, 8)...), 0x7f),
	} {
		if _, _, err := readVarint(b); err == nil {
			t.Errorf("%s: decoded % x", name, b)
		}
	}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "frames", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureFrame decodes a recorded frame, length prefix included.
func fixtureFrame(t testing.TB, name string) frame {
	t.Helper()
	f, _, err := readFrame(bytes.NewReader(readFixture(t, name)), nil, 1<<20, nil)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// The HAPROXY-HELLO frames HAProxy 3.2 sent: for a connection, and for a
// health check (option spop-check).
func TestDecodeHello(t *testing.T) {
	for _, c := range []struct {
		file        string
		caps        string
		healthcheck bool
	}{
		{"hello.bin", "pipelining", false},
		{"hello-healthcheck.bin", "", true},
	} {
		f := fixtureFrame(t, c.file)
		if f.typ != frameHAProxyHello || f.flags != flagFin || f.streamID != 0 || f.frameID != 0 {
			t.Fatalf("%s: frame %+v", c.file, f)
		}
		d := decoder{b: f.payload}
		items, err := d.kvList()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]value{}
		for _, it := range items {
			got[it.name] = it.val
		}
		if v := got["supported-versions"]; v.typ != typeString || v.String() != "2.0" {
			t.Errorf("%s: supported-versions %+v", c.file, v)
		}
		if v := got["max-frame-size"]; v.typ != typeUint32 || v.u != 16380 {
			t.Errorf("%s: max-frame-size %+v", c.file, v)
		}
		if v := got["capabilities"]; v.String() != c.caps {
			t.Errorf("%s: capabilities %q", c.file, v.String())
		}
		if v, ok := got["healthcheck"]; ok != c.healthcheck || v.b != c.healthcheck {
			t.Errorf("%s: healthcheck %+v", c.file, v)
		}
	}
}

// A NOTIFY frame of HAProxy 3.2 with the agent's message.
func TestDecodeNotify(t *testing.T) {
	f := fixtureFrame(t, "notify-get.bin")
	if f.typ != frameNotify || f.flags != flagFin || f.streamID == 0 || f.frameID == 0 {
		t.Fatalf("frame %+v", f)
	}
	d := decoder{b: f.payload}
	msgs, err := d.messages()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].name != MessageName {
		t.Fatalf("messages %+v", msgs)
	}
	var names []string
	for _, a := range msgs[0].args {
		names = append(names, a.name)
	}
	want := []string{ArgMethod, ArgPath, ArgVersion, ArgHeaders, ArgBody, ArgIP, ArgHTTPS}
	if len(names) != len(want) {
		t.Fatalf("arguments %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("arguments %v, want %v", names, want)
		}
	}
	ip := msgs[0].args[5].val
	if ip.typ != typeIPv4 || ip.ip != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("ip %+v", ip)
	}
}

func TestTypedData(t *testing.T) {
	for name, c := range map[string]struct {
		in   []byte
		want value
	}{
		"null":   {[]byte{typeNull}, value{typ: typeNull}},
		"true":   {[]byte{typeBool | 0x10}, value{typ: typeBool, b: true}},
		"false":  {[]byte{typeBool}, value{typ: typeBool}},
		"int32":  {[]byte{typeInt32, 0xf3, 0x0c}, value{typ: typeInt32, u: 0xf3 + 0x0c<<4}},
		"uint64": {[]byte{typeUint64, 7}, value{typ: typeUint64, u: 7}},
		"ipv6":   {append([]byte{typeIPv6}, netip.MustParseAddr("2001:db8::1").AsSlice()...), value{typ: typeIPv6, ip: netip.MustParseAddr("2001:db8::1")}},
		"string": {[]byte{typeString, 2, 'h', 'i'}, value{typ: typeString, data: []byte("hi")}},
	} {
		d := decoder{b: c.in}
		got, err := d.value()
		if err != nil || got.typ != c.want.typ || got.b != c.want.b || got.u != c.want.u || got.ip != c.want.ip || !bytes.Equal(got.data, c.want.data) || !d.empty() {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	for name, in := range map[string][]byte{
		"empty":         nil,
		"unknown type":  {10},
		"short ipv4":    {typeIPv4, 1, 2},
		"short ipv6":    {typeIPv6, 1},
		"string length": {typeString, 5, 'a'},
	} {
		d := decoder{b: in}
		if v, err := d.value(); err == nil {
			t.Errorf("%s: decoded %+v", name, v)
		}
	}
}

func TestReadFrameLimits(t *testing.T) {
	frame := newFrame(frameNotify, 1, 1).finish()
	if _, _, err := readFrame(bytes.NewReader(frame), nil, 4, nil); !errors.As(err, new(frameTooBigError)) {
		t.Errorf("a frame over the limit: %v", err)
	}
	if _, _, err := readFrame(bytes.NewReader(frame[:len(frame)-1]), nil, 1<<10, nil); err == nil {
		t.Error("read a truncated frame")
	}
	// Type and flags, but no stream ID.
	if _, _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 5, 3, 0, 0, 0, 1}), nil, 1<<10, nil); err == nil {
		t.Error("read a frame without stream ID")
	}
}

// The ACK the agent builds decodes as SPOE.txt §3.4 describes it.
func TestEncodeAck(t *testing.T) {
	e := newFrame(frameAck, 300, 2)
	setVerdict(e, ActionDeny, 403, "abc")
	f, _, err := readFrame(bytes.NewReader(e.finish()), nil, 1<<10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.typ != frameAck || f.flags != flagFin || f.streamID != 300 || f.frameID != 2 {
		t.Fatalf("frame %+v", f)
	}
	vars, err := decodeActions(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	if vars[VarAction].String() != ActionDeny || vars[VarStatus].typ != typeInt32 || vars[VarStatus].u != 403 || vars[VarRequestID].String() != "abc" {
		t.Errorf("variables %+v", vars)
	}
}

// decodeActions reads the set-var actions of an ACK, as HAProxy does: a
// scope byte, an untyped name and a typed value.
func decodeActions(b []byte) (map[string]value, error) {
	d := decoder{b: b}
	vars := map[string]value{}
	for !d.empty() {
		typ, err := d.byte()
		if err != nil {
			return nil, err
		}
		n, err := d.byte()
		if err != nil {
			return nil, err
		}
		if typ != actionSetVar || n != 3 {
			return nil, errors.New("not a set-var action")
		}
		scope, err := d.byte()
		if err != nil {
			return nil, err
		}
		if scope != scopeTransaction {
			return nil, errors.New("not in the transaction scope")
		}
		name, err := d.bytes()
		if err != nil {
			return nil, err
		}
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		vars[string(name)] = v
	}
	return vars, nil
}
