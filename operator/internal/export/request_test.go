// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// bigEvent is an event at the contract's field limits: about 8 KiB as
// JSON, so 1,000 of them pass 4 MiB.
func bigEvent(i int) *eventsv1.SecurityEvent {
	ev := fullEvent()
	ev.EventId = "big" + itoa(i)
	ev.Path = "/" + strings.Repeat("p", 1023)
	ev.Host = strings.Repeat("h", 255)
	ev.UserAgent = strings.Repeat("u", 256)
	ev.RequestId = strings.Repeat("r", 128)
	ev.Matches = nil
	for j := range 32 {
		ev.Matches = append(ev.Matches, &eventsv1.Match{RuleId: int32(942100 + j), Variable: strings.Repeat("v", 128), Snippet: strings.Repeat("\"", 64)})
	}
	return ev
}

// The encoder closes a request when the next event would pass 4 MiB, in
// the sink's own format: never one over it.
func TestRequestCutAt4MiB(t *testing.T) {
	for _, f := range []format{formatJSONLines, formatJSONArray, formatOTLPHTTP, formatOTLPGRPC} {
		b := newBuilder(f, &testView, maxRequest)
		n := 0
		for b.add(items(bigEvent(n))[0]) {
			n++
			if n > 5000 {
				t.Fatalf("format %d: no cut after %d events", f, n)
			}
		}
		p := b.payload()
		size := p.size
		if f == formatOTLPGRPC {
			size = proto.Size(p.otlp)
		}
		if size > maxRequest || size < maxRequest*9/10 || n < 100 {
			t.Errorf("format %d: %d events in %d bytes, want just under %d", f, n, size, maxRequest)
		}
		// The encoder's own measure is an upper bound of the real size.
		if f.otlp() {
			if est := b.(*otlpBuilder).enc.size; est < proto.Size(p.otlp) {
				t.Errorf("format %d: estimated %d, real %d", f, est, proto.Size(p.otlp))
			}
		}
	}
}

// A request always takes its first event, whatever its size.
func TestRequestTakesOneEvent(t *testing.T) {
	for _, f := range []format{formatJSONLines, formatJSONArray, formatOTLPHTTP} {
		b := newBuilder(f, &testView, 10)
		if !b.add(items(fullEvent())[0]) || b.add(items(fullEvent())[0]) {
			t.Errorf("format %d: want the first event taken, and the second not", f)
		}
	}
}

func BenchmarkEncodeJSON(b *testing.B) {
	it := items(fullEvent())[0]
	var buf []byte
	b.ReportAllocs()
	for b.Loop() {
		buf = appendJSON(buf[:0], it, &testView)
	}
	b.SetBytes(int64(len(buf)))
}

func BenchmarkEncodeOTLP(b *testing.B) {
	it := items(fullEvent())[0]
	b.ReportAllocs()
	for b.Loop() {
		_ = logRecord(it, &testView)
	}
}

// A full request: 500 events encoded and gzipped, as a sink sends them
// (the target of design 0010 §2.2: 10,000 events a second per sink, at
// under half a CPU, is 20 of these).
func BenchmarkBatch500(b *testing.B) {
	evs := make([]item, 500)
	for i := range evs {
		ev := fullEvent()
		ev.EventId = "e" + itoa(i)
		evs[i] = items(ev)[0]
	}
	for _, f := range []struct {
		name string
		f    format
	}{{"json", formatJSONLines}, {"otlp-http", formatOTLPHTTP}} {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				p := encode(f.f, &testView, evs)
				_ = compress(p.body)
			}
			b.ReportMetric(float64(b.N*len(evs))/b.Elapsed().Seconds(), "events/s")
		})
	}
}
