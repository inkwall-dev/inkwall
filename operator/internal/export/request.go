// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"google.golang.org/protobuf/proto"
)

// maxRequest bounds a request body before compression: gRPC's default
// message limit. It is measured after encoding, in the sink's format: the
// same events are larger as JSON or OTLP than as the engine's protobuf.
const maxRequest = 4 << 20

// format is how a sink's requests are encoded.
type format int

const (
	formatOTLPGRPC format = iota
	formatOTLPHTTP
	formatJSONLines
	formatJSONArray
)

func (f format) otlp() bool { return f == formatOTLPGRPC || f == formatOTLPHTTP }

// builder encodes events into one request.
type builder interface {
	// add takes an event, unless the request has some and would pass the
	// size limit with it.
	add(it item) bool
	len() int
	payload() payload
}

func newBuilder(f format, v *view, limit int) builder {
	if f.otlp() {
		return &otlpBuilder{enc: newOTLPEncoder(v, limit), http: f == formatOTLPHTTP}
	}
	return &jsonBuilder{v: v, limit: limit, array: f == formatJSONArray}
}

// jsonBuilder: Lines, one event per line; Array, one JSON array.
type jsonBuilder struct {
	v       *view
	limit   int
	array   bool
	buf     []byte
	scratch []byte
	n       int
}

func (b *jsonBuilder) add(it item) bool {
	b.scratch = appendJSON(b.scratch[:0], it, b.v)
	// Array: "[" or ",", the event, "]"; Lines: the event and "\n".
	grow := len(b.scratch) + 1
	closing := 0
	if b.array {
		closing = 1
	}
	if b.n > 0 && len(b.buf)+grow+closing > b.limit {
		return false
	}
	if b.array {
		if b.n == 0 {
			b.buf = append(b.buf, '[')
		} else {
			b.buf = append(b.buf, ',')
		}
		b.buf = append(b.buf, b.scratch...)
	} else {
		b.buf = append(b.buf, b.scratch...)
		b.buf = append(b.buf, '\n')
	}
	b.n++
	return true
}

func (b *jsonBuilder) len() int { return b.n }

func (b *jsonBuilder) payload() payload {
	if b.array {
		b.buf = append(b.buf, ']')
		return payload{body: b.buf, contentType: "application/json", size: len(b.buf)}
	}
	return payload{body: b.buf, contentType: "application/x-ndjson", size: len(b.buf)}
}

// otlpBuilder: an ExportLogsServiceRequest, sent by gRPC or as an HTTP
// POST of its protobuf.
type otlpBuilder struct {
	enc  *otlpEncoder
	http bool
}

func (b *otlpBuilder) add(it item) bool { return b.enc.add(it) }
func (b *otlpBuilder) len() int         { return b.enc.n }

func (b *otlpBuilder) payload() payload {
	p := payload{otlp: b.enc.req, size: b.enc.size}
	if b.http {
		raw, err := marshalOTLP(b.enc.req)
		if err == nil {
			p.body, p.contentType, p.size = raw, "application/x-protobuf", len(raw)
		}
	} else {
		p.size = proto.Size(b.enc.req)
	}
	return p
}

// marshalOTLP is proto.Marshal; tests make it fail.
var marshalOTLP = proto.Marshal

// encode builds the payload of items, all of them: a request split in half
// is encoded again from its halves.
func encode(f format, v *view, items []item) payload {
	b := newBuilder(f, v, 1<<62)
	for _, it := range items {
		b.add(it)
	}
	return b.payload()
}
