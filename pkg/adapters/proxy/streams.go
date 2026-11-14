// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"sync"

	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/streams"
)

// errStreamDenied ends a stream at an event the rules denied: ReverseProxy
// aborts the response, so the client never gets the event.
var errStreamDenied = errors.New("streamed response denied")

// proxyErrorLog is ReverseProxy's ErrorLog: its lines at error level, but
// for a stream ended at a denied event, which it reports as a read error
// during the body copy (#615). The denial is logged as a security event;
// it isn't an error.
func proxyErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(deniedStreamFilter{slog.NewLogLogger(logger.Handler(), slog.LevelError).Writer()}, "", 0)
}

// deniedStreamFilter drops the lines that report errStreamDenied.
type deniedStreamFilter struct{ w io.Writer }

func (f deniedStreamFilter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(errStreamDenied.Error())) {
		return len(p), nil
	}
	return f.w.Write(p)
}

// streamBody is the body of a streamed response inspected event by event
// (#323, 0006 §2), as ext_proc inspects it: it reads the upstream's body,
// splits it into events (pkg/streams), inspects each, and gives out only
// complete, allowed events when it holds them (block mode); a denied one
// ends it with errStreamDenied. Detect mode gives out each part at once and
// inspects a copy. It holds its share of the proxy's bound on held bytes
// until closed.
type streamBody struct {
	ctx   context.Context
	h     *Handler
	x     *exchange
	resp  *request.Response
	body  io.ReadCloser
	split *streams.Splitter
	holds bool

	buf []byte
	// held are the bytes read and not given out yet, from base, an offset
	// in the stream; out, those given out and not read yet.
	held   []byte
	base   int64
	out    []byte
	err    error
	events int

	release func()
	once    sync.Once
}

func (b *streamBody) Read(p []byte) (int, error) {
	for len(b.out) == 0 && b.err == nil {
		n, err := b.body.Read(b.buf)
		chunk := b.buf[:n]
		b.held = append(b.held, chunk...)
		evs := b.split.Write(chunk)
		if err != nil {
			evs = append(evs, b.split.Close()...)
		}
		if !b.holds {
			b.releaseTo(b.base + int64(len(b.held)))
		}
		for _, ev := range evs {
			b.events++
			v := b.x.ex.CheckEvent(b.ctx, b.x.req, b.resp, ev, b.events)
			if httpadapter.IsEvent(v) {
				httpadapter.LogEvent(b.ctx, b.h.logger, b.h.events, b.x.req, b.x.path, v)
			}
			if v.Action == pipeline.ActionDeny {
				// The events before it go out; it and the rest never do.
				b.held, b.err = nil, errStreamDenied
				break
			}
			b.releaseTo(ev.End)
		}
		if b.err != nil {
			break
		}
		if err != nil {
			b.releaseTo(b.base + int64(len(b.held)))
			b.err = err
			break
		}
		b.releaseTo(b.base + int64(len(b.held)) - b.split.Pending())
	}
	n := copy(p, b.out)
	b.out = b.out[n:]
	if len(b.out) == 0 && b.err != nil {
		return n, b.err
	}
	return n, nil
}

// releaseTo gives out the held bytes up to off, an offset in the stream.
func (b *streamBody) releaseTo(off int64) {
	if off <= b.base {
		return
	}
	k := min(off-b.base, int64(len(b.held)))
	b.out = append(b.out, b.held[:k]...)
	b.held = append(b.held[:0], b.held[k:]...)
	b.base += k
}

func (b *streamBody) Close() error {
	b.once.Do(b.release)
	return b.body.Close()
}
