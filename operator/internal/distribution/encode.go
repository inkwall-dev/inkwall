// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"sync"

	"google.golang.org/grpc"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// encodedVersions is how many bundles the encoder keeps encoded: the
// current one, and the one before for the streams that took it from the
// Store just before it was replaced.
const encodedVersions = 2

// encoder encodes each bundle once for every stream (#147). A stream's Send
// returns once its message is queued on the connection, not once it is
// written, so with every stream marshalling the bundle itself the operator
// held engines × bundle bytes until the slowest engine read it. The shared
// encoding is one buffer, which the transport only reads: the queued
// messages of all streams hold that one, whatever the number of engines.
type encoder struct {
	mu sync.Mutex
	// bundles, newest first, with their encodings by the stream's send
	// compressor ("" for none).
	bundles []encoded
}

type encoded struct {
	signed *bundlev1.SignedBundle
	msgs   map[string]*grpc.PreparedMsg
}

// message returns the message carrying signed for stream, encoded once
// for all the streams that send it with the same compressor. The encoding
// is gRPC's own for the stream, so engines receive the same bytes as when
// each stream marshalled the bundle.
func (e *encoder) message(stream grpc.ServerStream, signed *bundlev1.SignedBundle) (any, error) {
	msg := &agentv1.WatchResponse{Msg: &agentv1.WatchResponse_Bundle{Bundle: signed}}
	comp, ok := sendCompressor(stream.Context())
	if !ok {
		// Can't tell how the stream compresses: let it encode itself.
		return msg, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	i := 0
	for i < len(e.bundles) && e.bundles[i].signed != signed {
		i++
	}
	if i == len(e.bundles) {
		// A new bundle: forget the oldest, so it is freed once the streams
		// that queued it wrote it.
		if len(e.bundles) == encodedVersions {
			e.bundles = e.bundles[:encodedVersions-1]
		}
		e.bundles = append([]encoded{{signed: signed, msgs: map[string]*grpc.PreparedMsg{}}}, e.bundles...)
		i = 0
	}
	b := e.bundles[i]
	if p := b.msgs[comp]; p != nil {
		return p, nil
	}
	// Encoded under the lock: the streams that want it meanwhile wait for
	// it rather than encode it too.
	p := &grpc.PreparedMsg{}
	if err := p.Encode(stream, msg); err != nil {
		return nil, err
	}
	b.msgs[comp] = p
	return p, nil
}

// sendCompressor returns the compressor gRPC chose for the stream's
// messages: the engine's, if the operator has it, else none. A PreparedMsg
// is compressed with it, so it is shared only by streams that use the same.
func sendCompressor(ctx context.Context) (string, bool) {
	s, ok := grpc.ServerTransportStreamFromContext(ctx).(interface{ SendCompress() string })
	if !ok {
		return "", false
	}
	return s.SendCompress(), true
}
