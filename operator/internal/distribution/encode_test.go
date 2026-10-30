// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// countingCodec is gRPC's proto codec, counting the bundles it marshals.
type countingCodec struct {
	encoding.CodecV2
	bundles, bytes atomic.Int64
}

func (c *countingCodec) Marshal(v any) (mem.BufferSlice, error) {
	out, err := c.CodecV2.Marshal(v)
	if r, ok := v.(*agentv1.WatchResponse); ok && r.GetBundle() != nil {
		c.bundles.Add(1)
		c.bytes.Add(int64(out.Len()))
	}
	return out, err
}

func bigBundle(version uint64, size int) *bundlev1.SignedBundle {
	return &bundlev1.SignedBundle{Bundle: bytes.Repeat([]byte{byte(version)}, size), Signature: []byte("sig"), KeyId: "k"}
}

// watch connects engines and returns their streams, after their Hello.
func watch(t *testing.T, c agentv1.BundleServiceClient, engines int, opts ...grpc.CallOption) []agentv1.BundleService_WatchClient {
	t.Helper()
	ctx, cancel := context.WithCancel(withToken(context.Background(), "engine"))
	t.Cleanup(cancel)
	streams := make([]agentv1.BundleService_WatchClient, engines)
	for i := range streams {
		s, err := c.Watch(ctx, opts...)
		if err != nil {
			t.Fatal(err)
		}
		hello := &agentv1.Hello{EngineId: fmt.Sprintf("e%d", i)}
		if err := s.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: hello}}); err != nil {
			t.Fatal(err)
		}
		streams[i] = s
	}
	return streams
}

// receive checks that every stream gets want.
func receive(t *testing.T, streams []agentv1.BundleService_WatchClient, want *bundlev1.SignedBundle) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan string, len(streams))
	for _, s := range streams {
		wg.Go(func() {
			resp, err := s.Recv()
			if err != nil {
				errs <- err.Error()
			} else if !proto.Equal(resp.GetBundle(), want) {
				errs <- "got another bundle than the one sent"
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestWatchEncodesEachBundleOnce(t *testing.T) {
	// #147: the operator held one encoding of the bundle per engine.
	const engines, size = 40, 256 << 10
	codec := &countingCodec{CodecV2: encoding.GetCodecV2("proto")}
	store := NewStore()
	store.Set(bigBundle(1, size), 1)
	c := serve(t, NewServer(store, NewTable(), fakeAuth{}, "r", logr.Discard()), grpc.ForceServerCodecV2(codec))

	streams := watch(t, c, engines)
	receive(t, streams, bigBundle(1, size))
	b2 := bigBundle(2, size)
	store.Set(b2, 2)
	receive(t, streams, b2)

	if got := codec.bundles.Load(); got != 2 {
		t.Errorf("%d engines, 2 bundles: marshalled %d times, want 2", engines, got)
	}
	if got := codec.bytes.Load(); got > 2*(size+1<<10) {
		t.Errorf("marshalled %d bytes for 2 bundles of %d", got, size)
	}
}

func TestWatchEncodedCompatible(t *testing.T) {
	// Engines get the same message as when each stream marshalled it,
	// whether they ask for compression or not, on the same server.
	store := NewStore()
	b1 := bigBundle(1, 64<<10)
	store.Set(b1, 1)
	c := serve(t, NewServer(store, NewTable(), fakeAuth{}, "r", logr.Discard()))

	// The compressed encoding comes first: the others must not get it.
	gzipped := watch(t, c, 3, grpc.UseCompressor(gzip.Name))
	receive(t, gzipped, b1)
	plain := watch(t, c, 3)
	receive(t, plain, b1)
	all := slices.Concat(gzipped, plain)
	b2 := bigBundle(2, 64<<10)
	store.Set(b2, 2)
	receive(t, all, b2)
}
