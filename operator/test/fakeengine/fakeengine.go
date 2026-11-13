// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package fakeengine is a lightweight engine for operator tests (0004 §9):
// it speaks the bundle protocol, verifies each bundle's signature and
// acknowledges it, without inspecting any traffic. Many fit in one test.
package fakeengine

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// Engine is a fake engine.
type Engine struct {
	ID string
	// Addr is the operator's distribution server, host:port.
	Addr string
	// TLS verifies the operator's certificate.
	TLS *tls.Config
	// Token is the ServiceAccount token sent as a bearer token.
	Token string
	// PublicKeys verify bundles, chosen by their key ID; SetPublicKeys
	// changes them while the engine runs, as a reloaded key file does.
	PublicKeys []ed25519.PublicKey
	// Reject, if set, decides whether to refuse a bundle (Nack).
	Reject func(*bundlev1.Bundle) error
	// Heartbeat is the interval of heartbeats; 0 means 1s.
	Heartbeat time.Duration
	// OnApply, if set, is called with each bundle the engine applies,
	// before its Ack.
	OnApply func(*bundlev1.Bundle)
	// KeepVersionOnly keeps only the version of the applied bundle, not
	// its policies: hundreds of engines with a large bundle each would
	// take gigabytes (the scale test, operator/test/scale).
	KeepVersionOnly bool
	// Shared, if set, is shared by the engines of one process: an engine
	// given the very bundle another one verified, byte for byte with the
	// same key, takes that one's result instead of decoding it again. The
	// bundle passed to Reject and OnApply, and kept, is then shared: read
	// only. Real engines each decode on their own CPU, at once; hundreds
	// of fake engines in one process decoding a 2 MB bundle at once took
	// gigabytes, and on a busy machine stalled long enough for the
	// operator to close their connections (the scale test, #296).
	Shared *Shared
	// PodNamespace and PodName name the engine's pod in its Hello;
	// default "test" and ID.
	PodNamespace, PodName string
	// ProbeReceipts, if set, returns the probe receipts each heartbeat
	// reports (#475).
	ProbeReceipts func() []string

	mu      sync.Mutex
	applied *bundlev1.Bundle
	nacks   int
	err     error
}

// SetPublicKeys replaces the trusted keys; heartbeats report them.
func (e *Engine) SetPublicKeys(keys ...ed25519.PublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.PublicKeys = keys
}

func (e *Engine) keys() []ed25519.PublicKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.PublicKeys
}

// TrustedKeys returns the IDs of the trusted keys.
func (e *Engine) TrustedKeys() []string {
	var ids []string
	for _, k := range e.keys() {
		ids = append(ids, bundlekey.ID(k))
	}
	return ids
}

// Nacks returns how many bundles the engine rejected.
func (e *Engine) Nacks() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nacks
}

// Applied returns the bundle the engine runs, nil before the first.
func (e *Engine) Applied() *bundlev1.Bundle {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applied
}

// Err returns why the stream ended, once Run returned.
func (e *Engine) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}

func (bearer) RequireTransportSecurity() bool { return true }

// Run connects and serves one stream until ctx ends or the stream fails.
func (e *Engine) Run(ctx context.Context) error {
	err := e.run(ctx)
	e.mu.Lock()
	e.err = err
	e.mu.Unlock()
	return err
}

func (e *Engine) run(ctx context.Context) error {
	conn, err := grpc.NewClient(e.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(e.TLS)),
		grpc.WithPerRPCCredentials(bearer(e.Token)),
		// As the real engine: a bundle up to its limit, decompressed, so a
		// large bundle doesn't break the engines of later tests.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(bundlesecret.MaxBundleBytes+(1<<20))))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stream, err := agentv1.NewBundleServiceClient(conn).Watch(ctx)
	if err != nil {
		return err
	}
	var current uint64
	if a := e.Applied(); a != nil {
		current = a.GetVersion()
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{
		EngineId: e.ID, PodNamespace: cmp.Or(e.PodNamespace, "test"), PodName: cmp.Or(e.PodName, e.ID), EngineVersion: "fake", BundleVersion: current,
		TrustedKeyIds: e.TrustedKeys(),
	}}}); err != nil {
		// The operator may have ended the stream first (rejected the
		// engine): its status comes with Recv.
		if errors.Is(err, io.EOF) {
			_, err = stream.Recv()
		}
		return err
	}

	var sendMu sync.Mutex
	send := func(m *agentv1.WatchRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}
	interval := e.Heartbeat
	if interval == 0 {
		interval = time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				var v uint64
				if a := e.Applied(); a != nil {
					v = a.GetVersion()
				}
				hb := &agentv1.Heartbeat{BundleVersion: v, TrustedKeyIds: e.TrustedKeys()}
				if e.ProbeReceipts != nil {
					hb.ProbeReceipts = e.ProbeReceipts()
				}
				if send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: hb}}) != nil {
					return
				}
			case <-stream.Context().Done():
				return
			}
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		signed := msg.GetBundle()
		if signed == nil {
			continue
		}
		b, verr := e.verify(signed)
		if verr == nil && e.Reject != nil {
			verr = e.Reject(b)
		}
		if verr != nil {
			e.mu.Lock()
			e.nacks++
			e.mu.Unlock()
			var v uint64
			if b != nil {
				v = b.GetVersion()
			}
			if err := send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Nack{Nack: &agentv1.Nack{BundleVersion: v, Error: verr.Error()}}}); err != nil {
				return err
			}
			continue
		}
		if e.OnApply != nil {
			e.OnApply(b)
		}
		if e.KeepVersionOnly {
			b = &bundlev1.Bundle{Version: b.GetVersion()}
		}
		e.mu.Lock()
		e.applied = b
		e.mu.Unlock()
		if err := send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Ack{Ack: &agentv1.Ack{BundleVersion: b.GetVersion()}}}); err != nil {
			return err
		}
	}
}

// verify checks the signature before decoding, as a real engine must: an
// unverified bundle's content, its version included, can't be trusted.
func (e *Engine) verify(signed *bundlev1.SignedBundle) (*bundlev1.Bundle, error) {
	keys := e.keys()
	i := slices.IndexFunc(keys, func(k ed25519.PublicKey) bool { return bundlekey.ID(k) == signed.GetKeyId() })
	if i < 0 {
		return nil, fmt.Errorf("unknown key %q", signed.GetKeyId())
	}
	if e.Shared != nil {
		return e.Shared.verify(keys[i], signed)
	}
	return verify(keys[i], signed)
}

// Shared is the bundle the engines of a process verified last; the zero
// value is ready.
type Shared struct {
	mu   sync.Mutex
	last *verified
}

// verified is a signed bundle and the result of verifying it, once done
// is closed.
type verified struct {
	key       ed25519.PublicKey
	bundle    []byte
	signature []byte

	done chan struct{}
	b    *bundlev1.Bundle
	err  error
}

func (v *verified) is(key ed25519.PublicKey, signed *bundlev1.SignedBundle) bool {
	return v != nil && v.key.Equal(key) && bytes.Equal(v.signature, signed.GetSignature()) && bytes.Equal(v.bundle, signed.GetBundle())
}

// verify verifies signed with key, or takes the result for the same bytes
// and key.
func (s *Shared) verify(key ed25519.PublicKey, signed *bundlev1.SignedBundle) (*bundlev1.Bundle, error) {
	s.mu.Lock()
	v := s.last
	s.mu.Unlock()
	if !v.is(key, signed) { // compared unlocked: 2 MB take a while
		s.mu.Lock()
		if v = s.last; !v.is(key, signed) {
			v = &verified{key: key, bundle: signed.GetBundle(), signature: signed.GetSignature(), done: make(chan struct{})}
			s.last = v
			s.mu.Unlock()
			v.b, v.err = verify(key, signed)
			close(v.done)
			return v.b, v.err
		}
		s.mu.Unlock()
	}
	<-v.done
	return v.b, v.err
}

func verify(key ed25519.PublicKey, signed *bundlev1.SignedBundle) (*bundlev1.Bundle, error) {
	if !ed25519.Verify(key, signed.GetBundle(), signed.GetSignature()) {
		return nil, errors.New("bad signature")
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	return &b, nil
}
