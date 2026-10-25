// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package fakeengine is a lightweight engine for operator tests (0004 §9):
// it speaks the bundle protocol, verifies each bundle's signature and
// acknowledges it, without inspecting any traffic. Many fit in one test.
package fakeengine

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
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
	// PublicKey verifies bundles.
	PublicKey ed25519.PublicKey
	// Reject, if set, decides whether to refuse a bundle (Nack).
	Reject func(*bundlev1.Bundle) error
	// Heartbeat is the interval of heartbeats; 0 means 1s.
	Heartbeat time.Duration

	mu      sync.Mutex
	applied *bundlev1.Bundle
	err     error
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
		grpc.WithPerRPCCredentials(bearer(e.Token)))
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
		EngineId: e.ID, PodNamespace: "test", PodName: e.ID, EngineVersion: "fake", BundleVersion: current,
	}}}); err != nil {
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
				if send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{BundleVersion: v}}}) != nil {
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
			var v uint64
			if b != nil {
				v = b.GetVersion()
			}
			if err := send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Nack{Nack: &agentv1.Nack{BundleVersion: v, Error: verr.Error()}}}); err != nil {
				return err
			}
			continue
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
	if !ed25519.Verify(e.PublicKey, signed.GetBundle(), signed.GetSignature()) {
		return nil, errors.New("bad signature")
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	return &b, nil
}
