// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// DefaultEventsBufferBytes bounds a replica's events buffer.
const DefaultEventsBufferBytes = 64 << 20

// Forwarder sends the security events of the engines connected to this
// replica to the control plane, on the replica's own events stream (0002
// §5.3). It runs on every replica, with the cluster's certificate, which
// the leader keeps in the identity Secret. It buffers only while the
// control plane accepts events; otherwise, as in Standalone mode, the
// engines' logs are the record.
type Forwarder struct {
	Client          client.Client
	Namespace       string
	Replica         string
	OperatorVersion string
	CAFile          string
	// Dir holds the buffer ("" keeps it in memory: lost on restart);
	// MaxBytes bounds it (default DefaultEventsBufferBytes).
	Dir      string
	MaxBytes int64

	// Poll is how often an idle forwarder looks again (default 5 s);
	// Refused, how long it waits after the control plane said it doesn't
	// accept events (default 1 min); MinBackoff and MaxBackoff bound
	// reconnects (default 1 s and 1 min).
	Poll, Refused, MinBackoff, MaxBackoff time.Duration

	// q is set by Start; Add may run before.
	q       atomic.Pointer[queue]
	accepts atomic.Bool
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every
// replica forwards its own engines' events.
func (*Forwarder) NeedLeaderElection() bool { return false }

func (f *Forwarder) defaults() {
	if f.Poll == 0 {
		f.Poll = 5 * time.Second
	}
	if f.Refused == 0 {
		f.Refused = time.Minute
	}
	if f.MinBackoff == 0 {
		f.MinBackoff = time.Second
	}
	if f.MaxBackoff == 0 {
		f.MaxBackoff = time.Minute
	}
	if f.MaxBytes == 0 {
		f.MaxBytes = DefaultEventsBufferBytes
	}
}

// Add takes a batch from an engine (distribution.Server.Events). It never
// blocks the engine's stream.
func (f *Forwarder) Add(b *eventsv1.EventBatch) {
	q := f.q.Load()
	if !f.accepts.Load() || q == nil {
		return
	}
	if err := q.add(b); err != nil {
		eventsForwardErrors.Inc()
	}
}

// Start implements manager.Runnable.
func (f *Forwarder) Start(ctx context.Context) error {
	f.defaults()
	logger := log.FromContext(ctx).WithName("control-plane-events")
	q, err := openQueue(f.Dir, f.MaxBytes)
	if err != nil {
		logger.Error(err, "can't use the events buffer's directory; buffering in memory")
		if q, err = openQueue("", f.MaxBytes); err != nil {
			return err
		}
	}
	f.q.Store(q)
	// What's on disk is resent once the control plane accepts events
	// again.
	f.accepts.Store(len(q.batches) > 0)
	backoff := f.MinBackoff
	for {
		connected, err := f.run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			backoff = f.MinBackoff
		}
		wait := f.Poll
		switch {
		case errors.Is(err, errRefused):
			wait = f.Refused
		case !errors.Is(err, errIdle):
			logger.Info("events stream ended; retrying", "error", err, "in", backoff)
			wait = backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not security
			backoff = min(2*backoff, f.MaxBackoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// errRefused means the control plane doesn't accept events: ask again later.
var errRefused = errors.New("the control plane doesn't accept events")

// run holds one events stream: Hello, Welcome, then the buffered batches
// and every new one, freeing them as they are acknowledged.
func (f *Forwarder) run(ctx context.Context) (bool, error) {
	var cfg wafv1alpha1.InkwallConfig
	err := f.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg)
	if apierrors.IsNotFound(err) || (err == nil && (cfg.Spec.Mode == "" || cfg.Spec.Mode == wafv1alpha1.ModeStandalone || cfg.Spec.ControlPlane == nil)) {
		f.stop()
		return false, errIdle
	}
	if err != nil {
		return false, err
	}
	target, host, err := parseEndpoint(cfg.Spec.ControlPlane.Endpoint)
	if err != nil {
		return false, errIdle // the leader reports it
	}
	// The leader enrolls and renews; replicas use what it stored.
	id, err := loadIdentity(ctx, f.Client, f.Namespace)
	if err != nil || id == nil || !time.Now().Before(id.notAfter) {
		return false, errIdle
	}
	conn, err := dial(f.CAFile, target, host, &id.cert)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := controlplanev1.NewControlPlaneServiceClient(conn).Connect(sctx)
	if err != nil {
		return false, err
	}
	mode := controlplanev1.ClusterMode_CLUSTER_MODE_GITOPS
	if cfg.Spec.Mode == wafv1alpha1.ModeManaged {
		mode = controlplanev1.ClusterMode_CLUSTER_MODE_MANAGED
	}
	if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_Hello{Hello: &controlplanev1.Hello{
		Role: controlplanev1.StreamRole_STREAM_ROLE_EVENTS, Replica: f.Replica, OperatorVersion: f.OperatorVersion, Mode: mode,
		Capabilities: []string{wafv1alpha1.GroupVersion.String()},
	}}}); err != nil {
		return false, err
	}
	first, err := stream.Recv()
	if err != nil {
		return false, err
	}
	welcome := first.GetWelcome()
	if welcome == nil {
		return false, errors.New("the control plane didn't answer Hello with Welcome")
	}
	if !welcome.GetAcceptEvents() {
		f.stop()
		return true, errRefused
	}
	f.accepts.Store(true)
	q := f.q.Load()

	acks := make(chan uint64, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if a := m.GetEventsAck(); a != nil && a.GetBufferId() == q.id {
				select {
				case acks <- a.GetSequence():
				case <-sctx.Done():
					return
				}
			}
		}
	}()
	interval := 30 * time.Second
	if d := welcome.GetHeartbeatInterval().AsDuration(); d > 0 {
		interval = d
	}
	heartbeat := time.NewTicker(interval)
	defer heartbeat.Stop()
	reconfigure := time.NewTicker(f.Poll)
	defer reconfigure.Stop()

	// Unacknowledged batches are resent on every new stream; the control
	// plane removes duplicates by event ID.
	var sent uint64
	for {
		for _, b := range q.after(sent) {
			if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_Events{Events: &controlplanev1.EventUpload{
				BufferId: q.id, Sequence: b.seq, Batch: b.batch,
			}}}); err != nil {
				return true, err
			}
			eventsForwarded.Add(float64(len(b.batch.GetEvents())))
			sent = b.seq
		}
		select {
		case <-ctx.Done():
			return true, nil
		case err := <-recvErr:
			return true, fmt.Errorf("events stream: %w", err)
		case seq := <-acks:
			q.ack(seq)
		case <-q.changed:
		case <-heartbeat.C:
			if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_Heartbeat{Heartbeat: &controlplanev1.Heartbeat{
				Time: timestamppb.Now(), BufferedEvents: q.events(),
			}}}); err != nil {
				return true, err
			}
		case <-reconfigure.C:
			var now wafv1alpha1.InkwallConfig
			if err := f.Client.Get(ctx, types.NamespacedName{Name: "default"}, &now); err != nil || now.Generation != cfg.Generation {
				return true, errors.New("configuration changed")
			}
		}
		eventsBuffered.Set(float64(q.events()))
	}
}

// stop drops the buffer: the control plane doesn't take events (Standalone,
// or it said so).
func (f *Forwarder) stop() {
	f.accepts.Store(false)
	if q := f.q.Load(); q != nil {
		q.clear()
	}
	eventsBuffered.Set(0)
}
