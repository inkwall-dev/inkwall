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
	"github.com/inkwall-dev/inkwall/pkg/events"
)

const (
	// DefaultEventsBufferBytes bounds a replica's events buffer.
	DefaultEventsBufferBytes = 64 << 20
	// DefaultEventsMaxBackoff bounds the wait between events stream
	// reconnects.
	DefaultEventsMaxBackoff = 10 * time.Second
	// maxEventUpload bounds the events of an upload, encoded: each fits
	// the contract's maxMessage, with room.
	maxEventUpload = 4 << 20
)

// Forwarder sends the security events and request counts of the engines
// connected to this replica to the control plane, on the replica's own
// events stream (0002 §5.3). It runs on every replica, with the cluster's
// certificate, which the leader keeps in the identity Secret. It buffers
// events only while the control plane accepts them; otherwise, as in
// Standalone mode, the engines' logs are the record. Request counts are
// sent only to a control plane that accepts them.
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
	// accept events, or keeps a stream that carries only request counts
	// before asking again (default 1 min); MinBackoff and MaxBackoff bound
	// reconnects (default 1 s and 10 s: lower than the leader's, so the
	// buffer drains soon after an outage); StatsInterval, how often the
	// request counts that changed are sent (default DefaultStatsInterval).
	Poll, Refused, MinBackoff, MaxBackoff, StatsInterval time.Duration

	// HasPolicy reports whether the bundle this replica serves has a policy
	// (distribution.Store.HasPolicy). Past a limit, the request counts of
	// the others are forgotten; nil forgets them all. Set before AddStats.
	HasPolicy func(id string) bool

	// q is set by Start; Add may run before.
	q       atomic.Pointer[queue]
	accepts atomic.Bool
	stats   requestStats
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
		f.MaxBackoff = DefaultEventsMaxBackoff
	}
	if f.MaxBytes == 0 {
		f.MaxBytes = DefaultEventsBufferBytes
	}
	if f.StatsInterval == 0 {
		f.StatsInterval = DefaultStatsInterval
	}
}

// Add takes a batch from an engine (distribution.Server.Events). It never
// blocks the engine's stream.
func (f *Forwarder) Add(b *eventsv1.EventBatch) {
	q := f.q.Load()
	if !f.accepts.Load() || q == nil {
		return
	}
	for _, part := range events.Split(b, maxEventUpload) {
		if err := q.add(part); err != nil {
			eventsForwardErrors.Inc()
		}
	}
}

// AddStats takes what engines counted per policy since their previous
// reports (distribution.Server.Stats).
func (f *Forwarder) AddStats(deltas []*eventsv1.PolicyStats) { f.stats.add(deltas, f.HasPolicy) }

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
	q.track(eventsBuffered)
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
			wait = backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not security
			logger.Info("events stream ended; retrying", "error", err, "in", wait)
			backoff = min(2*backoff, f.MaxBackoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// errRefused means the control plane accepts neither events nor request
// counts: ask again later.
var errRefused = errors.New("the control plane doesn't accept events or request counts")

// statsCapability tells the control plane the replica can send request
// counts (Hello.capabilities).
const statsCapability = "request-stats"

// run holds one events stream: Hello, Welcome, then the buffered batches
// and every new one, freeing them as they are acknowledged, and the
// request counts.
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
		Capabilities: []string{statsCapability, wafv1alpha1.GroupVersion.String()},
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
	acceptStats := welcome.GetAcceptRequestStats()
	if !welcome.GetAcceptEvents() {
		f.stop()
		if !acceptStats {
			return true, errRefused
		}
	} else {
		f.accepts.Store(true)
	}
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
	var statsTick, askAgain <-chan time.Time
	if !welcome.GetAcceptEvents() {
		// Only request counts: Hello again in a while, to learn whether
		// events are accepted by then.
		t := time.NewTimer(f.Refused)
		defer t.Stop()
		askAgain = t.C
	}
	if acceptStats {
		t := time.NewTicker(f.StatsInterval)
		defer t.Stop()
		statsTick = t.C
		// Every policy first: the control plane may have lost the last.
		if err := f.sendStats(stream, true); err != nil {
			return true, err
		}
	}

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
		case <-askAgain:
			return true, errIdle
		case <-statsTick:
			if err := f.sendStats(stream, false); err != nil {
				return true, err
			}
		case <-reconfigure.C:
			var now wafv1alpha1.InkwallConfig
			if err := f.Client.Get(ctx, types.NamespacedName{Name: "default"}, &now); err != nil || now.Generation != cfg.Generation {
				return true, errors.New("configuration changed")
			}
		}
	}
}

// sendStats sends the request counts that changed since the last upload,
// or all of them.
func (f *Forwarder) sendStats(stream controlplanev1.ControlPlaneService_ConnectClient, all bool) error {
	up := f.stats.upload(all)
	if up == nil {
		return nil
	}
	return stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_RequestStats{RequestStats: up}})
}

// stop drops the buffer: the control plane doesn't take events (Standalone,
// or it said so).
func (f *Forwarder) stop() {
	f.accepts.Store(false)
	if q := f.q.Load(); q != nil {
		q.clear()
	}
}
