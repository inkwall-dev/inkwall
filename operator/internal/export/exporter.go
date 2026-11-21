// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package export sends the engines' security events to SIEMs and log
// pipelines, from every operator replica, without the control plane
// (design 0010): each replica exports the events of the engines connected
// to it, from one bounded buffer with a cursor per sink, as OTLP logs
// (gRPC or HTTP) or JSON over HTTP.
package export

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Defaults of the Exporter (design 0010 §2.4).
const (
	DefaultBufferBytes  = 32 << 20
	DefaultDiskBytes    = 512 << 20
	DefaultFlushTimeout = 15 * time.Second
	defaultPoll         = 2 * time.Second
)

// Exporter exports the security events this replica receives. It isn't a
// manager runnable: the distribution server starts it, and stops it once
// its gRPC server has stopped, so no Add comes after the flush.
type Exporter struct {
	// Client reads the InkwallConfig and the operator's Secrets (cached).
	Client client.Reader
	// APIReader reads the kube-system Namespace, whose UID is the cluster's
	// ID, which the manager doesn't cache.
	APIReader client.Reader
	// Namespace is the operator's: the Secrets the sinks name are there.
	Namespace string
	// Dir holds the buffer on disk ("": in memory only); MemoryBytes and
	// DiskBytes bound it (defaults DefaultBufferBytes, DefaultDiskBytes).
	Dir                    string
	MemoryBytes, DiskBytes int64
	// FlushTimeout bounds the flush on Stop (default DefaultFlushTimeout).
	FlushTimeout time.Duration
	// Poll is how often the configuration and its Secrets are read again
	// (default 2 s).
	Poll time.Duration
	// HasPolicy reports whether the bundle this replica serves has a policy
	// (distribution.Store.HasPolicy): an event's policy counts only then.
	HasPolicy func(string) bool
	Metrics   Metrics
	Log       logr.Logger

	buf     atomic.Pointer[buffer]
	mu      sync.Mutex
	sinks   map[string]*runningSink
	cluster string
	cancel  context.CancelFunc
	loop    chan struct{}
	stopped atomic.Bool
	// after makes the senders' timers; tests shorten the backoff.
	after func(time.Duration) <-chan time.Time
}

type runningSink struct {
	sender *sender
	state  *sinkState
	cancel context.CancelFunc
	rt     *sinkRuntime
	last   string // the last state logged
}

// Add takes a batch from an engine (distribution.Server.Events), read
// only. It never blocks: it appends the batch under a mutex and returns,
// and a full buffer drops the oldest.
func (e *Exporter) Add(b *eventsv1.EventBatch) {
	if buf := e.buf.Load(); buf != nil && !e.stopped.Load() {
		buf.add(b)
	}
}

func (e *Exporter) defaults() {
	if e.MemoryBytes <= 0 {
		e.MemoryBytes = DefaultBufferBytes
	}
	if e.DiskBytes <= 0 {
		e.DiskBytes = DefaultDiskBytes
	}
	if e.FlushTimeout <= 0 {
		e.FlushTimeout = DefaultFlushTimeout
	}
	if e.Poll <= 0 {
		e.Poll = defaultPoll
	}
	if e.Metrics == nil {
		e.Metrics = noMetrics{}
	}
}

// Start opens the buffer (loading what a previous run left on disk) and
// starts the export. A directory that can't be used is replaced by memory.
func (e *Exporter) Start() error {
	e.defaults()
	buf, err := openBuffer(e.Dir, e.MemoryBytes, e.DiskBytes)
	if err != nil {
		e.Log.Error(err, "can't use the export buffer's directory; buffering in memory")
		if buf, err = openBuffer("", e.MemoryBytes, e.DiskBytes); err != nil {
			return err
		}
	}
	buf.onDiskError = func(err error) {
		e.Log.Error(err, "can't write the export buffer to disk; buffering in memory from now on")
	}
	e.sinks = map[string]*runningSink{}
	go buf.run()
	e.buf.Store(buf)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel, e.loop = cancel, make(chan struct{})
	go e.run(ctx)
	return nil
}

func (e *Exporter) run(ctx context.Context) {
	defer close(e.loop)
	t := time.NewTicker(e.Poll)
	defer t.Stop()
	for {
		e.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// reconcile applies the InkwallConfig's sinks: new ones start, removed
// ones stop, changed ones take their new configuration (a new transport
// when its endpoint, TLS material or URL changed).
func (e *Exporter) reconcile(ctx context.Context) {
	buf := e.buf.Load()
	var cfg wafv1alpha1.InkwallConfig
	err := e.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg)
	if err != nil && !apierrors.IsNotFound(err) {
		if ctx.Err() == nil {
			e.Log.Error(err, "reading the InkwallConfig for the export")
		}
		return
	}
	spec := cfg.Spec.Events.Export
	if apierrors.IsNotFound(err) || spec == nil || len(spec.Sinks) == 0 {
		e.apply(buf, nil)
		return
	}
	if e.cluster == "" {
		var ns corev1.Namespace
		if err := e.APIReader.Get(ctx, types.NamespacedName{Name: "kube-system"}, &ns); err != nil {
			if ctx.Err() == nil {
				e.Log.Error(err, "reading the cluster ID (the kube-system Namespace's UID) for the export")
			}
			return
		}
		e.cluster = string(ns.UID)
	}
	e.apply(buf, resolve(ctx, e.Client, e.Namespace, e.cluster, spec))
	e.logChanges()
}

func (e *Exporter) apply(buf *buffer, sinks []*sinkConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make([]string, 0, len(sinks))
	keep := map[string]bool{}
	for _, sc := range sinks {
		names = append(names, sc.name)
		keep[sc.name] = true
	}
	buf.setSinks(names)
	for name, rs := range e.sinks {
		if !keep[name] {
			e.stopSink(rs)
			delete(e.sinks, name)
			e.Metrics.Forget(name)
			e.Log.Info("export sink removed", "sink", name)
		}
	}
	for _, sc := range sinks {
		rs := e.sinks[sc.name]
		if rs == nil {
			st := &sinkState{}
			sctx, cancel := context.WithCancel(context.Background())
			rs = &runningSink{sender: newSender(sc.name, buf, e.HasPolicy, e.Metrics, st), state: st, cancel: cancel}
			if e.after != nil {
				rs.sender.after = e.after
			}
			e.sinks[sc.name] = rs
			go rs.sender.run(sctx)
			e.Log.Info("export sink added", "sink", sc.name)
		}
		var ce *configError
		if sc.err != nil && !errors.As(sc.err, &ce) && rs.rt != nil {
			// A Secret couldn't be read now: keep what runs.
			continue
		}
		rt := &sinkRuntime{cfg: sc}
		if sc.err == nil {
			if rs.rt != nil && rs.rt.client != nil && rs.rt.cfg.key == sc.key {
				rt.client = rs.rt.client
			} else {
				c, err := newClient(sc.transport)
				if err != nil {
					sc.err = invalid("sink %s: %v", sc.name, err)
					rt.cfg = sc
				} else {
					rt.client = &sharedClient{sinkClient: c}
				}
			}
		}
		// The sender retires the old client once its requests end.
		rs.rt = rt
		rs.state.configure(sc.err, sc.plaintext)
		rs.sender.configure(rt)
	}
	_, all := buf.bytes()
	e.Metrics.BufferBytes(all)
}

func (e *Exporter) stopSink(rs *runningSink) {
	rs.cancel()
	<-rs.sender.done
	if rs.rt != nil && rs.rt.client != nil {
		rs.rt.client.retire()
	}
}

// logChanges logs each sink whose state class changed.
func (e *Exporter) logChanges() {
	for _, st := range e.Status() {
		e.mu.Lock()
		rs := e.sinks[st.Name]
		if rs == nil || rs.last == st.State {
			e.mu.Unlock()
			continue
		}
		first := rs.last == ""
		rs.last = st.State
		e.mu.Unlock()
		switch {
		case st.State != StateExporting:
			e.Log.Info("export sink not exporting", "sink", st.Name, "state", st.State, "message", st.Message)
		case !first:
			e.Log.Info("export sink exporting again", "sink", st.Name)
		}
	}
}

// Status is each sink's state on this replica, sorted by name; none
// without sinks.
func (e *Exporter) Status() []SinkStatus {
	buf := e.buf.Load()
	if buf == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	out := make([]SinkStatus, 0, len(e.sinks))
	for name, rs := range e.sinks {
		out = append(out, rs.state.status(name, buf.pending(name), now))
	}
	slices.SortFunc(out, func(a, b SinkStatus) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return out
}

// Stop flushes: each sink sends what it holds at once, for up to
// FlushTimeout; then the senders stop and the buffer writes what is left
// to disk (lost with the pod, kept across a container restart). Call it
// once no Add can come.
func (e *Exporter) Stop() {
	buf := e.buf.Load()
	if buf == nil || e.stopped.Swap(true) {
		return
	}
	e.cancel()
	<-e.loop
	e.mu.Lock()
	sinks := make([]*runningSink, 0, len(e.sinks))
	for _, rs := range e.sinks {
		sinks = append(sinks, rs)
		close(rs.sender.flush)
	}
	e.mu.Unlock()
	deadline := time.NewTimer(e.FlushTimeout)
	defer deadline.Stop()
wait:
	for _, rs := range sinks {
		select {
		case <-rs.sender.drained:
		case <-rs.sender.done:
		case <-deadline.C:
			e.Log.Info("export flush deadline passed; what is left stays in the buffer", "timeout", e.FlushTimeout)
			break wait
		}
	}
	for _, rs := range sinks {
		e.stopSink(rs)
	}
	buf.close()
}
