// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// Defaults of the Server.
const (
	// DefaultHelloTimeout bounds how long an engine may take to say Hello.
	DefaultHelloTimeout = 10 * time.Second
	// DefaultIdleTimeout closes a stream that sent nothing (no heartbeat)
	// for this long; engines send heartbeats every few seconds.
	DefaultIdleTimeout = 30 * time.Second
	// DefaultMaxSends bounds concurrent bundle sends, so a new bundle for
	// hundreds of engines doesn't spike the operator.
	DefaultMaxSends = 50
)

// Server implements BundleService.
type Server struct {
	agentv1.UnimplementedBundleServiceServer

	Bundles *Store
	Engines *Table
	Auth    Authenticator
	// Replica names this operator replica in the engine records.
	Replica string
	Log     logr.Logger

	HelloTimeout time.Duration
	IdleTimeout  time.Duration

	// Events receives the engines' security events, stamped with the
	// stream's engine and pod. Nil: they are counted and discarded.
	Events func(*eventsv1.EventBatch)

	sends chan struct{}
	enc   encoder
}

// NewServer returns a Server with the defaults.
func NewServer(bundles *Store, engines *Table, auth Authenticator, replica string, log logr.Logger) *Server {
	return &Server{
		Bundles:      bundles,
		Engines:      engines,
		Auth:         auth,
		Replica:      replica,
		Log:          log,
		HelloTimeout: DefaultHelloTimeout,
		IdleTimeout:  DefaultIdleTimeout,
		sends:        make(chan struct{}, DefaultMaxSends),
	}
}

func bearerToken(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		if t, ok := strings.CutPrefix(v, "Bearer "); ok {
			return t
		}
	}
	return ""
}

type received struct {
	msg *agentv1.WatchRequest
	err error
}

// Watch serves one engine: Hello, then the current bundle and every new one,
// while recording its acks, nacks and heartbeats.
func (s *Server) Watch(stream agentv1.BundleService_WatchServer) error {
	ctx := stream.Context()
	id, err := s.Auth.Authenticate(ctx, bearerToken(ctx))
	switch {
	case errors.Is(err, ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, err.Error())
	case err != nil:
		s.Log.Error(err, "authenticating an engine")
		return status.Error(codes.Unavailable, "can't authenticate the engine now; retry")
	}

	// Receive in the background, so the waits below can also time out.
	recv := make(chan received)
	go func() {
		for {
			msg, err := stream.Recv()
			select {
			case recv <- received{msg, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	var hello *agentv1.Hello
	select {
	case r := <-recv:
		if r.err != nil {
			return r.err
		}
		hello = r.msg.GetHello()
	case <-time.After(s.HelloTimeout):
		return status.Error(codes.DeadlineExceeded, "no Hello")
	case <-ctx.Done():
		return ctx.Err()
	}
	if hello == nil || hello.GetEngineId() == "" {
		return status.Error(codes.InvalidArgument, "the first message must be a Hello with an engine_id")
	}

	engineID := hello.GetEngineId()
	e := Engine{
		ID:             engineID,
		ServiceAccount: id.ServiceAccount,
		PodNamespace:   hello.GetPodNamespace(),
		PodName:        hello.GetPodName(),
		NodeName:       hello.GetNodeName(),
		EngineVersion:  hello.GetEngineVersion(),
		Applied:        hello.GetBundleVersion(),
		TrustedKeys:    hello.GetTrustedKeyIds(),
		Replica:        s.Replica,
		ConnectedAt:    time.Now().UTC(),
	}
	// A pod-bound token is the authoritative source.
	if id.PodName != "" {
		e.PodNamespace, e.PodName = id.PodNamespace, id.PodName
	}
	conn := s.Engines.Connect(e)
	defer s.Engines.Disconnect(engineID, conn)
	log := s.Log.WithValues("engine", engineID, "serviceAccount", id.ServiceAccount, "pod", hello.GetPodNamespace()+"/"+hello.GetPodName())
	log.Info("engine connected", "bundle", hello.GetBundleVersion())
	defer log.Info("engine disconnected")

	// Bundles are sent from their own goroutine, so the engine's messages
	// are still read, and its heartbeats still keep the stream alive, while
	// a send waits for a slot or for the engine to take the bundle (#148).
	sendCtx, stopSending := context.WithCancel(ctx)
	sendErr, sending := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(sending)
		sendErr <- s.sendBundles(sendCtx, stream, hello.GetBundleVersion())
	}()
	// The stream may not be used once Watch returns. A Send stuck on a dead
	// engine ends when keepalive closes its connection.
	defer func() { stopSending(); <-sending }()

	idle := time.NewTimer(s.IdleTimeout)
	defer idle.Stop()
	for {
		select {
		case err := <-sendErr:
			return err
		case r := <-recv:
			if r.err != nil {
				return r.err
			}
			if !idle.Stop() {
				<-idle.C
			}
			idle.Reset(s.IdleTimeout)
			if batch := r.msg.GetEvents(); batch != nil {
				s.events(e, batch)
				continue
			}
			s.record(engineID, r.msg, log)
		case <-idle.C:
			return status.Error(codes.DeadlineExceeded, "no message from the engine in "+s.IdleTimeout.String())
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// sendBundles sends the current bundle and every new one, starting from
// the engine's version sent, until ctx is done or a send fails.
func (s *Server) sendBundles(ctx context.Context, stream agentv1.BundleService_WatchServer, sent uint64) error {
	for {
		signed, version, changed := s.Bundles.Current()
		// Any other version is sent, even an older one: after the operator
		// lost its bundle Secret, the engine's newer version is not one
		// this cluster's operator can vouch for.
		if signed != nil && version != sent {
			if err := s.send(ctx, stream, signed); err != nil {
				return err
			}
			sent = version
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Server) send(ctx context.Context, stream agentv1.BundleService_WatchServer, signed *bundlev1.SignedBundle) error {
	select {
	case s.sends <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.sends }()
	msg, err := s.enc.message(stream, signed)
	if err != nil {
		return err
	}
	return stream.SendMsg(msg)
}

// events takes a batch from engine e. The engine and pod come from the
// stream, which the operator authenticated, not from the events.
func (s *Server) events(e Engine, batch *eventsv1.EventBatch) {
	eventsReceived.Add(float64(len(batch.GetEvents())))
	eventsDroppedByEngines.Add(float64(batch.GetDropped()))
	for _, ev := range batch.GetEvents() {
		ev.EngineId, ev.PodNamespace, ev.PodName = e.ID, e.PodNamespace, e.PodName
	}
	if s.Events != nil {
		s.Events(batch)
	}
}

func (s *Server) record(engineID string, msg *agentv1.WatchRequest, log logr.Logger) {
	switch m := msg.GetMsg().(type) {
	case *agentv1.WatchRequest_Ack:
		v := m.Ack.GetBundleVersion()
		s.Engines.Update(engineID, func(e *Engine) bool { return set(&e.Applied, v) })
		log.V(1).Info("bundle applied", "version", v)
	case *agentv1.WatchRequest_Nack:
		v, reason := m.Nack.GetBundleVersion(), m.Nack.GetError()
		s.Engines.Update(engineID, func(e *Engine) bool {
			a, b := set(&e.Rejected, v), set(&e.RejectError, reason) // both, no short circuit
			return a || b
		})
		log.Info("bundle rejected", "version", v, "error", reason)
	case *agentv1.WatchRequest_Heartbeat:
		// Mostly unchanged: it keeps the stream alive.
		v, keys := m.Heartbeat.GetBundleVersion(), m.Heartbeat.GetTrustedKeyIds()
		s.Engines.Update(engineID, func(e *Engine) bool {
			changed := set(&e.Applied, v)
			if !slices.Equal(e.TrustedKeys, keys) {
				e.TrustedKeys, changed = keys, true
			}
			return changed
		})
	}
}

// set assigns v to *p and reports whether that changed it.
func set[T comparable](p *T, v T) bool {
	if *p == v {
		return false
	}
	*p = v
	return true
}
