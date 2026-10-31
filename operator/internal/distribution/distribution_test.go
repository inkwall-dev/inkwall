// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func TestEnforced(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int64
		engines []Engine
		status  metav1.ConditionStatus
		reason  string
		message string
	}{
		{"not in a bundle", 0, []Engine{{Applied: 3}}, metav1.ConditionFalse, ReasonNotInBundle, "not in a bundle"},
		{"no engines", 3, nil, metav1.ConditionFalse, ReasonNoEngines, "no engine"},
		{"all current", 3, []Engine{{Applied: 3}, {Applied: 4}}, metav1.ConditionTrue, ReasonEnforced, "2/2 engines on bundle 3"},
		{"one behind", 3, []Engine{{Applied: 3}, {Applied: 2}}, metav1.ConditionFalse, ReasonEnginesBehind, "1/2 engines on bundle 3"},
		{
			"one rejected", 3,
			[]Engine{{Applied: 3}, {Applied: 2, Rejected: 3, RejectError: "line 1: bad rule", PodNamespace: "traefik", PodName: "traefik-1"}},
			metav1.ConditionFalse, ReasonEngineNack, "1/2 engines rejected bundle 3 (traefik/traefik-1: line 1: bad rule)",
		},
		// A rejection of an older bundle doesn't matter once the engine
		// runs a newer one.
		{"old rejection", 3, []Engine{{Applied: 3, Rejected: 2}}, metav1.ConditionTrue, ReasonEnforced, "1/1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, reason, msg := Enforced(tc.version, tc.engines)
			if st != tc.status || reason != tc.reason || !strings.Contains(msg, tc.message) {
				t.Fatalf("got %s %s %q, want %s %s %q", st, reason, msg, tc.status, tc.reason, tc.message)
			}
		})
	}
}

func TestTableReconnect(t *testing.T) {
	tab := NewTable()
	old := tab.Connect(Engine{ID: "e1", Applied: 1})
	// The engine reconnects before its old stream ended.
	cur := tab.Connect(Engine{ID: "e1", Applied: 2})
	tab.Disconnect("e1", old)
	got, _ := tab.Snapshot()
	if len(got) != 1 || got[0].Applied != 2 {
		t.Fatalf("the old stream's disconnect removed the new one: %+v", got)
	}
	_, gen := tab.Snapshot()
	tab.Update("e1", func(e *Engine) bool { return set(&e.Applied, 2) })
	if _, g := tab.Snapshot(); g != gen {
		t.Error("an update that changed nothing changed the generation")
	}
	tab.Disconnect("e1", cur)
	if got, _ := tab.Snapshot(); len(got) != 0 {
		t.Fatalf("not removed: %+v", got)
	}
}

func TestReadEngines(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	report := func(replica string, updated time.Time, engines ...Engine) *corev1.ConfigMap {
		data, _ := json.Marshal(engines)
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + replica, Labels: map[string]string{EnginesLabel: "true"}},
			Data:       map[string]string{enginesKey: string(data), updatedAtKey: updated.Format(time.RFC3339Nano)},
		}
	}
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		report("a", now.Add(-time.Second),
			Engine{ID: "e1", Applied: 1, ConnectedAt: now.Add(-time.Hour)},
			Engine{ID: "e2", Applied: 2}),
		// e1 moved to replica b more recently.
		report("b", now.Add(-time.Second), Engine{ID: "e1", Applied: 3, ConnectedAt: now.Add(-time.Minute)}),
		// Replica c is gone: its report is stale.
		report("c", now.Add(-time.Hour), Engine{ID: "e3", Applied: 3}),
	).Build()

	got, err := ReadEngines(context.Background(), c, "inkwall-system", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Engine{}
	for _, e := range got {
		byID[e.ID] = e
	}
	if len(byID) != 2 || byID["e1"].Applied != 3 || byID["e2"].Applied != 2 {
		t.Fatalf("got %+v", got)
	}
}

type fakeAuth struct{ err error }

func (f fakeAuth) Authenticate(_ context.Context, token string) (Identity, error) {
	if f.err != nil {
		return Identity{}, f.err
	}
	return Identity{ServiceAccount: "edge/" + token}, nil
}

// serve runs a Server on an in-memory listener and returns a client.
func serve(t *testing.T, s *Server, opts ...grpc.ServerOption) agentv1.BundleServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer(opts...)
	agentv1.RegisterBundleServiceServer(g, s)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewBundleServiceClient(conn)
}

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func signed(version uint64) *bundlev1.SignedBundle {
	return &bundlev1.SignedBundle{Bundle: []byte{byte(version)}, KeyId: "k"}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWatch(t *testing.T) {
	store, table := NewStore(), NewTable()
	store.Set(signed(1), 1)
	c := serve(t, NewServer(store, table, fakeAuth{}, "replica-0", logr.Discard()))
	ctx, cancel := context.WithCancel(withToken(context.Background(), "engine"))
	defer cancel()

	stream, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{
		EngineId: "e1", PodName: "traefik-1", TrustedKeyIds: []string{"k"},
	}}}); err != nil {
		t.Fatal(err)
	}
	// The current bundle comes first.
	resp, err := stream.Recv()
	if err != nil || resp.GetBundle().GetKeyId() != "k" {
		t.Fatalf("first message: %v, %v", resp, err)
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Ack{Ack: &agentv1.Ack{BundleVersion: 1}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the ack", func() bool {
		got, _ := table.Snapshot()
		return len(got) == 1 && got[0].Applied == 1 && got[0].ServiceAccount == "edge/engine" && got[0].Replica == "replica-0" &&
			slices.Equal(got[0].TrustedKeys, []string{"k"})
	})
	// The engine reloaded its keys: heartbeats report them.
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		BundleVersion: 1, TrustedKeyIds: []string{"k", "k2"},
	}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the new trusted keys", func() bool {
		got, _ := table.Snapshot()
		return len(got) == 1 && slices.Equal(got[0].TrustedKeys, []string{"k", "k2"})
	})

	// A new bundle is pushed; a rejection is recorded.
	store.Set(signed(2), 2)
	if resp, err := stream.Recv(); err != nil || resp.GetBundle() == nil {
		t.Fatalf("pushed bundle: %v, %v", resp, err)
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Nack{Nack: &agentv1.Nack{BundleVersion: 2, Error: "bad"}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the nack", func() bool {
		got, _ := table.Snapshot()
		return len(got) == 1 && got[0].Rejected == 2 && got[0].RejectError == "bad" && got[0].Applied == 1
	})

	// Disconnecting removes the engine.
	cancel()
	waitFor(t, "the disconnect", func() bool { got, _ := table.Snapshot(); return len(got) == 0 })
}

func TestWatchCurrentEngine(t *testing.T) {
	// An engine that already runs the current bundle isn't sent it again.
	store := NewStore()
	store.Set(signed(5), 5)
	c := serve(t, NewServer(store, NewTable(), fakeAuth{}, "r", logr.Discard()))
	ctx, cancel := context.WithTimeout(withToken(context.Background(), "e"), 300*time.Millisecond)
	defer cancel()
	stream, _ := c.Watch(ctx)
	_ = stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e", BundleVersion: 5}}})
	if resp, err := stream.Recv(); err == nil {
		t.Fatalf("got %v, want nothing until the deadline", resp)
	}
}

func TestWatchErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		auth  Authenticator
		hello *agentv1.WatchRequest
		code  codes.Code
	}{
		{"unauthenticated", fakeAuth{err: ErrUnauthenticated}, nil, codes.Unauthenticated},
		{"forbidden", fakeAuth{err: ErrForbidden}, nil, codes.PermissionDenied},
		{"no hello first", fakeAuth{}, &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Ack{Ack: &agentv1.Ack{}}}, codes.InvalidArgument},
		{"hello without id", fakeAuth{}, &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{}}}, codes.InvalidArgument},
		{"id over 253 bytes", fakeAuth{}, &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: strings.Repeat("e", 254)}}}, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, NewServer(NewStore(), NewTable(), tc.auth, "r", logr.Discard()))
			stream, err := c.Watch(withToken(context.Background(), "e"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.hello != nil {
				_ = stream.Send(tc.hello)
			}
			_, err = stream.Recv()
			if status.Code(err) != tc.code {
				t.Fatalf("got %v, want code %s", err, tc.code)
			}
		})
	}
}

func TestWatchIdle(t *testing.T) {
	s := NewServer(NewStore(), NewTable(), fakeAuth{}, "r", logr.Discard())
	s.IdleTimeout = 100 * time.Millisecond
	c := serve(t, s)
	stream, _ := c.Watch(withToken(context.Background(), "e"))
	_ = stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e"}}})
	if _, err := stream.Recv(); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("a silent engine: got %v, want DeadlineExceeded", err)
	}
}

// podAuth binds the token to a pod, as a projected token does.
type podAuth struct{}

func (podAuth) Authenticate(_ context.Context, token string) (Identity, error) {
	return Identity{ServiceAccount: "edge/traefik", PodNamespace: "edge", PodName: token}, nil
}

func TestWatchEvents(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*eventsv1.SecurityEvent
	)
	s := NewServer(NewStore(), NewTable(), podAuth{}, "replica-0", logr.Discard())
	s.Events = func(b *eventsv1.EventBatch) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, b.GetEvents()...)
	}
	c := serve(t, s)
	ctx, cancel := context.WithCancel(withToken(context.Background(), "traefik-1"))
	defer cancel()
	stream, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e1", PodNamespace: "edge", PodName: "traefik-1"}}}); err != nil {
		t.Fatal(err)
	}
	// The engine claims another pod in its events: the stream's identity wins.
	batch := &eventsv1.EventBatch{Dropped: 3, Events: []*eventsv1.SecurityEvent{
		{EventId: "a", EngineId: "forged", PodNamespace: "kube-system", PodName: "other"},
		{EventId: "b"},
	}}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Events{Events: batch}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the events", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	mu.Lock()
	defer mu.Unlock()
	for _, ev := range got {
		if ev.GetEngineId() != "e1" || ev.GetPodNamespace() != "edge" || ev.GetPodName() != "traefik-1" {
			t.Errorf("event %s from %s %s/%s, want e1 edge/traefik-1", ev.GetEventId(), ev.GetEngineId(), ev.GetPodNamespace(), ev.GetPodName())
		}
	}
}

// A batch as engines take from their buffer, 256 events at the contract's
// field limits in one message (as older engines send it),
// arrives whole.
func TestWatchEventsMaximalBatch(t *testing.T) {
	var (
		mu  sync.Mutex
		got int
	)
	s := NewServer(NewStore(), NewTable(), podAuth{}, "replica-0", logr.Discard())
	s.Events = func(b *eventsv1.EventBatch) { mu.Lock(); defer mu.Unlock(); got += len(b.GetEvents()) }
	c := serve(t, s, grpc.MaxRecvMsgSize(maxEngineMessage))
	ctx, cancel := context.WithCancel(withToken(context.Background(), "traefik-1"))
	defer cancel()
	stream, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e1"}}}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 4096)
	src := events.Source{EngineID: strings.Repeat("e", 253), PodNamespace: strings.Repeat("n", 63), PodName: strings.Repeat("p", 253)}
	v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, Policy: long}
	for i := range 64 {
		v.Matches = append(v.Matches, rules.Match{RuleID: 900000 + i, Variable: "ARGS:" + long, Value: long})
	}
	req := &request.Request{ID: long, Method: long, Host: long, Headers: http.Header{"User-Agent": {long}}}
	batch := &eventsv1.EventBatch{}
	for range 256 {
		batch.Events = append(batch.Events, events.New(src, req, "/"+long, v, time.Now()))
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Events{Events: batch}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the batch", func() bool { mu.Lock(); defer mu.Unlock(); return got == 256 })
}

// A batch over the contract's MaxBatch keeps its first MaxBatch events;
// the rest count as dropped by the engine.
func TestWatchEventsOverMaxBatch(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*eventsv1.EventBatch
	)
	s := NewServer(NewStore(), NewTable(), podAuth{}, "replica-0", logr.Discard())
	s.Events = func(b *eventsv1.EventBatch) { mu.Lock(); defer mu.Unlock(); got = append(got, b) }
	c := serve(t, s)
	ctx, cancel := context.WithCancel(withToken(context.Background(), "traefik-1"))
	defer cancel()
	stream, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The longest engine ID, a pod name's, is accepted.
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: strings.Repeat("e", 253)}}}); err != nil {
		t.Fatal(err)
	}
	dropped := testutil.ToFloat64(eventsDroppedByEngines)
	batch := &eventsv1.EventBatch{Dropped: 3}
	for i := range events.MaxBatch + 5 {
		batch.Events = append(batch.Events, &eventsv1.SecurityEvent{EventId: strconv.Itoa(i)})
	}
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Events{Events: batch}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the batch", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 })
	mu.Lock()
	defer mu.Unlock()
	b := got[0]
	if n := len(b.GetEvents()); n != events.MaxBatch || b.GetEvents()[n-1].GetEventId() != strconv.Itoa(events.MaxBatch-1) {
		t.Errorf("got %d events, want the first %d", n, events.MaxBatch)
	}
	if b.GetDropped() != 8 {
		t.Errorf("dropped %d, want 8 (3 + 5 over the limit)", b.GetDropped())
	}
	if d := testutil.ToFloat64(eventsDroppedByEngines) - dropped; d != 8 {
		t.Errorf("the engine-drop metric grew by %v, want 8", d)
	}
}

func TestWatchWaitingForASendSlot(t *testing.T) {
	// Every send slot is taken for longer than the idle timeout (#148).
	store, table := NewStore(), NewTable()
	store.Set(signed(1), 1)
	s := NewServer(store, table, fakeAuth{}, "r", logr.Discard())
	s.IdleTimeout = 200 * time.Millisecond
	s.sends = make(chan struct{}, 1)
	s.sends <- struct{}{}
	c := serve(t, s)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hello := func(id string) agentv1.BundleService_WatchClient {
		stream, err := c.Watch(withToken(ctx, id))
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: id}}}); err != nil {
			t.Fatal(err)
		}
		return stream
	}
	alive, silent := hello("alive"), hello("silent")

	// An engine that heartbeats keeps its stream, and its heartbeats are
	// recorded while it waits.
	for i := range 10 {
		hb := &agentv1.Heartbeat{TrustedKeyIds: []string{"k", strconv.Itoa(i)}}
		if err := alive.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: hb}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A silent engine is still cut off, slot or not.
	if _, err := silent.Recv(); !strings.Contains(status.Convert(err).Message(), "no message from the engine") {
		t.Fatalf("a silent engine waiting for a slot: got %v, want the idle timeout", err)
	}
	waitFor(t, "the heartbeats", func() bool {
		got, _ := table.Snapshot()
		return len(got) == 1 && got[0].ID == "alive" && slices.Equal(got[0].TrustedKeys, []string{"k", "9"})
	})
	<-s.sends
	if resp, err := alive.Recv(); err != nil || resp.GetBundle() == nil {
		t.Fatalf("an engine that waited for a slot: got %v, %v, want the bundle", resp, err)
	}
}

// Request counts: the server passes on the differences between an
// engine's reports, for the bundle's policies only. A restarted engine
// opens a new stream that counts from zero again.
func TestWatchStats(t *testing.T) {
	store, table := NewStore(), NewTable()
	store.Set(signed(1), 1)
	store.SetPolicies(map[string]bool{"shop/site": true})
	var mu sync.Mutex
	var got []*eventsv1.PolicyStats
	s := NewServer(store, table, fakeAuth{}, "replica-0", logr.Discard())
	s.Stats = func(d []*eventsv1.PolicyStats) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, d...)
	}
	c := serve(t, s)
	total := func() (allowed, denied, timed uint64) {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range got {
			allowed, denied = allowed+p.GetAllowed(), denied+p.GetDenied()
			for _, n := range p.GetLatencyCounts() {
				timed += n
			}
		}
		return allowed, denied, timed
	}
	report := func(stream agentv1.BundleService_WatchClient, bounds []float64, policies ...*eventsv1.PolicyStats) {
		t.Helper()
		if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Stats{Stats: &eventsv1.RequestStats{
			LatencyBounds: bounds, Policies: policies,
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	site := func(allowed, denied uint64) *eventsv1.PolicyStats {
		counts := make([]uint64, len(latencyBounds)+1)
		counts[0] = allowed + denied
		return &eventsv1.PolicyStats{Policy: "shop/site", Allowed: allowed, Denied: denied, LatencyCounts: counts}
	}
	open := func() agentv1.BundleService_WatchClient {
		t.Helper()
		stream, err := c.Watch(withToken(t.Context(), "engine"))
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e1"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		return stream
	}

	dropped := func(reason string) float64 { return testutil.ToFloat64(RequestStatsDropped.WithLabelValues(reason)) }
	notInBundle, buckets := dropped(DroppedNotInBundle), dropped(DroppedLatencyBuckets)

	stream := open()
	report(stream, latencyBounds, site(3, 1), &eventsv1.PolicyStats{Policy: "gone/policy", Allowed: 100})
	report(stream, latencyBounds, site(5, 2))
	waitFor(t, "the differences", func() bool { a, d, n := total(); return a == 5 && d == 2 && n == 7 })

	// The engine restarts: its new stream counts from zero.
	_ = stream.CloseSend()
	stream = open()
	report(stream, latencyBounds, site(1, 0))
	waitFor(t, "the restarted engine's counts", func() bool { a, d, n := total(); return a == 6 && d == 2 && n == 8 })

	// Latency in other buckets is left out; the counts are taken.
	report(stream, []float64{1, 2}, site(2, 0))
	waitFor(t, "the counts without latency", func() bool { a, _, n := total(); return a == 7 && n == 8 })
	if d := dropped(DroppedNotInBundle) - notInBundle; d != 1 {
		t.Errorf("dropped as not in the bundle: %v, want 1", d)
	}
	if d := dropped(DroppedLatencyBuckets) - buckets; d != 1 {
		t.Errorf("dropped for other latency buckets: %v, want 1", d)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range got {
		if p.GetPolicy() != "shop/site" {
			t.Errorf("counts of %s, which the bundle doesn't have", p.GetPolicy())
		}
	}
}
