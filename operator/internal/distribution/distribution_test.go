// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
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
func serve(t *testing.T, s *Server) agentv1.BundleServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
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
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{EngineId: "e1", PodName: "traefik-1"}}}); err != nil {
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
		return len(got) == 1 && got[0].Applied == 1 && got[0].ServiceAccount == "edge/engine" && got[0].Replica == "replica-0"
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
