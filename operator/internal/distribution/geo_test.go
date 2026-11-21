// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	operatorgeo "github.com/inkwall-dev/inkwall/operator/internal/geo"
	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
)

func fakeTable(name string) (hash, gz []byte) {
	gz = []byte("gzipped table " + name)
	h := sha256.Sum256(gz)
	return h[:], gz
}

func geoHello(id string, held []byte, capable bool) *agentv1.Hello {
	h := &agentv1.Hello{EngineId: id, GeoTableSha256: held}
	if capable {
		h.Capabilities = []string{CapabilityGeoTable, "something-else"}
	}
	return h
}

// open connects an engine to s and returns its stream.
func open(t *testing.T, c agentv1.BundleServiceClient, h *agentv1.Hello) agentv1.BundleService_WatchClient {
	t.Helper()
	stream, err := c.Watch(withToken(t.Context(), h.GetEngineId()))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(hello(h)); err != nil {
		t.Fatal(err)
	}
	return stream
}

// next returns what the stream receives next: "table:<hash>" or
// "bundle:<first byte>".
func next(t *testing.T, stream agentv1.BundleService_WatchClient) string {
	t.Helper()
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if g := resp.GetGeoTable(); g != nil {
		if !bytes.Equal(g.GetSha256(), hashOf(g.GetTable())) {
			t.Fatal("a table message whose hash isn't its table's")
		}
		return "table:" + hex.EncodeToString(g.GetSha256())[:8]
	}
	return "bundle:" + string('0'+rune(resp.GetBundle().GetBundle()[0]))
}

func tag(h []byte) string { return "table:" + hex.EncodeToString(h)[:8] }

// TestWatchGeoTable: the table goes before the bundle that names it, to
// engines that take tables and don't hold it; never to older engines.
func TestWatchGeoTable(t *testing.T) {
	store := NewStore()
	h1, gz1 := fakeTable("one")
	store.AddGeoTable(h1, gz1)
	store.SetWithGeo(signed(1), 1, h1)
	c := serve(t, NewServer(store, NewTable(), fakeAuth{}, "r", logr.Discard()))

	capable := open(t, c, geoHello("new", nil, true))
	if got := []string{next(t, capable), next(t, capable)}; !slices.Equal(got, []string{tag(h1), "bundle:1"}) {
		t.Fatalf("a new engine got %v", got)
	}
	holding := open(t, c, geoHello("holding", h1, true))
	if got := next(t, holding); got != "bundle:1" {
		t.Fatalf("an engine holding the table got %s first", got)
	}
	old := open(t, c, geoHello("old", nil, false))
	if got := next(t, old); got != "bundle:1" {
		t.Fatalf("an engine before 0.7.0 got %s first", got)
	}

	// A new database: the table, then the bundle, to each capable engine.
	h2, gz2 := fakeTable("two")
	store.AddGeoTable(h2, gz2)
	store.SetWithGeo(signed(2), 2, h2)
	for name, s := range map[string]agentv1.BundleService_WatchClient{"new": capable, "holding": holding} {
		if got := []string{next(t, s), next(t, s)}; !slices.Equal(got, []string{tag(h2), "bundle:2"}) {
			t.Errorf("%s: got %v", name, got)
		}
	}
	if got := next(t, old); got != "bundle:2" {
		t.Errorf("old: got %s", got)
	}
	// The Store keeps two tables.
	h3, gz3 := fakeTable("three")
	store.AddGeoTable(h3, gz3)
	if store.HasGeoTable(h1) || !store.HasGeoTable(h2) || !store.HasGeoTable(h3) {
		t.Error("the Store doesn't keep the newest two tables")
	}
}

// TestWatchGeoTableWaits: a bundle whose table the Store doesn't hold yet
// isn't sent before it.
func TestWatchGeoTableWaits(t *testing.T) {
	store := NewStore()
	h, gz := fakeTable("late")
	store.SetWithGeo(signed(1), 1, h)
	c := serve(t, NewServer(store, NewTable(), fakeAuth{}, "r", logr.Discard()))
	s := open(t, c, geoHello("e", nil, true))
	time.Sleep(100 * time.Millisecond)
	store.AddGeoTable(h, gz)
	if got := []string{next(t, s), next(t, s)}; !slices.Equal(got, []string{tag(h), "bundle:1"}) {
		t.Fatalf("got %v", got)
	}
}

// TestWatchGeoTableRetry: an engine that still reports another table is
// sent it again, with backoff.
func TestWatchGeoTableRetry(t *testing.T) {
	store := NewStore()
	h, gz := fakeTable("t")
	store.AddGeoTable(h, gz)
	store.SetWithGeo(signed(1), 1, h)
	table := NewTable()
	srv := NewServer(store, table, fakeAuth{}, "r", logr.Discard())
	srv.GeoRetry, srv.GeoRetryMax = 50*time.Millisecond, 100*time.Millisecond
	c := serve(t, srv)
	s := open(t, c, geoHello("e", nil, true))
	if got := []string{next(t, s), next(t, s), next(t, s)}; !slices.Equal(got, []string{tag(h), "bundle:1", tag(h)}) {
		t.Fatalf("got %v", got)
	}
	// Once the engine reports it, it isn't sent again, and the record has
	// it.
	if err := s.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{BundleVersion: 1, GeoTableSha256: h}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the table in the record", func() bool {
		got, _ := table.Snapshot()
		return len(got) == 1 && got[0].GeoTable == hex.EncodeToString(h)
	})
	done := make(chan string, 1)
	go func() {
		resp, err := s.Recv()
		if err == nil {
			done <- resp.String()
		}
	}()
	select {
	case m := <-done:
		// One resend may have been in flight before the heartbeat.
		if !strings.Contains(m, "geo_table") {
			t.Fatalf("got %s", m)
		}
		select {
		case m := <-done:
			t.Fatalf("sent again: %s", m)
		case <-time.After(300 * time.Millisecond):
		}
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWatchGeoLimits(t *testing.T) {
	for name, h := range map[string]*agentv1.Hello{
		"short hash":        {EngineId: "e", GeoTableSha256: []byte{1}},
		"many capabilities": {EngineId: "e", Capabilities: slices.Repeat([]string{"c"}, maxCapabilities+1)},
		"long capability":   {EngineId: "e", Capabilities: []string{strings.Repeat("c", maxCapability+1)}},
		"empty capability":  {EngineId: "e", Capabilities: []string{""}},
	} {
		c := serve(t, NewServer(NewStore(), NewTable(), fakeAuth{}, "r", logr.Discard()))
		s := open(t, c, h)
		if _, err := s.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	_, stream := connect(t, fakeAuth{}, "e", &agentv1.Hello{EngineId: "e"})
	if err := stream.Send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{GeoTableSha256: make([]byte, 33)}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("heartbeat: %v, want InvalidArgument", err)
	}
}

// TestBundleSourceGeo: a replica serves a bundle naming a table only once
// it holds the table, from the geo Secrets.
func TestBundleSourceGeo(t *testing.T) {
	ctx := context.Background()
	const ns = "inkwall-system"
	c := fake.NewClientBuilder().Build()
	db, err := mmdbtest.DB{Networks: []mmdbtest.Network{{Prefix: netip.MustParsePrefix("1.0.0.0/8"), Record: &mmdbtest.Record{Country: "AU"}}}}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tb, err := operatorgeo.Compile(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := bundle.NewSigner(priv)
	b := &bundlev1.Bundle{Version: 1, GeoTable: &bundlev1.GeoTableRef{Sha256: tb.Hash[:], Size: uint64(tb.Size)}}
	sb, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Store(ctx, c, c, ns, b, sb, pub); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	src := &BundleSource{Client: c, Namespace: ns, Store: store}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: bundle.BundleSecret}}
	res, err := src.Reconcile(ctx, req)
	if err != nil || res.RequeueAfter == 0 {
		t.Fatalf("without the table: %v, %+v", err, res)
	}
	if s, _, _ := store.Current(); s != nil {
		t.Fatal("the bundle is served before its table")
	}
	if err := operatorgeo.Store(ctx, c, c, ns, tb); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	s, v, _ := store.Current()
	if s == nil || v != 1 || !proto.Equal(s, sb) {
		t.Fatal("the bundle isn't served")
	}
	m := store.GeoTable(tb.Hash[:])
	if m == nil || !bytes.Equal(m.GetGeoTable().GetTable(), tb.Compressed) {
		t.Fatal("the table isn't served")
	}
}
