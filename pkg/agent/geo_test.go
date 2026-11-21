// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/geo"
)

// countryTable is a gzipped table mapping all of IPv4 to code.
type countryTable struct {
	gz   []byte
	hash [32]byte
	size uint64
}

func newTable(t *testing.T, code string) countryTable {
	t.Helper()
	gz, size, err := geo.Encode(&geov1.CountryTable{
		V4Starts: []uint32{0}, V4Codes: []byte(code),
		V6Starts: make([]byte, 16), V6Codes: []byte{0, 0},
		DatabaseType: "Test-Country", DatabaseBuildEpoch: 1_700_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return countryTable{gz: gz, hash: geo.Hash(gz), size: uint64(size)}
}

func (c countryTable) msg() *agentv1.WatchResponse {
	return &agentv1.WatchResponse{Msg: &agentv1.WatchResponse_GeoTable{GeoTable: &agentv1.CountryTableMessage{Sha256: c.hash[:], Table: c.gz}}}
}

// geoBundle is bundle() naming table (none if nil).
func geoBundle(t *testing.T, key ed25519.PrivateKey, version uint64, table *countryTable) *bundlev1.SignedBundle {
	t.Helper()
	var b bundlev1.Bundle
	if err := proto.Unmarshal(bundle(t, key, version, time.Now(), blockAttack).GetBundle(), &b); err != nil {
		t.Fatal(err)
	}
	b.CreatedAt = timestamppb.Now()
	b.ContentHash = []byte{byte(version)}
	if table != nil {
		b.GeoTable = &bundlev1.GeoTableRef{Sha256: table.hash[:], Size: table.size}
	}
	raw, _ := proto.Marshal(&b)
	return &bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(key, raw), KeyId: bundlekey.ID(key.Public().(ed25519.PublicKey))}
}

func enforced(t *testing.T, a *Agent) (string, bool) {
	t.Helper()
	tb, named := a.cfg.Holder.Load().GeoTable()
	if tb == nil {
		return "", named
	}
	h := tb.Hash()
	return string(h[:]), named
}

func ready(a *Agent) bool {
	select {
	case <-a.GeoReady():
		return true
	default:
		return false
	}
}

func mustApply(t *testing.T, a *Agent, signed *bundlev1.SignedBundle) {
	t.Helper()
	if _, err := a.apply(signed, true); err != nil {
		t.Fatal(err)
	}
}

// TestGeoTableBeforeBundle: on the stream, the table comes first and is
// held until the bundle that names it, then both are applied at once.
func TestGeoTableBeforeBundle(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, func(c *Config) { c.GeoCacheFile = filepath.Join(e.dir, "geo.table") })
	run(t, a)
	<-e.op.sawHello
	_, _, hellos, _, _ := e.op.snapshot()
	if !slices.Contains(hellos[0].GetCapabilities(), CapabilityGeoTable) || len(hellos[0].GetGeoTableSha256()) != 0 {
		t.Fatalf("hello: %v", hellos[0])
	}
	de := newTable(t, "DE")
	e.op.msgs <- de.msg()
	e.op.bundles <- geoBundle(t, e.priv, 1, &de)
	waitFor(t, "the ack", func() bool { acks, _, _, _, _ := e.op.snapshot(); return len(acks) == 1 })
	if h, named := enforced(t, a); h != string(de.hash[:]) || !named || !ready(a) {
		t.Fatalf("enforced %x named %v ready %v", h, named, ready(a))
	}
	waitFor(t, "the heartbeat's hash", func() bool {
		e.op.mu.Lock()
		defer e.op.mu.Unlock()
		return bytes.Equal(e.op.beatGeo, de.hash[:])
	})
	if b, err := os.ReadFile(filepath.Join(e.dir, "geo.table")); err != nil || !bytes.Equal(b, de.gz) {
		t.Errorf("cache: %v", err)
	}
}

// TestGeoTableAfterBundle: a bundle naming a table not held yet runs
// without one (or with the previous one), and the table, when it comes,
// makes a new set sharing the compiled policies.
func TestGeoTableAfterBundle(t *testing.T) {
	e := newEnv(t)
	a, _, compiles := e.agent(t, nil)
	de, fr := newTable(t, "DE"), newTable(t, "FR")
	mustApply(t, a, geoBundle(t, e.priv, 1, &de))
	if h, named := enforced(t, a); h != "" || !named || ready(a) {
		t.Fatalf("before the table: %x named %v ready %v", h, named, ready(a))
	}
	a.offerTable(de.hash[:], de.gz)
	if h, _ := enforced(t, a); h != string(de.hash[:]) || !ready(a) || compiles.n.Load() != 1 {
		t.Fatalf("after the table: %x ready %v, %d compiles", h, ready(a), compiles.n.Load())
	}
	if !bytes.Equal(a.GeoTableHash(), de.hash[:]) {
		t.Error("the held hash isn't reported")
	}
	// A new database: the previous table is kept until the new one comes.
	mustApply(t, a, geoBundle(t, e.priv, 2, &fr))
	if h, _ := enforced(t, a); h != string(de.hash[:]) {
		t.Fatal("the previous table isn't kept")
	}
	a.offerTable(fr.hash[:], fr.gz)
	if h, _ := enforced(t, a); h != string(fr.hash[:]) {
		t.Fatal("the new table isn't enforced")
	}
	// A bundle without geo drops the table.
	mustApply(t, a, geoBundle(t, e.priv, 3, nil))
	if h, named := enforced(t, a); h != "" || named || a.GeoTableHash() != nil {
		t.Error("a bundle without geo kept the table")
	}
}

func TestGeoTableRefusals(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, nil)
	de, fr := newTable(t, "DE"), newTable(t, "FR")
	mustApply(t, a, geoBundle(t, e.priv, 1, &de))
	a.offerTable(de.hash[:], de.gz)
	mustApply(t, a, geoBundle(t, e.priv, 2, &fr))
	// The bytes of another table under the named hash: refused, the
	// previous table kept and reported.
	a.offerTable(fr.hash[:], de.gz)
	if h, _ := enforced(t, a); h != string(de.hash[:]) || !bytes.Equal(a.GeoTableHash(), de.hash[:]) {
		t.Error("a table with the wrong hash replaced the previous one")
	}
	// Over the bound: refused before anything.
	a.offerTable(fr.hash[:], make([]byte, geo.MaxCompressedBytes+1))
	a.offerTable([]byte("short"), fr.gz)
	if n := testutil.ToFloat64(a.geo.failures); n != 3 {
		t.Errorf("%v failures counted, want 3", n)
	}
}

// TestGeoPending: one pending table at a time, a newer one replacing it,
// and one the next bundle doesn't name is dropped.
func TestGeoPending(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, nil)
	de, fr := newTable(t, "DE"), newTable(t, "FR")
	a.offerTable(de.hash[:], de.gz)
	a.offerTable(fr.hash[:], fr.gz)
	mustApply(t, a, geoBundle(t, e.priv, 1, &de))
	if h, _ := enforced(t, a); h != "" {
		t.Fatal("a replaced pending table was used")
	}
	a.offerTable(fr.hash[:], fr.gz)
	mustApply(t, a, geoBundle(t, e.priv, 2, &de))
	a.mu.Lock()
	p := a.pending
	a.mu.Unlock()
	if p != nil {
		t.Error("a pending table the bundle doesn't name is kept")
	}
}

// TestGeoCache: a restarted engine enforces the cached table with the
// cached bundle, at once.
func TestGeoCache(t *testing.T) {
	e := newEnv(t)
	cache := func(c *Config) { c.GeoCacheFile = filepath.Join(e.dir, "geo.table"); c.Addr = "127.0.0.1:1" }
	a, _, _ := e.agent(t, cache)
	de := newTable(t, "DE")
	mustApply(t, a, geoBundle(t, e.priv, 1, &de))
	a.offerTable(de.hash[:], de.gz)

	b, _, _ := e.agent(t, cache)
	if !b.LoadCache() {
		t.Fatal("no cached bundle")
	}
	if h, _ := enforced(t, b); h != string(de.hash[:]) || !ready(b) {
		t.Fatalf("cached table not enforced: %x", h)
	}
	// Without its table, a cached bundle that names one isn't ready.
	if err := os.Remove(filepath.Join(e.dir, "geo.table")); err != nil {
		t.Fatal(err)
	}
	c, _, _ := e.agent(t, cache)
	c.LoadCache()
	if h, named := enforced(t, c); h != "" || !named || ready(c) {
		t.Errorf("without the table: %x named %v ready %v", h, named, ready(c))
	}
}

func TestGeoReadyWithoutGeo(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, nil)
	mustApply(t, a, geoBundle(t, e.priv, 1, nil))
	if !ready(a) {
		t.Error("a bundle without geo isn't ready")
	}
}
