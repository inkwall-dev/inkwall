// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"testing"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// geoTable maps 198.51.100.0/24 to RU and every other IPv4 address to DE.
func geoTable(t *testing.T) *geo.Table {
	t.Helper()
	start := func(s string) uint32 { return binary.BigEndian.Uint32(netip.MustParseAddr(s).AsSlice()) }
	tb, err := geo.FromProto(&geov1.CountryTable{
		V4Starts: []uint32{0, start("198.51.100.0"), start("198.51.101.0")},
		V4Codes:  []byte("DERUDE"),
		V6Starts: make([]byte, 16), V6Codes: []byte{0, 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

type lookups struct {
	mu sync.Mutex
	n  map[geo.Result]int
}

func (l *lookups) ObserveVerdict(pipeline.Verdict) {}

func (l *lookups) ObserveGeoLookup(r geo.Result) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n[r]++
}

func (l *lookups) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.n {
		n += c
	}
	return n
}

func TestGeo(t *testing.T) {
	b := testBundle()
	// Each policy applies its own geo: a deny list, an allow list.
	b.Policies[0].Geo = &bundlev1.Geo{Deny: []string{"RU"}}
	b.Policies[1].Geo = &bundlev1.Geo{Allow: []string{"DE"}}
	obs := &lookups{n: map[geo.Result]int{}}
	compiled, err := Compile(b, Options{Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	set := compiled.WithGeo(true, geoTable(t))
	from := func(host, uri, ip string) *request.Request {
		r := req(host, uri)
		r.ClientIP = netip.MustParseAddr(ip)
		return r
	}
	ctx := context.Background()
	for _, tc := range []struct {
		r      *request.Request
		action pipeline.Action
		reason pipeline.Reason
	}{
		{from("shop.example.com", "/", "198.51.100.7"), pipeline.ActionDeny, pipeline.ReasonGeoDeny},
		{from("shop.example.com", "/", "192.0.2.7"), pipeline.ActionAllow, pipeline.ReasonNone},
		// shop/api is in Detect: its allow list logs.
		{from("shop.example.com", "/api/x", "198.51.100.7"), pipeline.ActionLog, pipeline.ReasonGeoDeny},
		// No geo on admin: no lookup.
		{from("admin.example.com", "/", "198.51.100.7"), pipeline.ActionAllow, pipeline.ReasonNone},
	} {
		before := obs.total()
		// As adapters do: BodyLimit, then Check, on the same request.
		set.BodyLimit(tc.r, 1<<20)
		v := set.Check(ctx, tc.r)
		if v.Action != tc.action || v.Reason != tc.reason {
			t.Errorf("%s%s from %s: %s/%s, want %s/%s", tc.r.Host, tc.r.RawURI, tc.r.ClientIP, v.Action, v.Reason, tc.action, tc.reason)
		}
		want := 1
		if tc.r.Host == "admin.example.com" {
			want = 0
		}
		if got := obs.total() - before; got != want {
			t.Errorf("%s%s: %d lookups, want %d", tc.r.Host, tc.r.RawURI, got, want)
		}
	}

	// No table named: geo skipped, no lookup.
	before := obs.total()
	if v := compiled.WithGeo(false, nil).Check(ctx, from("shop.example.com", "/", "198.51.100.7")); v.Reason != pipeline.ReasonNone {
		t.Errorf("no table named: %s", v.Reason)
	}
	if obs.total() != before {
		t.Error("looked up without a table named")
	}
	// A named table the engine doesn't hold: the Block policy fails closed.
	if v := compiled.WithGeo(true, nil).Check(ctx, from("shop.example.com", "/", "192.0.2.7")); v.Reason != pipeline.ReasonGeoUnavailable || v.Status != 503 {
		t.Errorf("table missing: %s %d", v.Reason, v.Status)
	}
	if tb, named := set.GeoTable(); tb == nil || !named {
		t.Error("GeoTable")
	}
	h := &Holder{}
	h.Store(set)
	if h.GeoTable() == nil {
		t.Error("Holder.GeoTable")
	}
}

func TestGeoCompileErrors(t *testing.T) {
	for name, g := range map[string]*bundlev1.Geo{
		"both":    {Deny: []string{"RU"}, Allow: []string{"DE"}},
		"neither": {},
		"bad":     {Deny: []string{"ru"}},
	} {
		b := testBundle()
		b.Policies[0].Geo = g
		if _, err := Compile(b, Options{}); err == nil || !strings.Contains(err.Error(), "shop/site") {
			t.Errorf("%s: %v, want an error naming the policy", name, err)
		}
	}
}
