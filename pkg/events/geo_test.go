// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net/http"
	"net/netip"
	"testing"
	"time"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// TestEventCountry: every event carries the client's country when the
// engine holds a table: the geo policy's lookup, or one made for the event.
func TestEventCountry(t *testing.T) {
	tb, err := geo.FromProto(&geov1.CountryTable{
		V4Starts: []uint32{0, 0x08000000, 0x09000000}, V4Codes: []byte("\x00\x00US\x00\x00"),
		V6Starts: make([]byte, 16), V6Codes: []byte{0, 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	ru, _ := geo.ParseCountry("RU")
	withTable := Source{GeoTable: func() *geo.Table { return tb }}
	for _, tc := range []struct {
		name string
		src  Source
		geo  request.Geo
		ip   string
		want string
	}{
		{"looked up by the policy", Source{}, request.Geo{Looked: true, Country: ru, Result: geo.ResultCountry}, "198.51.100.1", "RU"},
		{"looked up for the event", withTable, request.Geo{}, "8.8.8.8", "US"},
		{"unknown", withTable, request.Geo{}, "7.7.7.7", "unknown"},
		{"private", withTable, request.Geo{}, "10.0.0.1", ""},
		{"no table", Source{GeoTable: func() *geo.Table { return nil }}, request.Geo{}, "8.8.8.8", ""},
	} {
		r := &request.Request{Method: "GET", Host: "h", RawURI: "/", Headers: http.Header{}, ClientIP: netip.MustParseAddr(tc.ip), Geo: tc.geo}
		ev := New(tc.src, r, "/", pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule}, time.Now())
		if ev.GetCountry() != tc.want {
			t.Errorf("%s: country %q, want %q", tc.name, ev.GetCountry(), tc.want)
		}
	}
	ev := New(Source{}, &request.Request{Headers: http.Header{}}, "/", pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonGeoDeny, SampledCount: 7}, time.Now())
	if ev.GetReason() != enginev1.Reason_REASON_GEO_DENY || ev.GetSampledCount() != 7 {
		t.Errorf("geo-deny event: %s %d", ev.GetReason(), ev.GetSampledCount())
	}
	if Reason(pipeline.ReasonGeoUnavailable) != enginev1.Reason_REASON_GEO_UNAVAILABLE {
		t.Error("geo-unavailable")
	}
}
