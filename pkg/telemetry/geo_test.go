// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func TestGeoMetrics(t *testing.T) {
	m := NewMetrics("test")
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonGeoDeny, GeoMatch: true, Country: "RU"})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionLog, Reason: pipeline.ReasonGeoDeny, GeoMatch: true, Country: "unknown"})
	// Detect geo, a rule decided: counted as log.
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionDeny, Reason: pipeline.ReasonRule, GeoMatch: true, Country: "RU"})
	m.ObserveVerdict(pipeline.Verdict{Action: pipeline.ActionAllow})
	for _, c := range []struct {
		action, country string
		want            float64
	}{{"deny", "RU", 1}, {"log", "unknown", 1}, {"log", "RU", 1}} {
		if got := testutil.ToFloat64(m.geoDenied.WithLabelValues(c.action, c.country)); got != c.want {
			t.Errorf("%s %s: %v", c.action, c.country, got)
		}
	}
	m.ObserveGeoLookup(geo.ResultPrivate)
	m.ObserveGeoLookup(geo.ResultPrivate)
	m.ObserveGeoLookup(geo.ResultNoTable)
	if testutil.ToFloat64(m.geoLookups.WithLabelValues("private")) != 2 || testutil.ToFloat64(m.geoLookups.WithLabelValues("no-table")) != 1 {
		t.Error("lookups")
	}
	var none *Metrics
	none.ObserveGeoLookup(geo.ResultCountry)
}
