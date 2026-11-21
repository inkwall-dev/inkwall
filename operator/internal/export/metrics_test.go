// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A new sink's series start at 0, so rates are 0 rather than absent; a
// removed sink's go.
func TestPrometheusMetrics(t *testing.T) {
	var m PrometheusMetrics
	m.Start("metrics-test")
	if got := testutil.ToFloat64(exportDropped.WithLabelValues("metrics-test", DropBufferFull)); got != 0 {
		t.Errorf("buffer_full starts at %v", got)
	}
	m.Exported("metrics-test", 3)
	m.Dropped("metrics-test", DropRejected, 2)
	m.Failed("metrics-test", kindAuth)
	m.Succeeded("metrics-test", time.Unix(1_800_000_000, 0))
	m.Pending("metrics-test", 7)
	m.Duration("metrics-test", 20*time.Millisecond)
	if testutil.ToFloat64(exportedTotal.WithLabelValues("metrics-test")) != 3 ||
		testutil.ToFloat64(exportDropped.WithLabelValues("metrics-test", DropRejected)) != 2 ||
		testutil.ToFloat64(exportFailures.WithLabelValues("metrics-test", kindAuth)) != 1 ||
		testutil.ToFloat64(exportLastSuccess.WithLabelValues("metrics-test")) != 1_800_000_000 ||
		testutil.ToFloat64(exportPending.WithLabelValues("metrics-test")) != 7 {
		t.Error("a metric didn't count")
	}
	m.Forget("metrics-test")
	for name, n := range map[string]int{
		"exported": testutil.CollectAndCount(exportedTotal), "dropped": testutil.CollectAndCount(exportDropped),
		"failures": testutil.CollectAndCount(exportFailures), "pending": testutil.CollectAndCount(exportPending),
	} {
		if n != 0 {
			t.Errorf("%s: %d series after Forget", name, n)
		}
	}
}
