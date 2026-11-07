// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/inkwall-dev/inkwall/operator/bundle"
)

// The signing key's age and the rotation's phase are gauges, and failed
// publishes are counted by reason (#378).
func TestKeyMetrics(t *testing.T) {
	now := time.Now()
	k, err := bundle.NewKeyring(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	observeKeys(k)
	if age := testutil.ToFloat64(signingKeyAge); age < 3600 || age > 3700 {
		t.Errorf("key age %v s, want about 3600", age)
	}
	phase := func(p string) float64 { return testutil.ToFloat64(rotationPhase.WithLabelValues(p)) }
	if phase("Idle") != 1 || phase("Publishing") != 0 || phase("Retiring") != 0 {
		t.Errorf("phases idle %v publishing %v retiring %v, want 1 0 0", phase("Idle"), phase("Publishing"), phase("Retiring"))
	}
	k.Next, _ = bundle.GenerateSigner()
	observeKeys(k)
	if phase("Idle") != 0 || phase("Publishing") != 1 {
		t.Errorf("publishing: idle %v publishing %v, want 0 1", phase("Idle"), phase("Publishing"))
	}

	before := testutil.ToFloat64(publishFailures.WithLabelValues("too_large"))
	publishFailed(fmt.Errorf("x: %w", bundle.ErrTooLarge))
	publishFailed(errors.New("conflict"))
	if got := testutil.ToFloat64(publishFailures.WithLabelValues("too_large")); got != before+1 {
		t.Errorf("too_large failures %v, want %v", got, before+1)
	}
	if got := testutil.ToFloat64(publishFailures.WithLabelValues("error")); got < 1 {
		t.Errorf("error failures %v, want at least 1", got)
	}
}
