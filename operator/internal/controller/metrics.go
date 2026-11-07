// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/inkwall-dev/inkwall/operator/bundle"
)

// activeSince is when the active signing key began to sign, in Unix
// nanoseconds; 0 before the leader reads the keys.
var activeSince atomic.Int64

var (
	signingKeyAge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "inkwall_operator_signing_key_age_seconds",
		Help: "Time since the active bundle signing key began to sign. Reported by the leader.",
	}, func() float64 {
		since := activeSince.Load()
		if since == 0 {
			return 0
		}
		return time.Since(time.Unix(0, since)).Seconds()
	})
	rotationPhase = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_signing_key_rotation_phase",
		Help: "1 for the phase the signing key rotation is in (Idle, Publishing, Retiring), 0 for the others. Reported by the leader.",
	}, []string{"phase"})
	publishFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_operator_bundle_publish_failures_total",
		Help: "Bundles the leader failed to publish, by reason: too_large (over the size limit: policy changes aren't published until it fits), error (the API server refused or failed; retried).",
	}, []string{"reason"})
)

func init() {
	metrics.Registry.MustRegister(signingKeyAge, rotationPhase, publishFailures)
}

// observeKeys reports the keyring's age and phase.
func observeKeys(k *bundle.Keyring) {
	if !k.ActiveSince.IsZero() {
		activeSince.Store(k.ActiveSince.UnixNano())
	}
	current := string(k.Phase())
	if current == "" {
		current = "Idle"
	}
	for _, p := range []string{"Idle", string(bundle.PhasePublishing), string(bundle.PhaseRetiring)} {
		v := 0.0
		if p == current {
			v = 1
		}
		rotationPhase.WithLabelValues(p).Set(v)
	}
}

// publishFailed counts a failed publish.
func publishFailed(err error) {
	reason := "error"
	if errors.Is(err, bundle.ErrTooLarge) {
		reason = "too_large"
	}
	publishFailures.WithLabelValues(reason).Inc()
}
