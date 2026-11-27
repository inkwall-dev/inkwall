// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"errors"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
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
		Help: "Bundles the leader failed to publish, by reason: too_large (over the size limit with every change: changes are held back, namespace by namespace, until it fits), error (the API server refused or failed; retried).",
	}, []string{"reason"})
	bundleHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_held_policies",
		Help: "Policies and rule sets the published bundle holds back at their previous version, or leaves out (new, or not compiling with a rule set held), because their namespace would be over its share of the bundle (spec.bundle.namespaceShare), the bundle with them over the size limit, or namespaces' changes into the cluster reserve (spec.bundle.clusterReserve); and ClusterWAFRuleSets whose change isn't published (Accepted=False, BundleTooLarge). Reported by the leader.",
	})
	// bundleNamespaceShare has a series only for the namespaces over their
	// share, so its cardinality is bounded by 100/namespaceShare per limit.
	bundleNamespaceShare = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_namespace_share_percent",
		Help: "The share of the published bundle's size limit (7,200 KiB compressed, 64 MiB raw) a namespace's content takes, in percent of the limit it takes most of, for the namespaces over spec.bundle.namespaceShare only: no series for the others, or with a single namespace. A compressed share is measured for at most 16 namespaces, the largest raw shares first, at most every 10 minutes unless the share changes. Reported by the leader.",
	}, []string{"policy_namespace"})
)

func init() {
	metrics.Registry.MustRegister(signingKeyAge, rotationPhase, publishFailures, bundleHeld, bundleNamespaceShare)
}

// sharesSeen is the bundle, the spec.bundle.namespaceShare and the time
// bundleNamespaceShare was last measured for.
type sharesSeen struct {
	content []byte
	share   int
	at      time.Time
}

// observeShares reports, in bundleNamespaceShare, the namespaces over
// their share of b, the published bundle: when the share changed, or b
// did and the last measure is a resync period old (it encodes up to
// maxMeasured bundles; the alert waits 30 minutes).
func (r *BundleReconciler) observeShares(b *bundlev1.Bundle, signer *bundle.Signer, share int) error {
	now := r.Now()
	seen := sharesSeen{content: b.GetContentHash(), share: share, at: now}
	if r.shares.at != (time.Time{}) && seen.share == r.shares.share &&
		(bytes.Equal(seen.content, r.shares.content) || now.Sub(r.shares.at) < resync) {
		return nil
	}
	lim := secretLimits
	if r.fitOptions.limits != (fitLimits{}) {
		lim = r.fitOptions.limits
	}
	over, err := overShares(b, signer, lim, share)
	if err != nil {
		return err
	}
	bundleNamespaceShare.Reset()
	for ns, pct := range over {
		bundleNamespaceShare.WithLabelValues(ns).Set(pct)
	}
	r.shares = seen
	return nil
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
