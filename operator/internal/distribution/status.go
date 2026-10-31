// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Reasons of the Enforced condition.
const (
	ReasonEnforced      = "Enforced"
	ReasonEnginesBehind = "EnginesBehind"
	// ReasonEnginesUnreported: a replica's engine report was over its
	// size limit, so not every engine is known.
	ReasonEnginesUnreported = "EnginesUnreported"
	ReasonEngineNack        = "EngineNack"
	ReasonNoEngines         = "NoEngines"
	ReasonNotInBundle       = "NotInBundle"
)

var (
	bundleVersion = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_version",
		Help: "Version of the bundle this replica serves.",
	})
	bundleBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_compressed_bytes",
		Help: "Size of the bundle this replica serves, gzip-compressed, as stored in its Secrets: over 900 KiB it is split into chunks, over 7.2 MiB it can't be published.",
	})
	engineCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_engines",
		Help: "Connected engines, by whether they run the current bundle (current, behind, rejected). Reported by the leader.",
	}, []string{"state"})
	eventsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "inkwall_operator_events_received_total",
		Help: "Security events received from the engines on this replica.",
	})
	eventsDroppedByEngines = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "inkwall_operator_engine_events_dropped_total",
		Help: "Security events the engines on this replica reported dropping (their buffer was full).",
	})
	// RequestStatsDropped counts, per policy and report, the request counts
	// this replica drops: here, and in the controlplane package's totals.
	RequestStatsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "inkwall_operator_request_stats_dropped_total",
		Help: "Policies' request counts this replica dropped, by reason: not_in_bundle (an engine reported a policy the bundle served here doesn't have), latency_buckets (its latency was counted in other buckets: the counts are kept, the latency dropped), evicted (the totals of a policy no longer in the bundle, forgotten so they stay bounded).",
	}, []string{"reason"})
)

// Reasons of RequestStatsDropped.
const (
	DroppedNotInBundle    = "not_in_bundle"
	DroppedLatencyBuckets = "latency_buckets"
	DroppedEvicted        = "evicted"
)

func init() {
	metrics.Registry.MustRegister(bundleVersion, bundleBytes, engineCount, eventsReceived, eventsDroppedByEngines, RequestStatsDropped)
}

// Enforced computes a policy's Enforced condition: whether every connected
// engine runs a bundle that contains the policy's current generation: the
// first such bundle is its status.bundleVersion, and later ones have it too. Every engine gets the same bundle, so every
// engine counts until engines are matched to the routes they serve.
//
// leftOut engines are connected but missing from their replica's report.
//
// The messages don't count engines, so engines connecting or going away
// don't rewrite every policy's status; the inkwall_operator_engines metric
// has the counts. EngineNack names the first engine (by ID) that rejected
// the bundle, with its error.
func Enforced(version int64, engines []Engine, leftOut int) (metav1.ConditionStatus, string, string) {
	if version <= 0 {
		return metav1.ConditionFalse, ReasonNotInBundle, "the policy's current spec is not in a bundle"
	}
	v := uint64(version)
	if len(engines) == 0 && leftOut == 0 {
		return metav1.ConditionFalse, ReasonNoEngines, "no engine is connected"
	}
	current := 0
	var rejectErr string
	for _, e := range engines {
		switch {
		case e.Applied >= v:
			current++
		case e.Rejected >= v && rejectErr == "":
			rejectErr = fmt.Sprintf("%s: %s", engineName(e), e.RejectError)
		}
	}
	total := len(engines) + leftOut
	switch {
	case rejectErr != "":
		return metav1.ConditionFalse, ReasonEngineNack,
			fmt.Sprintf("some engines rejected bundle %d (first: %s)", v, rejectErr)
	case leftOut > 0:
		return metav1.ConditionFalse, ReasonEnginesUnreported,
			fmt.Sprintf("some engines are not in their replica's report (over its size limit), so bundle %d is not known to run everywhere", v)
	case current < total:
		return metav1.ConditionFalse, ReasonEnginesBehind, fmt.Sprintf("some engines don't run bundle %d yet", v)
	}
	return metav1.ConditionTrue, ReasonEnforced, fmt.Sprintf("every engine runs bundle %d or later", v)
}

func engineName(e Engine) string {
	if e.PodName != "" {
		return e.PodNamespace + "/" + e.PodName
	}
	return e.ID
}

// Ready combines a policy's conditions (0004 §3.2): True when Accepted,
// Programmed and Enforced all are; otherwise the first that isn't, by its
// reason, so kubectl shows what is missing.
func Ready(conds []metav1.Condition, generation int64) metav1.Condition {
	for _, t := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced} {
		c := meta.FindStatusCondition(conds, t)
		if c == nil {
			return metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: "Not" + t,
				Message: t + " is not reported yet", ObservedGeneration: generation}
		}
		if c.Status != metav1.ConditionTrue {
			return metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: c.Reason,
				Message: t + ": " + c.Message, ObservedGeneration: generation}
		}
	}
	return metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Ready",
		Message: "accepted, programmed into the proxy and enforced by every engine", ObservedGeneration: generation}
}

// statusWriters is how many policy statuses the Reporter writes at once.
const statusWriters = 8

// Reporter writes the Enforced condition of every policy. It runs on the
// leader, from the replicas' engine reports.
type Reporter struct {
	Client client.Client
	// Reader reads the reports uncached (the manager doesn't cache them).
	Reader    client.Reader
	Namespace string
	Interval  time.Duration
	// Stale is how old a replica's report may be before it is ignored.
	Stale time.Duration
	// Store has the bundle being served, for the engine metrics.
	Store *Store
}

// Start implements manager.Runnable.
func (r *Reporter) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("enforced")
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	for {
		if err := r.report(ctx); err != nil && ctx.Err() == nil {
			logger.Error(err, "can't report engine status")
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// NeedLeaderElection implements LeaderElectionRunnable.
func (*Reporter) NeedLeaderElection() bool { return true }

func (r *Reporter) report(ctx context.Context) error {
	engines, leftOut, err := ReadEngines(ctx, r.Reader, r.Namespace, r.Stale, time.Now())
	if err != nil {
		return err
	}
	var policies wafv1alpha1.WAFPolicyList
	if err := r.Client.List(ctx, &policies, client.UnsafeDisableDeepCopy); err != nil {
		return err
	}

	_, latest, _ := r.Store.Current()
	var current, behind, rejected float64
	for _, e := range engines {
		switch {
		case e.Applied >= latest:
			current++
		case e.Rejected >= latest:
			rejected++
		default:
			behind++
		}
	}
	engineCount.WithLabelValues("current").Set(current)
	engineCount.WithLabelValues("behind").Set(behind)
	engineCount.WithLabelValues("rejected").Set(rejected)

	// Most policies don't change; those that do are written 8 at a time,
	// like the bundle builder's writes.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(statusWriters)
	for i := range policies.Items {
		p := &policies.Items[i]
		// The bundle builder reports Accepted and the policy's bundle
		// first, for this generation; wait for it.
		if meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionAccepted) == nil ||
			p.Status.ObservedGeneration != p.Generation {
			continue
		}
		// The list is the cache's, not a copy: copy only what is written.
		if _, changed := enforcedConditions(p, engines, leftOut); !changed {
			continue
		}
		p = p.DeepCopy()
		g.Go(func() error { return r.write(gctx, p, engines, leftOut) })
	}
	return g.Wait()
}

// enforcedConditions returns p's conditions with Enforced and Ready set
// from the engines, and whether they changed. p is left as it is.
func enforcedConditions(p *wafv1alpha1.WAFPolicy, engines []Engine, leftOut int) ([]metav1.Condition, bool) {
	conds := slices.Clone(p.Status.Conditions)
	st, reason, msg := Enforced(p.Status.BundleVersion, engines, leftOut)
	changed := meta.SetStatusCondition(&conds, metav1.Condition{
		Type: wafv1alpha1.ConditionEnforced, Status: st, Reason: reason, Message: msg, ObservedGeneration: p.Generation,
	})
	if meta.SetStatusCondition(&conds, Ready(conds, p.Generation)) {
		changed = true
	}
	return conds, changed
}

func (r *Reporter) write(ctx context.Context, p *wafv1alpha1.WAFPolicy, engines []Engine, leftOut int) error {
	first := true
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if !first {
			if err := r.Client.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
				return err
			}
		}
		first = false
		conds, changed := enforcedConditions(p, engines, leftOut)
		if !changed {
			return nil
		}
		p.Status.Conditions = conds
		return r.Client.Status().Update(ctx, p)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
