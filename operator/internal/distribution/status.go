// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
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
	// ReasonEnginesOutdated: an engine runs the bundle but is too old to
	// enforce a field the policy sets, which it ignores.
	ReasonEnginesOutdated = "EnginesOutdated"
	// ReasonSuspended: the bundle suspends inspection (the InkwallConfig's
	// spec.suspend), so engines allow every request.
	ReasonSuspended = "Suspended"
)

// suspendedMessage is the Enforced message of a suspended policy.
const suspendedMessage = "InkwallConfig default suspends inspection (spec.suspend): every engine allows every request"

var (
	bundleVersion = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_version",
		Help: "Version of the bundle this replica serves.",
	})
	bundleBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inkwall_operator_bundle_compressed_bytes",
		Help: "Size of the bundle this replica serves, gzip-compressed, as stored in its Secrets: over 900 KiB it is split into chunks, over 7,200 KiB it can't be published.",
	})
	engineCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inkwall_operator_engines",
		Help: "Connected engines, by whether they run the current bundle (current, behind, rejected), and by the integration whose proxy pod runs them (unknown: not matched to one yet). Reported by the leader.",
	}, []string{"state", "integration"})
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

// Enforced computes a policy's Enforced condition: whether every engine
// given runs a bundle that contains the policy's current generation: the
// first such bundle is its status.bundleVersion, and later ones have it
// too. The engines given are those that serve the policy's routes, or all
// of them when that isn't known (ServedPods).
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

// outdatedEngine returns the first engine too old for a field p sets
// (an engine ignores fields it doesn't know), the field and the version it
// needs; nil when there is none. An engine whose version isn't a release
// (a development build) counts as new enough.
func outdatedEngine(p *wafv1alpha1.WAFPolicy, engines []Engine) (*Engine, string, string) {
	var field string
	var need [3]int
	if w := p.Spec.WebSocket; w != nil && (len(w.AllowedOrigins) > 0 || len(w.RequiredHeaders) > 0) {
		field, need = "spec.webSocket", [3]int{0, 4, 0}
	}
	if b := p.Spec.Body; field == "" && b != nil && b.GRPCMessages == wafv1alpha1.GRPCMessagesInspect {
		field, need = "spec.body.grpcMessages", [3]int{0, 4, 0}
	}
	if r := p.Spec.Responses; field == "" && r != nil && r.Inspect {
		// An older engine inspects requests only (#274).
		field, need = "spec.responses", [3]int{0, 4, 0}
	}
	for i, b := range p.Spec.RuleSets {
		if field == "" && !b.CRS.IsZero() {
			// An older engine keeps the CRS's defaults (#352).
			field, need = fmt.Sprintf("spec.ruleSets[%d].crs", i), [3]int{0, 5, 0}
		}
	}
	if field == "" {
		return nil, "", ""
	}
	for i := range engines {
		if v, ok := releaseVersion(engines[i].EngineVersion); ok && slices.Compare(v[:], need[:]) < 0 {
			return &engines[i], field, fmt.Sprintf("%d.%d.%d", need[0], need[1], need[2])
		}
	}
	return nil, "", ""
}

// releaseVersion parses "MAJOR.MINOR.PATCH", with or without a leading
// "v", ignoring a pre-release or build suffix.
func releaseVersion(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func engineName(e Engine) string {
	if e.PodName != "" {
		return e.PodNamespace + "/" + e.PodName
	}
	return e.ID
}

// Ready combines a policy's conditions (0004 §3.2): True when Accepted,
// Programmed and Enforced all are; otherwise the first that isn't, by its
// reason, so kubectl shows what is missing. Suspended inspection (Enforced's
// reason Suspended) comes first: whatever else holds, every engine allows
// every request (#291).
func Ready(conds []metav1.Condition, generation int64) metav1.Condition {
	if c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced); c != nil &&
		c.Status != metav1.ConditionTrue && c.Reason == ReasonSuspended {
		return metav1.Condition{Type: wafv1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: c.Reason,
			Message: wafv1alpha1.ConditionEnforced + ": " + c.Message, ObservedGeneration: generation}
	}
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
	// Served maps policies to the pods that serve them; nil: every engine
	// counts for every policy.
	Served *ServedPods
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
	suspended := r.Store.Suspended()
	served := r.Served.view()
	counts := map[[2]string]float64{}
	for _, e := range engines {
		state := "behind"
		switch {
		case e.Applied >= latest:
			state = "current"
		case e.Rejected >= latest:
			state = "rejected"
		}
		counts[[2]string{state, served.integrationOf(e)}]++
	}
	engineCount.Reset()
	for _, state := range []string{"current", "behind", "rejected"} {
		engineCount.WithLabelValues(state, "unknown").Set(0)
	}
	for k, n := range counts {
		engineCount.WithLabelValues(k[0], k[1]).Set(n)
	}

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
		key := p.Namespace + "/" + p.Name
		version := r.Store.PolicyVersion(key)
		mine := served.enginesFor(key, engines)
		// The list is the cache's, not a copy: copy only what is written.
		if _, changed := enforcedConditions(p, version, suspended, mine, leftOut); !changed {
			continue
		}
		p = p.DeepCopy()
		g.Go(func() error { return r.write(gctx, p, version, suspended, mine, leftOut) })
	}
	return g.Wait()
}

// enforcedConditions returns p's conditions with Enforced and Ready set
// from the engines, and whether they changed. p is left as it is.
//
// served is the policy's version in the bundle served (Store.PolicyVersion),
// which may be newer than its status: the builder writes the status after
// publishing. Engines must run it too, so that when inspection resumes,
// engines still on the suspended bundle don't count. A suspended bundle
// enforces nothing.
func enforcedConditions(p *wafv1alpha1.WAFPolicy, served uint64, suspended bool, engines []Engine, leftOut int) ([]metav1.Condition, bool) {
	conds := slices.Clone(p.Status.Conditions)
	version := max(p.Status.BundleVersion, int64(served)) // #nosec G115 -- versions count builds
	st, reason, msg := Enforced(version, engines, leftOut)
	if st == metav1.ConditionTrue {
		if e, field, need := outdatedEngine(p, engines); e != nil {
			st, reason = metav1.ConditionFalse, ReasonEnginesOutdated
			msg = fmt.Sprintf("some engines are too old to enforce %s, which they ignore (first: %s runs %s; it needs %s or later)",
				field, engineName(*e), e.EngineVersion, need)
		}
	}
	if suspended {
		st, reason, msg = metav1.ConditionFalse, ReasonSuspended, suspendedMessage
	}
	changed := meta.SetStatusCondition(&conds, metav1.Condition{
		Type: wafv1alpha1.ConditionEnforced, Status: st, Reason: reason, Message: msg, ObservedGeneration: p.Generation,
	})
	if meta.SetStatusCondition(&conds, Ready(conds, p.Generation)) {
		changed = true
	}
	return conds, changed
}

func (r *Reporter) write(ctx context.Context, p *wafv1alpha1.WAFPolicy, served uint64, suspended bool, engines []Engine, leftOut int) error {
	first := true
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if !first {
			if err := r.Client.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
				return err
			}
		}
		first = false
		conds, changed := enforcedConditions(p, served, suspended, engines, leftOut)
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
