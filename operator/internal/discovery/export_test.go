// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

func replica(name string, sinks ...enginereport.Sink) enginereport.ReplicaSinks {
	return enginereport.ReplicaSinks{Replica: name, Sinks: sinks}
}

// The replicas' reports fold into one condition: the first of
// ExportConfigInvalid, ExportAddressRefused, ExportFailing, ExportDropping
// wins, and the message lists the sinks of each.
func TestExportCondition(t *testing.T) {
	ok := func(name string) enginereport.Sink {
		return enginereport.Sink{Name: name, State: enginereport.SinkExporting}
	}
	for _, tc := range []struct {
		name     string
		sinks    []string
		reports  []enginereport.ReplicaSinks
		missing  []NotReported // past the grace
		nilCond  bool
		status   metav1.ConditionStatus
		reason   string
		contains []string
		lacks    []string
	}{
		{name: "no sinks", reports: []enginereport.ReplicaSinks{replica("a", ok("x"))}, nilCond: true},
		{name: "no report yet", sinks: []string{"x"}, nilCond: true},
		{name: "every sink exports", sinks: []string{"x", "y"},
			reports: []enginereport.ReplicaSinks{replica("a", ok("x"), ok("y")), replica("b", ok("x"), ok("y"))},
			status:  metav1.ConditionTrue, reason: ReasonExporting, contains: []string{"every sink exports (2)"}},
		// A live replica that doesn't report a sink, past the grace, doesn't
		// export it.
		{name: "a sink a replica doesn't report", sinks: []string{"x", "y"},
			reports: []enginereport.ReplicaSinks{replica("a", ok("x"), ok("y")), replica("b", ok("x"))},
			missing: []NotReported{{Sink: "y", Replica: "b"}},
			status:  metav1.ConditionFalse, reason: ReasonExportNotReported, contains: []string{"ExportNotReported: sink y on b: not in its report"}},
		{name: "no replica reports", sinks: []string{"x"},
			missing: []NotReported{{Sink: "x"}},
			status:  metav1.ConditionFalse, reason: ReasonExportNotReported, contains: []string{"sink x: no operator replica reports it"}},
		// Renamed: the old name is still reported, the new one by no one.
		{name: "renamed sink", sinks: []string{"new"},
			reports: []enginereport.ReplicaSinks{replica("a", ok("old"))},
			missing: []NotReported{{Sink: "new", Replica: "a"}},
			status:  metav1.ConditionFalse, reason: ReasonExportNotReported, lacks: []string{"old"}},
		{name: "failing over not reported", sinks: []string{"x", "y"},
			reports: []enginereport.ReplicaSinks{replica("a", enginereport.Sink{Name: "x", State: enginereport.SinkFailing})},
			missing: []NotReported{{Sink: "y", Replica: "a"}},
			status:  metav1.ConditionFalse, reason: ReasonExportFailing, contains: []string{"ExportNotReported: sink y on a"}},
		{name: "plaintext named", sinks: []string{"x"},
			reports: []enginereport.ReplicaSinks{replica("a", enginereport.Sink{Name: "x", State: enginereport.SinkExporting, Plaintext: true})},
			status:  metav1.ConditionTrue, reason: ReasonExporting, contains: []string{"plaintext (insecure: true): x"}},
		{name: "precedence", sinks: []string{"x", "y", "z", "w"},
			reports: []enginereport.ReplicaSinks{
				replica("a", enginereport.Sink{Name: "x", State: enginereport.SinkFailing, Message: "network: connection failed"},
					enginereport.Sink{Name: "y", State: enginereport.SinkDropping}),
				replica("b", enginereport.Sink{Name: "z", State: enginereport.SinkAddressRefused, Message: "refused: metadata"}, ok("w")),
			},
			status: metav1.ConditionFalse, reason: ReasonExportAddressRefused,
			contains: []string{"ExportAddressRefused: sink z on b: refused: metadata", "ExportFailing: sink x on a: network: connection failed", "ExportDropping: sink y on a"}},
		{name: "config invalid first", sinks: []string{"x", "y"},
			reports: []enginereport.ReplicaSinks{replica("a",
				enginereport.Sink{Name: "x", State: enginereport.SinkFailing}, enginereport.Sink{Name: "y", State: enginereport.SinkConfigInvalid, Message: "the Secret s doesn't exist"})},
			status: metav1.ConditionFalse, reason: ReasonExportConfigInvalid, contains: []string{"sink y on a: the Secret s doesn't exist"}},
		{name: "dropping only", sinks: []string{"x"},
			reports: []enginereport.ReplicaSinks{replica("a", enginereport.Sink{Name: "x", State: enginereport.SinkDropping})},
			status:  metav1.ConditionFalse, reason: ReasonExportDropping},
		// A sink removed from the spec, which a replica still reports.
		{name: "removed sink ignored", sinks: []string{"x"},
			reports: []enginereport.ReplicaSinks{replica("a", ok("x"), enginereport.Sink{Name: "old", State: enginereport.SinkFailing})},
			status:  metav1.ConditionTrue, reason: ReasonExporting, lacks: []string{"old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ExportCondition(tc.sinks, tc.reports, tc.missing, 3)
			if tc.nilCond {
				if c != nil {
					t.Fatalf("condition %+v, want none", c)
				}
				return
			}
			if c == nil || c.Type != wafv1alpha1.ConditionEventsExported || c.Status != tc.status || c.Reason != tc.reason || c.ObservedGeneration != 3 {
				t.Fatalf("condition %+v, want %s %s", c, tc.status, tc.reason)
			}
			for _, s := range tc.contains {
				if !strings.Contains(c.Message, s) {
					t.Errorf("message %q lacks %q", c.Message, s)
				}
			}
			for _, s := range tc.lacks {
				if strings.Contains(c.Message, s) {
					t.Errorf("message %q has %q", c.Message, s)
				}
			}
		})
	}
	long := []enginereport.Sink{}
	for range 40 {
		long = append(long, enginereport.Sink{Name: "x", State: enginereport.SinkFailing, Message: strings.Repeat("m", 100)})
	}
	if c := ExportCondition([]string{"x"}, []enginereport.ReplicaSinks{replica("a", long...)}, nil, 1); len(c.Message) > maxConditionMessage {
		t.Errorf("message of %d bytes", len(c.Message))
	}
	// Cut at a rune boundary.
	if got := cut(strings.Repeat("é", 600), maxConditionMessage); !utf8.ValidString(got) || len(got) > maxConditionMessage {
		t.Errorf("cut to %d bytes, valid UTF-8 %t", len(got), utf8.ValidString(got))
	}
}

// Missing names each configured sink a live replica's report lacks, or
// every one when no replica reports.
func TestMissing(t *testing.T) {
	ok := enginereport.Sink{Name: "x", State: enginereport.SinkExporting}
	got := Missing([]string{"x", "y"}, []enginereport.ReplicaSinks{replica("a", ok), replica("b")})
	want := []NotReported{{"x", "b"}, {"y", "a"}, {"y", "b"}}
	if !slices.Equal(got, want) {
		t.Errorf("missing %v, want %v", got, want)
	}
	if got := Missing([]string{"x"}, nil); !slices.Equal(got, []NotReported{{Sink: "x"}}) {
		t.Errorf("missing %v with no reports", got)
	}
}

// A missing sink counts only once missing for the grace.
func TestNotReportedAfterGrace(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	r := &Reconciler{NotReportedAfter: time.Minute}
	m := []NotReported{{Sink: "x", Replica: "a"}}
	if got := r.notReported(m, now); len(got) != 0 {
		t.Errorf("at once: %v", got)
	}
	if got := r.notReported(m, now.Add(59*time.Second)); len(got) != 0 {
		t.Errorf("within the grace: %v", got)
	}
	if got := r.notReported(m, now.Add(time.Minute)); len(got) != 1 {
		t.Errorf("past the grace: %v", got)
	}
	// Reported again: forgotten, and the grace starts over.
	r.notReported(nil, now.Add(2*time.Minute))
	if got := r.notReported(m, now.Add(3*time.Minute)); len(got) != 0 {
		t.Errorf("missing again: %v, want the grace again", got)
	}
}

// The leader writes EventsExported from the replicas' reports, alone, with
// a server-side apply: the conditions others write stay; without sinks,
// it goes.
func TestReconcileEventsExported(t *testing.T) {
	testenv.Skip(t, env)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	c, err := client.New(env.Config, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "inkwall-export-test"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{Client: c, Reports: c, Namespace: ns.Name, ReportStale: time.Minute}
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wafv1alpha1.InkwallConfigSpec{Events: wafv1alpha1.EventsSpec{Export: &wafv1alpha1.ExportSpec{Sinks: []wafv1alpha1.EventSink{
			{Name: "splunk", JSON: &wafv1alpha1.JSONSink{URL: "https://splunk.example.com/in"}},
		}}}}}
	if err := c.Create(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	testenv.DeleteOnCleanup(t, c, cfg)
	// Another writer's condition: the control plane connector's.
	cfg.Status.Conditions = []metav1.Condition{{Type: wafv1alpha1.ConditionControlPlaneConnected, Status: metav1.ConditionFalse, Reason: "Unreachable", Message: "x", LastTransitionTime: metav1.Now()}}
	if err := c.Status().Update(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	report := func(sinks ...enginereport.Sink) {
		t.Helper()
		raw, _ := json.Marshal(sinks)
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: enginereport.NamePrefix + "op-a", Labels: map[string]string{enginereport.Label: "true"}},
			Data: map[string]string{enginereport.EnginesKey: "[]", enginereport.UpdatedAtKey: time.Now().UTC().Format(time.RFC3339Nano), enginereport.ExportKey: string(raw)}}
		if err := c.Update(ctx, cm); err != nil {
			if err := c.Create(ctx, cm); err != nil {
				t.Fatal(err)
			}
		}
	}
	reconcileOnce := func() (reconcile.Result, *wafv1alpha1.InkwallConfig) {
		t.Helper()
		res, err := r.Reconcile(ctx, reconcile.Request{})
		if err != nil {
			t.Fatal(err)
		}
		got := &wafv1alpha1.InkwallConfig{}
		if err := c.Get(ctx, client.ObjectKey{Name: "default"}, got); err != nil {
			t.Fatal(err)
		}
		return res, got
	}

	// No report yet: nothing written, and it looks again.
	res, got := reconcileOnce()
	if meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported) != nil || res.RequeueAfter != exportResync {
		t.Errorf("before any report: %v, requeue %v", got.Status.Conditions, res.RequeueAfter)
	}

	report(enginereport.Sink{Name: "splunk", State: enginereport.SinkFailing, Message: "auth: 401"})
	_, got = reconcileOnce()
	ee := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported)
	if ee == nil || ee.Status != metav1.ConditionFalse || ee.Reason != ReasonExportFailing || !strings.Contains(ee.Message, "sink splunk on op-a: auth: 401") {
		t.Fatalf("EventsExported %+v", ee)
	}
	if cp := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionControlPlaneConnected); cp == nil || cp.Reason != "Unreachable" {
		t.Errorf("the connector's condition: %+v", cp)
	}
	failedAt := ee.LastTransitionTime

	// The same state: not written again.
	rv := got.ResourceVersion
	if _, got = reconcileOnce(); got.ResourceVersion != rv {
		t.Error("an unchanged condition was written again")
	}

	report(enginereport.Sink{Name: "splunk", State: enginereport.SinkExporting})
	_, got = reconcileOnce()
	ee = meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported)
	if ee == nil || ee.Status != metav1.ConditionTrue || ee.Reason != ReasonExporting || ee.LastTransitionTime.Before(&failedAt) {
		t.Fatalf("EventsExported %+v after the sink recovered", ee)
	}

	// The replicas stop reporting (gone, or their reports stale): not
	// True forever, but NotReported once missing for the grace.
	if err := c.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: enginereport.NamePrefix + "op-a"}}); err != nil {
		t.Fatal(err)
	}
	later := time.Now()
	r.now = func() time.Time { return later }
	if _, got = reconcileOnce(); meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported).Reason != ReasonExporting {
		t.Error("changed within the grace")
	}
	later = later.Add(DefaultNotReportedAfter)
	_, got = reconcileOnce()
	ee = meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported)
	if ee == nil || ee.Status != metav1.ConditionFalse || ee.Reason != ReasonExportNotReported || !strings.Contains(ee.Message, "no operator replica reports it") {
		t.Fatalf("EventsExported %+v with no report past the grace", ee)
	}
	r.now = nil

	// No sinks: the condition goes, the others stay.
	got.Spec.Events.Export = nil
	if err := c.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	res, got = reconcileOnce()
	if meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEventsExported) != nil || res.RequeueAfter != 0 {
		t.Errorf("without sinks: %v, requeue %v", got.Status.Conditions, res.RequeueAfter)
	}
	if meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionControlPlaneConnected) == nil {
		t.Error("removing EventsExported removed the connector's condition")
	}
}
