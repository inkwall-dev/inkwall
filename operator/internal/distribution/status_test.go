// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The Reporter writes a policy's status only when Enforced or Ready
// changes, not when engines come and go, and writes several at once.
func TestReporterWrites(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)

	const policies = 40
	var objs []client.Object
	for i := range policies {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p" + strconv.Itoa(i), Generation: 1}}
		p.Status.ObservedGeneration = 1
		p.Status.BundleVersion = 1
		for _, c := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed} {
			meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c, ObservedGeneration: 1})
		}
		objs = append(objs, p)
	}
	report := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + "a", Labels: map[string]string{EnginesLabel: "true"}}}
	setEngines := func(c client.Client, engines ...Engine) {
		t.Helper()
		data, _ := json.Marshal(engines)
		report.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := c.Update(ctx, report); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu                    sync.Mutex
		writes, running, most int
	)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(append(objs, report)...).
		WithStatusSubresource(&wafv1alpha1.WAFPolicy{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			mu.Lock()
			writes++
			running++
			most = max(most, running)
			mu.Unlock()
			defer func() { mu.Lock(); running--; mu.Unlock() }()
			time.Sleep(10 * time.Millisecond)
			return c.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	r := &Reporter{Client: c, Reader: c, Namespace: "inkwall-system", Stale: time.Minute, Store: NewStore()}

	step := func(what string, want int, engines ...Engine) {
		t.Helper()
		setEngines(c, engines...)
		writes = 0
		if err := r.report(ctx); err != nil {
			t.Fatal(err)
		}
		if got := writes; got != want {
			t.Errorf("%s: %d status writes, want %d", what, got, want)
		}
	}
	step("first engine", policies, Engine{ID: "e1", Applied: 1})
	if most < 2 || most > statusWriters {
		t.Errorf("%d writes at once, want 2 to %d", most, statusWriters)
	}
	step("same engines", 0, Engine{ID: "e1", Applied: 1})
	step("another engine, current", 0, Engine{ID: "e1", Applied: 1}, Engine{ID: "e2", Applied: 1})
	step("one engine gone", 0, Engine{ID: "e2", Applied: 1})
	step("an engine behind", policies, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3"})
	step("another engine behind", 0, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3"}, Engine{ID: "e4"})
	step("caught up", policies, Engine{ID: "e2", Applied: 1}, Engine{ID: "e3", Applied: 1}, Engine{ID: "e4", Applied: 1})

	var p wafv1alpha1.WAFPolicy
	if err := c.Get(ctx, client.ObjectKey{Namespace: "web", Name: "p0"}, &p); err != nil {
		t.Fatal(err)
	}
	if cond := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionReady); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("Ready: %+v", cond)
	}
}

// A suspended bundle enforces nothing; and when inspection resumes, the
// policy's version in the bundle served counts before the builder writes
// it into the status (#263).
func TestEnforcedSuspended(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "p", Generation: 1}}
	p.Status.BundleVersion = 3
	engines := []Engine{{ID: "e1", Applied: 3}}
	for _, tc := range []struct {
		name      string
		served    uint64
		suspended bool
		status    metav1.ConditionStatus
		reason    string
	}{
		{"enforced", 3, false, metav1.ConditionTrue, ReasonEnforced},
		{"suspended", 3, true, metav1.ConditionFalse, ReasonSuspended},
		{"resumed, status not written yet", 4, false, metav1.ConditionFalse, ReasonEnginesBehind},
		{"served bundle older than the status", 2, false, metav1.ConditionTrue, ReasonEnforced},
	} {
		conds, _ := enforcedConditions(p, tc.served, tc.suspended, engines, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c == nil || c.Status != tc.status || c.Reason != tc.reason {
			t.Errorf("%s: Enforced %+v, want %s %s", tc.name, c, tc.status, tc.reason)
		}
		if tc.suspended && !strings.Contains(c.Message, "InkwallConfig default") {
			t.Errorf("%s: message %q doesn't name the InkwallConfig", tc.name, c.Message)
		}
		if r := meta.FindStatusCondition(conds, wafv1alpha1.ConditionReady); r == nil || r.Status != metav1.ConditionFalse {
			t.Errorf("%s: Ready %+v, want False (not Programmed)", tc.name, r)
		}
	}
}
