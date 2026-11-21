// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// TestGeoEnforced (design 0011 §7): a geo policy is Enforced only with a
// table named and held by every engine running the bundle;
// EnginesOutdated takes precedence.
func TestGeoEnforced(t *testing.T) {
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 1},
		Spec: wafv1alpha1.WAFPolicySpec{Geo: &wafv1alpha1.GeoSpec{Deny: []wafv1alpha1.CountryCode{"RU"}}}}
	p.Status.BundleVersion = 3
	held := Engine{ID: "a", EngineVersion: "0.7.0", Applied: 3, GeoTable: "ab"}
	none := Engine{ID: "b", PodNamespace: "shop", PodName: "traefik-2", EngineVersion: "0.7.0", Applied: 3}
	old := Engine{ID: "c", EngineVersion: "0.6.2", Applied: 3}
	for _, tc := range []struct {
		name    string
		named   bool
		engines []Engine
		status  metav1.ConditionStatus
		reason  string
		message string
	}{
		{"no table named", false, []Engine{held}, metav1.ConditionFalse, ReasonGeoDatabaseUnavailable, "set InkwallConfig spec.geo.database"},
		{"every engine holds one", true, []Engine{held}, metav1.ConditionTrue, ReasonEnforced, ""},
		{"an engine holds none", true, []Engine{held, none}, metav1.ConditionFalse, ReasonGeoDatabaseUnavailable, "1 of 2 engines have no country table (first: shop/traefik-2)"},
		{"an old engine", true, []Engine{held, old}, metav1.ConditionFalse, ReasonEnginesOutdated, "spec.geo"},
	} {
		conds, _ := enforcedConditions(p, false, 3, false, tc.named, tc.engines, nil, 0, 0)
		c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced)
		if c.Status != tc.status || c.Reason != tc.reason || !strings.Contains(c.Message, tc.message) {
			t.Errorf("%s: %s %s %q", tc.name, c.Status, c.Reason, c.Message)
		}
	}
	// Without spec.geo, a table or not changes nothing.
	plain := p.DeepCopy()
	plain.Spec.Geo = nil
	conds, _ := enforcedConditions(plain, false, 3, false, false, []Engine{none}, nil, 0, 0)
	if c := meta.FindStatusCondition(conds, wafv1alpha1.ConditionEnforced); c.Reason != ReasonEnforced {
		t.Errorf("without geo: %s", c.Reason)
	}
	if f, v := requirement(p, false); f != "spec.geo" || v != [3]int{0, 7, 0} {
		t.Errorf("requirement %s %v", f, v)
	}
}

// TestReadEnginesGeoTable: the table an engine holds survives its
// replica's report, for the leader's GeoDatabaseUnavailable.
func TestReadEnginesGeoTable(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	data, _ := json.Marshal([]Engine{{ID: "e1", GeoTable: "ab12"}})
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: reportNamePrefix + "a", Labels: map[string]string{EnginesLabel: "true"}},
		Data:       map[string]string{enginesKey: string(data), updatedAtKey: now.Format(time.RFC3339Nano)},
	}).Build()
	got, _, err := ReadEngines(context.Background(), c, "inkwall-system", time.Minute, now)
	if err != nil || len(got) != 1 || got[0].GeoTable != "ab12" {
		t.Fatalf("%+v, %v", got, err)
	}
}
