// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func TestSelectors(t *testing.T) {
	traefik := map[string]string{"app.kubernetes.io/name": "traefik"}
	edge := map[string]string{"app": "edge-proxy"}

	var defaults *Selectors
	if defaults.ForPod(traefik) != &All[0] || defaults.ForPod(edge) != nil {
		t.Error("defaults")
	}
	if got := defaults.PodSelector().String(); got != "app.kubernetes.io/name=traefik" {
		t.Errorf("default pod selector %q", got)
	}

	custom, ignored, err := FromConfig([]wafv1alpha1.IntegrationSpec{
		{Controller: "traefik", Selector: &metav1.LabelSelector{MatchLabels: edge}},
		{Controller: "ingress-nginx", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}},
		{Controller: "traefik-adapter-only"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ignored) != 1 || ignored[0] != "ingress-nginx" {
		t.Errorf("ignored %v", ignored)
	}
	if custom.ForPod(edge) == nil || custom.ForPod(edge).Name != "traefik" || custom.ForPod(traefik) != nil {
		t.Error("the override is not used")
	}
	again, _, _ := FromConfig([]wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: &metav1.LabelSelector{MatchLabels: edge}}})
	if custom.LabelSelector("traefik").MatchLabels["app"] != "edge-proxy" || custom.Equal(Defaults()) || !custom.Equal(again) {
		t.Error("LabelSelector or Equal")
	}
	if !Defaults().Equal(nil) {
		t.Error("nil is the defaults")
	}

	for _, bad := range []*metav1.LabelSelector{
		{},
		{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Near"}}},
	} {
		if _, _, err := FromConfig([]wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: bad}}); err == nil {
			t.Errorf("selector %v accepted", bad)
		}
	}
}
