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
	envoy := map[string]string{"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway", "app.kubernetes.io/component": "proxy"}
	otherEnvoy := map[string]string{"app.kubernetes.io/name": "envoy"}
	edge := map[string]string{"app": "edge-proxy"}

	var defaults *Selectors
	name := func(i *Integration) string {
		if i == nil {
			return ""
		}
		return i.Name
	}
	if name(defaults.ForPod(traefik)) != "traefik" || name(defaults.ForPod(envoy)) != "envoy-gateway" || defaults.ForPod(edge) != nil || defaults.IsProxyPod(otherEnvoy) {
		t.Error("defaults")
	}
	// The cache's selector: a superset of the integrations' pods.
	if got := defaults.PodSelector().String(); got != "app.kubernetes.io/name in (envoy,traefik)" {
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
	// No key in common with Envoy Gateway's selector: every pod.
	if got := custom.PodSelector(); !got.Empty() {
		t.Errorf("pod selector %q, want every pod", got)
	}
	sameKey, _, _ := FromConfig([]wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: &metav1.LabelSelector{
		MatchLabels:      map[string]string{"app.kubernetes.io/name": "edge"},
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app.kubernetes.io/managed-by", Operator: metav1.LabelSelectorOpIn, Values: []string{"helm", "flux"}}},
	}}})
	if got := sameKey.PodSelector().String(); got != "app.kubernetes.io/managed-by in (envoy-gateway,flux,helm),app.kubernetes.io/name in (edge,envoy)" {
		t.Errorf("pod selector %q", got)
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
