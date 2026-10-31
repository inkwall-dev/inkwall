// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

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
	if name(defaults.ForPod(traefik)) != "traefik" || name(defaults.ForPod(envoy)) != "envoy-gateway" || defaults.ForPod(edge) != nil || defaults.ForPod(otherEnvoy) != nil {
		t.Error("defaults")
	}
	// The cache's selectors: one per integration.
	if got := fmt.Sprint(defaults.PodSelectors()); got != "[app.kubernetes.io/name=traefik app.kubernetes.io/managed-by=envoy-gateway,app.kubernetes.io/name=envoy]" {
		t.Errorf("default pod selectors %s", got)
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
	// No key in common with Envoy Gateway's selector: still only their pods.
	if got := fmt.Sprint(custom.PodSelectors()); got != "[app=edge-proxy app.kubernetes.io/managed-by=envoy-gateway,app.kubernetes.io/name=envoy]" {
		t.Errorf("pod selectors %s", got)
	}
	again, _, _ := FromConfig([]wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: &metav1.LabelSelector{MatchLabels: edge}}})
	if custom.LabelSelector("traefik").MatchLabels["app"] != "edge-proxy" || custom.Equal(Defaults()) || !custom.Equal(again) {
		t.Error("LabelSelector or Equal")
	}
	if !Defaults().Equal(nil) {
		t.Error("nil is the defaults")
	}
	if none, _ := metav1.LabelSelectorAsSelector(NoPods()); none.Matches(labels.Set(traefik)) || none.Matches(labels.Set{}) {
		t.Error("NoPods matches")
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
