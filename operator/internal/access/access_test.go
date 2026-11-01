// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

// The disabled message names the chart value that grants the
// integration's ClusterRole: each is a key of rbac.integrations.
func TestChartValue(t *testing.T) {
	roles, err := Roles()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../deploy/helm/inkwall/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		RBAC struct {
			Integrations map[string]string `json:"integrations"`
		} `json:"rbac"`
	}
	if err := yaml.Unmarshal(b, &values); err != nil {
		t.Fatal(err)
	}
	if len(roles) != len(values.RBAC.Integrations) {
		t.Errorf("integrations %d, rbac.integrations keys %v", len(roles), values.RBAC.Integrations)
	}
	for name := range roles {
		if _, ok := values.RBAC.Integrations[chartValue(name)]; !ok {
			t.Errorf("no rbac.integrations.%s in the chart's values for the %s integration", chartValue(name), name)
		}
	}
}
