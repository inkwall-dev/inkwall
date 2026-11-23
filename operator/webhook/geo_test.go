// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func TestGeoWarnings(t *testing.T) {
	if len(isoCountries) != 250 {
		t.Errorf("%d codes, want the 249 assigned and XK", len(isoCountries))
	}
	// One of deny and allow (the CRD's rule), each.
	var warnings []string
	for _, g := range []*wafv1alpha1.GeoSpec{
		{Deny: []wafv1alpha1.CountryCode{"RU", "UK", "XK"}},
		{Allow: []wafv1alpha1.CountryCode{"EU", "XA"}},
	} {
		w, err := validateWAFPolicy(&wafv1alpha1.WAFPolicy{Spec: wafv1alpha1.WAFPolicySpec{Geo: g}})
		if err != nil {
			t.Fatal(err)
		}
		warnings = append(warnings, w...)
	}
	got := strings.Join(warnings, "\n")
	for _, want := range []string{
		"spec.geo.deny[1]: UK is not an ISO 3166-1 country code; the United Kingdom is GB",
		"spec.geo.allow[0]: EU is not a country",
		"spec.geo.allow[1]: XA is not an assigned ISO 3166-1 country code",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no warning %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "RU") || strings.Contains(got, "XK") {
		t.Errorf("warned of an assigned code:\n%s", got)
	}
	if w := geoWarnings(&wafv1alpha1.WAFPolicy{}); w != nil {
		t.Errorf("without geo: %v", w)
	}
}
