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

// An allow list warns that unknown addresses get through, unless unknown
// is Deny; a deny list doesn't.
func TestGeoWarningsUnknown(t *testing.T) {
	const want = "spec.geo.allow: with unknown: Allow (the default), public addresses the database has no country for get through geo"
	for _, tc := range []struct {
		name string
		geo  wafv1alpha1.GeoSpec
		warn bool
	}{
		{"allow, defaulted", wafv1alpha1.GeoSpec{Allow: []wafv1alpha1.CountryCode{"DE"}, Unknown: wafv1alpha1.GeoUnknownAllow}, true},
		{"allow, unset", wafv1alpha1.GeoSpec{Allow: []wafv1alpha1.CountryCode{"DE"}}, true},
		{"allow, unknown Deny", wafv1alpha1.GeoSpec{Allow: []wafv1alpha1.CountryCode{"DE"}, Unknown: wafv1alpha1.GeoUnknownDeny}, false},
		{"deny", wafv1alpha1.GeoSpec{Deny: []wafv1alpha1.CountryCode{"RU"}, Unknown: wafv1alpha1.GeoUnknownAllow}, false},
	} {
		warnings, err := validateWAFPolicy(&wafv1alpha1.WAFPolicy{Spec: wafv1alpha1.WAFPolicySpec{Geo: &tc.geo}})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(strings.Join(warnings, "\n"), want); got != tc.warn {
			t.Errorf("%s: warned %v, want %v: %q", tc.name, got, tc.warn, warnings)
		}
	}
}
