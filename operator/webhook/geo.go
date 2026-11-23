// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// isoCountries are the ISO 3166-1 alpha-2 codes officially assigned, and XK
// (Kosovo), which the databases use. The CRD takes any two upper-case
// letters, since custom databases use others (XA to XZ) and the list
// changes; the webhook warns of the rest (design 0011 §2.4).
var isoCountries = func() map[string]bool {
	const codes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
		"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
		"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
		"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
		"MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
		"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
		"UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK"
	m := map[string]bool{}
	for _, c := range strings.Fields(codes) {
		m[c] = true
	}
	return m
}()

// geoWarnings warns of a policy's country codes that aren't assigned: UK
// and EU, the likely mistakes, with their own messages.
func geoWarnings(p *wafv1alpha1.WAFPolicy) admission.Warnings {
	g := p.Spec.Geo
	if g == nil {
		return nil
	}
	var warnings admission.Warnings
	check := func(path *field.Path, codes []wafv1alpha1.CountryCode) {
		for i, c := range codes {
			switch s := string(c); {
			case s == "UK":
				warnings = append(warnings, fmt.Sprintf("%s: UK is not an ISO 3166-1 country code; the United Kingdom is GB", path.Index(i)))
			case s == "EU":
				warnings = append(warnings, fmt.Sprintf("%s: EU is not a country; databases give each member state's code (DE, FR, ...), list those", path.Index(i)))
			case !isoCountries[s]:
				warnings = append(warnings, fmt.Sprintf("%s: %s is not an assigned ISO 3166-1 country code: only a custom database gives it", path.Index(i), s))
			}
		}
	}
	geo := field.NewPath("spec", "geo")
	check(geo.Child("deny"), g.Deny)
	check(geo.Child("allow"), g.Allow)
	return warnings
}
