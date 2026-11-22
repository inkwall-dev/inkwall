// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// A geo event: the client's country, and the requests of the country the
// sampled event stands for; any event: the country, when the engine held a
// table.
func TestExplainRequestGeo(t *testing.T) {
	policy := writeFile(t, "policy.yaml", `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: storefront, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: storefront}]
  mode: Block
  geo: {deny: [RU]}
`)
	log := writeFile(t, "engine.log", `{"time":"2026-11-21T10:00:00Z","level":"WARN","msg":"security event","phase":"request","status":403,"client_ip":"198.51.100.7","method":"GET","host":"shop.example.com","policy":"shop/storefront","action":"deny","reason":"geo-deny","country":"RU","sampled_count":12,"path":"/","request_id":"req-geo"}
`)
	_, out, _ := runCLI(t, "explain", "request", "--file", log, "--policy", policy, "--ingress", "testdata/policy/ingress.yaml", "-o", "json", "req-geo")
	var re RequestExplanation
	if err := json.Unmarshal([]byte(out), &re); err != nil || len(re.Events) != 1 {
		t.Fatalf("%v: %s", err, out)
	}
	if ev := re.Events[0]; ev.Request.Country != "RU" || ev.GeoSampled != 12 || ev.Reason != "geo-deny" {
		t.Errorf("event %+v", ev)
	}
	_, text, _ := runCLI(t, "explain", "request", "--file", log, "--policy", policy, "--ingress", "testdata/policy/ingress.yaml", "req-geo")
	for _, want := range []string{"Country: RU", "stands for 12 requests of the country"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

func TestExplainPolicyGeo(t *testing.T) {
	for _, tc := range []struct {
		geo  *wafv1alpha1.GeoSpec
		want string
	}{
		{&wafv1alpha1.GeoSpec{Deny: []wafv1alpha1.CountryCode{"RU", "KP"}}, "Geo: denies RU, KP\n"},
		{&wafv1alpha1.GeoSpec{Allow: []wafv1alpha1.CountryCode{"DE"}, Unknown: wafv1alpha1.GeoUnknownDeny, Mode: wafv1alpha1.GeoModeDetect},
			"Geo: allows only DE; denies addresses of no country (Detect: logs only)\n"},
	} {
		p := failingPolicy("", "", "")
		p.Spec.Geo = tc.geo
		ec, _ := explainTestCluster(t, p)
		withExplainCluster(t, ec)
		_, out, errOut := runCLI(t, "explain", "policy", "shop/web")
		if !strings.Contains(out, tc.want) {
			t.Errorf("explain policy lacks %q: %s%s", tc.want, out, errOut)
		}
	}
}
