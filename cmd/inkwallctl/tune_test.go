// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func readTuneFile(t *testing.T, name string, fromLogs bool) []tuneEvent {
	t.Helper()
	f, err := os.Open("testdata/tune/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs, err := readTuneEvents(f, fromLogs)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// The report and the exclusions for a sample of engine logs (#383).
func TestTuneReport(t *testing.T) {
	code, out, errOut := runCLI(t, "tune", "--from-logs", "testdata/tune/engine.log")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "tune/report.golden", out)
	code, out, _ = runCLI(t, "tune", "--from-logs", "-o", "yaml", "testdata/tune/engine.log")
	if code != 0 {
		t.Fatalf("yaml: exit %d", code)
	}
	golden(t, "tune/exclusions.golden", out)
}

// With the policies, the suggestions are validated as inkwallctl test
// --policy does, and the policies come back patched.
func TestTunePolicies(t *testing.T) {
	code, out, errOut := runCLI(t, "tune", "--from-logs", "-o", "yaml",
		"--policy", "testdata/policy/wafpolicy.yaml", "--rule-set", "testdata/policy/wafruleset.yaml",
		"--configmap", "testdata/policy/configmap.yaml", "--ingress", "testdata/policy/ingress.yaml",
		"testdata/tune/engine.log")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "tune/patched.golden", out)
}

// Suggestions are never broader than the evidence: the exact path, never
// a prefix nor every path; the variable's own field; nothing for what no
// field can name, unless --broad, and then only on the path.
func TestTuneNarrow(t *testing.T) {
	evs := readTuneFile(t, "engine.log", true)
	for _, broad := range []bool{false, true} {
		rep := tune(evs, broad, 1)
		for p, exs := range rep.Suggestions {
			for _, ex := range exs {
				if ex.When == nil || ex.When.Path == "" || strings.HasSuffix(string(ex.When.Path), "*") {
					t.Errorf("broad %t, %s: %+v is not on one exact path", broad, p, ex)
				}
				if slices.Contains(ex.RuleIDs, 949110) {
					t.Errorf("the anomaly score rule excluded: %+v", ex)
				}
			}
		}
		storefront := rep.Suggestions["shop/storefront"]
		has := func(path string, w wafv1alpha1.ExclusionMatch) bool {
			w.Path = wafv1alpha1.PathPattern(path)
			return slices.ContainsFunc(storefront, func(ex wafv1alpha1.Exclusion) bool { return *ex.When == w })
		}
		if !has("/search", wafv1alpha1.ExclusionMatch{Argument: "q"}) || !has("/account", wafv1alpha1.ExclusionMatch{Cookie: "session_hint"}) ||
			!has("/account", wafv1alpha1.ExclusionMatch{Header: "Referer"}) || !has("/api/import", wafv1alpha1.ExclusionMatch{ArgumentName: "select"}) {
			t.Errorf("broad %t: suggestions %+v", broad, storefront)
		}
		if got := has("/upload", wafv1alpha1.ExclusionMatch{}); got != broad {
			t.Errorf("broad %t: a rule off on /upload for every variable: %t", broad, got)
		}
		for _, ex := range storefront {
			if strings.Contains(string(ex.When.Path), ";") || ex.When.Argument == "q text" {
				t.Errorf("unrepresentable suggestion %+v", ex)
			}
		}
	}

	// The two rules on /search's q share one exclusion.
	rep := tune(evs, false, 1)
	for _, ex := range rep.Suggestions["shop/storefront"] {
		if ex.When.Argument == "q" && !slices.Equal(ex.RuleIDs, []int32{942100, 942430}) {
			t.Errorf("q's exclusion: %v", ex.RuleIDs)
		}
	}
	// --min-count leaves out what was seen once.
	rep = tune(evs, false, 2)
	if exs := rep.Suggestions["shop/storefront"]; len(exs) != 1 || !slices.Equal(exs[0].RuleIDs, []int32{942100}) {
		t.Errorf("--min-count 2: %+v", exs)
	}
	// Detect mode's logged requests are what Block mode would deny.
	if rep.WouldDeny["shop/storefront"] != 13 || rep.WouldDeny["shop/api"] != 0 {
		t.Errorf("would deny %v", rep.WouldDeny)
	}
}

// Events from the events API, protojson's names, read as log lines are.
func TestTuneEventsFile(t *testing.T) {
	evs := readTuneFile(t, "events.jsonl", false)
	if len(evs) != 1 || evs[0].Action != "log" || evs[0].Reason != "rule" || evs[0].RequestID != "e-1" || evs[0].ClientIP != "203.0.113.1" ||
		len(evs[0].Matches) != 1 || evs[0].Matches[0] != (tuneMatch{942100, "ARGS:q"}) {
		t.Fatalf("events %+v", evs)
	}
	if code, _, _ := runCLI(t, "tune"); code != 2 {
		t.Error("no file: want exit 2")
	}
	if code, _, _ := runCLI(t, "tune", "testdata/tune/engine.log"); code != 2 {
		t.Error("a log read as events: want exit 2")
	}
}

// Only the anomaly score's rules are score rules: 921180 matches a TX
// variable too, its argument counter (#764).
func TestScoreRule(t *testing.T) {
	for _, tt := range []struct {
		id       int
		variable string
		want     bool
	}{
		{949110, "TX:blocking_inbound_anomaly_score", true},
		{959100, "TX:blocking_outbound_anomaly_score", true},
		{980170, "", true},
		{100001, "TX:anomaly_score", true},
		{100002, "TX:inbound_anomaly_score_pl1", true},
		{921180, "TX:paramcounter_args_names:fields[]", false},
		{942100, "ARGS:q", false},
		{100003, "TX:my_flag", false},
	} {
		if got := scoreRule(tt.id, tt.variable); got != tt.want {
			t.Errorf("scoreRule(%d, %q) = %t, want %t", tt.id, tt.variable, got, tt.want)
		}
	}
}

// 921180 (HTTP parameter pollution) is reported, and excluded through 921170,
// the counter of the argument it checks: an exclusion of 921180 for the
// argument name wouldn't stop it. The suggestions let Directus's request
// through (#764).
func TestTuneParameterPollution(t *testing.T) {
	const query = "/items/articles?limit=25&fields[]=id&fields[]=title&sort[]=-date_created"
	events := writeFile(t, "events.jsonl", `{"action":"ACTION_DENY","reason":"REASON_RULE","policy":"default/directus","path":"/items/articles","request_id":"req-1",`+
		`"matches":[{"rule_id":921180,"variable":"TX:paramcounter_args_names:fields[]"},{"rule_id":932350,"variable":"ARGS:fields[]"},`+
		`{"rule_id":949110,"variable":"TX:blocking_inbound_anomaly_score"}]}`+"\n")
	code, out, errOut := runCLI(t, "tune", events)
	if code != 0 || !strings.Contains(out, "921180@TX:paramcounter_args_names:fields[] on /items/articles") ||
		!strings.Contains(out, "excluded as rule 921170") || !strings.Contains(out, "rules 921170, on /items/articles, for argument name fields[]") {
		t.Fatalf("exit %d, output %q %q", code, out, errOut)
	}

	policy := writeFile(t, "policy.yaml", `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: directus, namespace: default}
spec:
  targetRefs: [{kind: Ingress, name: app}]
  mode: Block
  ruleSets:
    - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
      paranoiaLevel: 3
`)
	ruleSet := "../../operator/config/samples/clusterwafruleset.yaml"
	if code, out, _ := runCLI(t, "test", "--policy", policy, "--rule-set", ruleSet, "--expect", "deny", "http://directus.example.com"+query); code != 0 {
		t.Fatalf("without the suggestions: exit %d, output %q", code, out)
	}
	code, out, errOut = runCLI(t, "tune", "-o", "yaml", "--policy", policy, "--rule-set", ruleSet, events)
	if code != 0 {
		t.Fatalf("tune --policy: exit %d: %s", code, errOut)
	}
	patched := writeFile(t, "patched.yaml", out)
	if code, out, _ := runCLI(t, "test", "--policy", patched, "--rule-set", ruleSet, "--expect", "allow", "http://directus.example.com"+query); code != 0 {
		t.Fatalf("with the suggestions: exit %d, output %q", code, out)
	}
}

// A rule ID out of int32's range (the bundle's type) is no rule: it isn't
// wrapped into another rule's ID.
func TestTuneRuleIDRange(t *testing.T) {
	in := `{"policy":"shop/web","path":"/search","action":"ACTION_LOG","reason":"REASON_RULE","matches":[{"ruleId":"4294968238","variable":"ARGS:q"},{"ruleId":"942100","variable":"ARGS:q"}]}` + "\n"
	evs, err := readTuneEvents(strings.NewReader(in), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || len(evs[0].Matches) != 2 || evs[0].Matches[0].RuleID != 0 || evs[0].Matches[1].RuleID != 942100 {
		t.Fatalf("matches %+v, want the out-of-range ID read as 0 (no rule)", evs[0].Matches)
	}
}
