// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package monitoring checks the chart's monitoring kit against the code:
// the dashboard's queries and the alerts' expressions use metrics that
// exist (#381). promtool tests the alerts themselves (alerts_test.yaml).
package monitoring

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const kit = "../../deploy/helm/inkwall/monitoring"

var (
	registeredRE = regexp.MustCompile(`Name:\s*"(inkwall_[a-z0-9_]+)"`)
	usedRE       = regexp.MustCompile(`\binkwall_[a-z0-9_]+`)
)

// registered returns the metrics the shipped code registers.
func registered(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, root := range []string{"../../pkg", "../../operator", "../../cmd"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "test" || d.Name() == "testdata") {
				return fs.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range registeredRE.FindAllStringSubmatch(string(b), -1) {
				names[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(names) < 20 {
		t.Fatalf("found only %d metrics: the search is broken", len(names))
	}
	return names
}

// checkNames fails for each inkwall_* name in expr the code doesn't
// register (a histogram's _bucket, _count and _sum are its own).
func checkNames(t *testing.T, where, expr string, names map[string]bool) {
	t.Helper()
	for _, n := range usedRE.FindAllString(expr, -1) {
		base := n
		for _, s := range []string{"_bucket", "_count", "_sum"} {
			if b, ok := strings.CutSuffix(n, s); ok && names[b] {
				base = b
			}
		}
		if !names[base] {
			t.Errorf("%s: %s is not a metric the code registers", where, n)
		}
	}
}

func TestDashboardQueries(t *testing.T) {
	names := registered(t)
	b, err := os.ReadFile(filepath.Join(kit, "dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		UID    string `json:"uid"`
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
		Templating struct {
			List []struct {
				Definition string `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("dashboard.json: %v", err)
	}
	if d.UID == "" {
		t.Error("the dashboard has no uid")
	}
	queries := 0
	for _, p := range d.Panels {
		for _, tg := range p.Targets {
			queries++
			checkNames(t, "panel "+p.Title, tg.Expr, names)
		}
	}
	for _, v := range d.Templating.List {
		checkNames(t, "variable", v.Definition, names)
	}
	if queries < 10 {
		t.Errorf("%d queries: the dashboard didn't parse as expected", queries)
	}
}

func TestAlerts(t *testing.T) {
	names := registered(t)
	b, err := os.ReadFile(filepath.Join(kit, "alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Alert       string            `json:"alert"`
				Expr        string            `json:"expr"`
				For         string            `json:"for"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"rules"`
		} `json:"groups"`
	}
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		t.Fatalf("alerts.yaml: %v", err)
	}
	doc, err := os.ReadFile("../../docs/monitoring.md")
	if err != nil {
		t.Fatal(err)
	}
	var alerts []string
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			alerts = append(alerts, r.Alert)
			checkNames(t, r.Alert, r.Expr, names)
			if r.Labels["severity"] == "" || r.Annotations["summary"] == "" {
				t.Errorf("%s: no severity or summary", r.Alert)
			}
			// Each alert's runbook is its section of docs/monitoring.md.
			want := "https://github.com/inkwall-dev/inkwall/blob/main/docs/monitoring.md#" + strings.ToLower(r.Alert)
			if r.Annotations["runbook_url"] != want {
				t.Errorf("%s: runbook_url %q, want %q", r.Alert, r.Annotations["runbook_url"], want)
			}
			if !strings.Contains(string(doc), "\n### "+r.Alert+"\n") {
				t.Errorf("%s: no section in docs/monitoring.md", r.Alert)
			}
		}
	}
	if len(alerts) == 0 || slices.Contains(alerts, "") {
		t.Fatalf("alerts %q", alerts)
	}
	// Every alert has a unit test.
	tests, err := os.ReadFile("alerts_test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if !strings.Contains(string(tests), "alertname: "+a+"\n") {
			t.Errorf("%s has no promtool test in alerts_test.yaml", a)
		}
	}
}
