// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package reasons

import (
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

var update = flag.Bool("update", false, "rewrite docs/troubleshooting.md's reason tables from the entries")

// guide is the troubleshooting guide, from this package's directory.
const guide = "../../docs/troubleshooting.md"

// reasonRE is hack/docscheck's: the operator's Reason* constants.
var reasonRE = regexp.MustCompile(`\bReason[A-Za-z0-9]*\s*=\s*"([A-Za-z]+)"`)

// Every condition reason the operator sets has an entry, so inkwallctl
// explain can say what it means and what to do (#438).
func TestEveryOperatorReasonHasAnEntry(t *testing.T) {
	defined := map[string]string{}
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(p) != ".go" || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 -- the repository's own files
		if err != nil {
			return err
		}
		for _, m := range reasonRE.FindAllStringSubmatch(string(b), -1) {
			defined[m[1]] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(defined) < 40 {
		t.Fatalf("found %d condition reasons in operator/: is the walk broken?", len(defined))
	}
	// Ready's reason while a condition isn't reported yet
	// (distribution.Ready: "Not" + the condition).
	for _, c := range []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced} {
		defined["Not"+c] = "operator/internal/distribution/status.go"
	}
	for reason, file := range defined {
		if !slices.ContainsFunc(entries, func(e Entry) bool {
			return e.Reason == reason && (e.Kind == KindWAFPolicy || e.Kind == KindInkwallConfig)
		}) {
			t.Errorf("condition reason %s (%s) has no entry in operator/reasons: add what it means and the fix", reason, file)
		}
	}
}

// Every reason a security event can give has an entry.
func TestEveryEventReasonHasAnEntry(t *testing.T) {
	// Verdicts with these reasons are never security events
	// (httpadapter.IsEvent).
	notEvents := []pipeline.Reason{pipeline.ReasonNone, pipeline.ReasonCanceled, pipeline.ReasonSkipped,
		pipeline.ReasonNoPolicy, pipeline.ReasonSuspended, pipeline.ReasonIPAllow}
	for r := pipeline.Reason(0); r < 64; r++ {
		if r.String() == "unknown" || slices.Contains(notEvents, r) {
			continue
		}
		if _, ok := Lookup(KindSecurityEvent, "reason", r.String()); !ok {
			t.Errorf("security event reason %q has no entry in operator/reasons", r)
		}
	}
}

func TestEntriesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range entries {
		key := e.Kind + "/" + e.Condition + "/" + e.Reason
		if seen[key] {
			t.Errorf("%s: two entries", key)
		}
		seen[key] = true
		if e.Kind == "" || e.Condition == "" || e.Reason == "" || e.Meaning == "" {
			t.Errorf("%s: kind, condition, reason and meaning are required", key)
		}
		for _, s := range []string{e.Meaning, e.Fix} {
			if strings.Contains(s, "|") || strings.Contains(s, "\n") {
				t.Errorf("%s: a | or a line break would break the guide's table: %q", key, s)
			}
		}
	}
}

// markerRE finds a reason table of the guide: its kind and condition, and
// the table rendered between the markers.
var markerRE = regexp.MustCompile(`(?s)<!-- reasons: (\w+)(?: (\w+))? -->\n(.*?)<!-- end reasons -->`)

// The guide's reason tables are the entries' (one source for the guide and
// inkwallctl explain). go test ./operator/reasons -update rewrites them.
func TestGuideTablesMatchEntries(t *testing.T) {
	b, err := os.ReadFile(guide)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	rendered := map[string]bool{}
	out := markerRE.ReplaceAllStringFunc(doc, func(block string) string {
		m := markerRE.FindStringSubmatch(block)
		kind, condition, table := m[1], m[2], m[3]
		want := Table(kind, condition)
		rendered[strings.TrimSpace(kind+" "+condition)] = true
		if table != want && !*update {
			t.Errorf("%s: the table of %s %s isn't the entries' (go test ./operator/reasons -update rewrites it):\n got:\n%s\nwant:\n%s", guide, kind, condition, table, want)
		}
		head, _, _ := strings.Cut(block, "\n")
		return head + "\n" + want + "<!-- end reasons -->"
	})
	for _, e := range entries {
		key := e.Kind + " " + e.Condition
		if e.Kind == KindInkwallConfig {
			key = e.Kind
		}
		if !rendered[key] {
			t.Errorf("%s: no table for %s %s: add <!-- reasons: %s --> ... <!-- end reasons -->", guide, e.Kind, e.Condition, key)
			rendered[key] = true
		}
	}
	if *update && out != doc {
		if err := os.WriteFile(guide, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestText(t *testing.T) {
	for _, tc := range [][2]string{
		{"see [Bundle limit](monitoring.md#inkwallbundlenearsizelimit).", "see Bundle limit (docs/monitoring.md#inkwallbundlenearsizelimit)."},
		{"[the chart](../deploy/helm/inkwall/README.md)", "the chart (deploy/helm/inkwall/README.md)"},
		{"[above](#conditions)", "above (docs/troubleshooting.md#conditions)"},
		{"[MCP](https://modelcontextprotocol.io/)", "MCP (https://modelcontextprotocol.io/)"},
		{"no link, `code`", "no link, `code`"},
	} {
		if got := Text(tc[0]); got != tc[1] {
			t.Errorf("Text(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
}
