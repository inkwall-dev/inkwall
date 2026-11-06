// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

func TestSplitDirectives(t *testing.T) {
	in := strings.Join([]string{
		"# a comment",
		"",
		`SecRule ARGS "@rx a" "id:1,phase:1,deny"`,
		`  SecRule ARGS:x "@rx b" \`,
		`    "id:2,phase:1,\`,
		`    deny"`,
		"SecMarker END",
	}, "\n")
	got, err := SplitDirectives(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []Directive{
		{Line: 3, Name: "secrule", Text: `SecRule ARGS "@rx a" "id:1,phase:1,deny"`},
		{Line: 4, Name: "secrule", Text: `SecRule ARGS:x "@rx b" "id:2,phase:1,deny"`},
		{Line: 7, Name: "secmarker", Text: "SecMarker END"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d directives: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("directive %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	for _, bad := range []string{"SecRule ARGS \"@rx a\" \\", "SecDataset x `\na\n"} {
		var re *RuleError
		if _, err := SplitDirectives(bad); !errors.As(err, &re) || re.Line != 1 {
			t.Errorf("%q: got %v, want a RuleError at line 1", bad, err)
		}
	}
}

func TestCheckUserRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules string
		// wantLine is the line the error must name; 0 means no error.
		wantLine int
		wantErr  string
	}{
		{name: "empty"},
		{name: "a rule", rules: `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100001,phase:1,deny,status:403"`},
		// Exclusions refer to CRS rules: they only compile after CRS, as
		// the engine loads them.
		{name: "CRS exclusions", rules: "SecRuleRemoveById 920350\nSecRuleUpdateTargetById 942100 \"!ARGS:q\"\nSecRuleRemoveByTag attack-protocol"},
		{name: "a chain", rules: "SecRule ARGS \"@rx a\" \"id:100002,phase:2,deny,chain\"\nSecRule ARGS \"@rx b\" \"t:none\""},
		{
			name:     "unknown operator",
			rules:    "SecRule ARGS \"@rx a\" \"id:100003,phase:1,deny\"\n\n# fine so far\nSecRule ARGS \"@nosuchop a\" \"id:100004,phase:1,deny\"\nSecMarker END",
			wantLine: 4, wantErr: `operator "nosuchop" is not allowed`,
		},
		{
			name:     "missing rule",
			rules:    "SecRuleRemoveById 920350\nSecRuleUpdateTargetById 999998 \"!ARGS:q\"",
			wantLine: 2, wantErr: `rule "999998" not found`,
		},
		{
			name:     "duplicate id",
			rules:    "SecAction \"id:100005,phase:1,pass,nolog\"\nSecAction \"id:100005,phase:1,pass,nolog\"",
			wantLine: 2, wantErr: "100005",
		},
		{
			name:     "an id CRS uses",
			rules:    `SecAction "id:942100,phase:1,pass,nolog"`,
			wantLine: 1, wantErr: "942100",
		},
		{
			name:     "error after a chain",
			rules:    "SecRule ARGS \"@rx a\" \"id:100007,phase:2,deny,chain\"\nSecRule ARGS \"@rx b\" \"t:none\"\nSecRule ARGS \"@nosuchop a\" \"id:100008,phase:1,deny\"",
			wantLine: 3, wantErr: `operator "nosuchop" is not allowed`,
		},
		{name: "negated operator", rules: `SecRule ARGS "!@within a b" "id:100009,phase:1,deny"`},
		{name: "default operator", rules: `SecRule ARGS "^a$" "id:100010,phase:1,deny"`},
		{name: "escaped quote", rules: `SecRule ARGS "@rx a\"b" "id:100011,phase:1,deny"`},
		// Operators that reach outside the engine: inspectFile runs a
		// program, rbl queries DNS.
		{
			name:     "inspectFile",
			rules:    "SecRule ARGS \"@rx a\" \"id:100012,phase:1,deny\"\nSecRule ARGS:f \"@inspectFile /usr/bin/touch\" \"id:100013,phase:1,pass,nolog\"",
			wantLine: 2, wantErr: `operator "inspectFile" is not allowed`,
		},
		{name: "negated inspectFile", rules: `SecRule ARGS:f "!@inspectFile /bin/true" "id:100014,phase:1,pass"`, wantLine: 1, wantErr: `operator "inspectFile" is not allowed`},
		{name: "rbl", rules: `SecRule REMOTE_ADDR "@rbl attacker.example" "id:100015,phase:1,pass"`, wantLine: 1, wantErr: `operator "rbl" is not allowed`},
		{name: "rbl in a chain", rules: "SecRule ARGS \"@rx a\" \"id:100016,phase:1,deny,chain\"\nSecRule REMOTE_ADDR \"@rbl attacker.example\" \"t:none\"", wantLine: 2, wantErr: `operator "rbl" is not allowed`},
		{name: "engine switch", rules: "SecRuleEngine Off", wantLine: 1, wantErr: `directive "secruleengine" is not allowed`},
		{name: "audit log file", rules: "SecRule ARGS \"@rx a\" \"id:100006,phase:1,deny\"\nSecAuditLog /tmp/audit.log", wantLine: 2, wantErr: `directive "secauditlog" is not allowed`},
		{name: "include", rules: "Include @owasp_crs/REQUEST-901-INITIALIZATION.conf", wantLine: 1, wantErr: `directive "include" is not allowed`},
		{name: "body limit", rules: "secrequestbodylimit 1", wantLine: 1, wantErr: `directive "secrequestbodylimit" is not allowed`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckUserRules(tc.rules)
			if tc.wantLine == 0 {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			var re *RuleError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want a RuleError", err)
			}
			if re.Line != tc.wantLine || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %q, want line %d and %q", err, tc.wantLine, tc.wantErr)
			}
			if strings.Contains(err.Error(), "invalid WAF config") {
				t.Errorf("error keeps Coraza's wrapping: %q", err)
			}
		})
	}
}

// The error in a large rule set is still located exactly. It takes about
// 10 compiles (~150ms without the race detector), well within the
// webhook's 2s timeout.
func TestCheckUserRulesLarge(t *testing.T) {
	var b strings.Builder
	for i := range 500 {
		b.WriteString("SecRule ARGS \"@rx a\" \"id:")
		b.WriteString(strconv.Itoa(110000 + i))
		b.WriteString(",phase:1,deny\"\n")
	}
	b.WriteString("SecRule ARGS \"@nosuchop a\" \"id:120000,phase:1,deny\"\n")
	start := time.Now()
	err := CheckUserRules(b.String())
	var re *RuleError
	if !errors.As(err, &re) || re.Line != 501 {
		t.Fatalf("got %v, want a RuleError at line 501", err)
	}
	t.Logf("located in %v", time.Since(start))
}

func TestCRSRuleIDs(t *testing.T) {
	ids, err := CRSRuleIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{920350, 942100, 949110} {
		if !slices.Contains(ids, id) {
			t.Errorf("no rule %d in %d CRS rules", id, len(ids))
		}
	}
	if !slices.IsSorted(ids) || ids[0] < crsIDMin || ids[len(ids)-1] > crsIDMax {
		t.Errorf("ids not sorted or outside the CRS range: %d..%d", ids[0], ids[len(ids)-1])
	}
}

// inspectFile and rbl never run in the engine, whatever reaches it without
// CheckUserRules (rule sets accepted before it rejected them, hand-made
// bundles): they compile, so such a bundle still loads, but never match,
// and inspectFile runs no program.
func TestDisabledOperators(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	for id, rule := range map[int]string{
		100020: `SecRule ARGS:f "@inspectFile /usr/bin/touch" "id:100020,phase:1,deny,status:403"`,
		100021: `SecRule REMOTE_ADDR "@rbl attacker.example" "id:100021,phase:1,deny,status:403"`,
	} {
		for _, cfg := range []Config{{Directives: rule}, {DirectivesBeforeCRS: rule}, {Directives: rule, DisableCRS: true}} {
			e, err := New(cfg)
			if err != nil {
				t.Fatalf("%s: %v", rule, err)
			}
			req := &request.Request{Method: "GET", RawURI: "/?f=" + url.QueryEscape(marker), Proto: "HTTP/1.1", Host: "a.example",
				Headers: http.Header{"User-Agent": {"curl/8"}, "Accept": {"*/*"}}, PeerIP: netip.MustParseAddr("127.0.0.1")}
			res, err := e.Evaluate(context.Background(), req)
			if err != nil || slices.Contains(res.MatchedRuleIDs, id) {
				t.Errorf("%s: matched %v (%v), want no match", rule, res.MatchedRuleIDs, err)
			}
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("inspectFile ran a program")
	}
}

// Every operator the CRS uses stays allowed, so rules copied from it check.
func TestUserOperatorsCoverCRS(t *testing.T) {
	n := 0
	err := fs.WalkDir(coreruleset.FS, "@owasp_crs", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
			return err
		}
		b, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}
		dirs, err := SplitDirectives(string(b))
		if err != nil {
			return err
		}
		for _, d := range dirs {
			if d.Name != "secrule" {
				continue
			}
			n++
			op, ok := ruleOperator(d.Text)
			if !ok || !userOperators[op] {
				t.Errorf("%s:%d: operator %q (parsed %v) is not allowed", path, d.Line, op, ok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 500 {
		t.Fatalf("checked %d CRS rules, want all of them", n)
	}
}
