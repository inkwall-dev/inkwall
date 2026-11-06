// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package crs runs the OWASP CRS regression test suite against Inkwall's
// standalone reverse proxy, so detection is verified through the same code
// path as production: request translation, the inspection pipeline and the
// Coraza evaluator.
//
// The harness is adapted from Coraza's (testing/coreruleset, Apache-2.0).
// It lives in its own module so go-ftw's dependencies stay out of the engine.
package crs

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	crstests "github.com/corazawaf/coraza-coreruleset/v4/tests"
	"github.com/corazawaf/coraza/v3/types"
	albedo "github.com/coreruleset/albedo/server"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog"

	"github.com/inkwall-dev/inkwall/pkg/adapters/proxy"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// testingConfig is the setup the CRS test suite expects (see the CRS
// regression test README): detection only, fixed limits, and a marker rule
// that writes the X-CRS-Test header to the log so go-ftw can find the log
// lines of each test. The README's paranoia level 4 is not set here: the
// suite runs at each level, set per transaction as for a WAFPolicy.
const testingConfig = `
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
`

// Inkwall inspects requests only (phases 1 and 2). Response rules (95x) are
// not exercised until response inspection exists.
func isResponseTest(path string) bool {
	return strings.HasPrefix(path, "RESPONSE-")
}

// ruleParanoiaLevels returns the paranoia level of each CRS rule, from its
// paranoia-level/N tag (rules without one run at every level).
func ruleParanoiaLevels(t *testing.T) map[uint]int {
	t.Helper()
	files, err := fs.Glob(coreruleset.FS, "@owasp_crs/*.conf")
	if err != nil || len(files) == 0 {
		t.Fatalf("CRS rule files: %v", err)
	}
	id := regexp.MustCompile(`id:(\d+)`)
	tag := regexp.MustCompile(`tag:'paranoia-level/(\d)'`)
	levels := map[uint]int{}
	for _, f := range files {
		conf, err := fs.ReadFile(coreruleset.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		// One directive per chunk; a chained rule's tags are in its first.
		for _, rule := range regexp.MustCompile(`(?m)^Sec`).Split(string(conf), -1) {
			m := id.FindStringSubmatch(rule)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			if pl := tag.FindStringSubmatch(rule); pl != nil {
				levels[uint(n)], _ = strconv.Atoi(pl[1])
			}
		}
	}
	if levels[942480] != 2 {
		t.Fatalf("rule 942480's paranoia level: %d, want 2", levels[942480])
	}
	return levels
}

// TestCRSRegression runs the suite at each paranoia level, set on each
// transaction (coraza.Config.ParanoiaLevel) rather than by SecLang: one
// compiled rule set serves every level, so this checks the level reaches
// the CRS. At level N, the tests of rules above N are left out (they expect
// a match the level turns off); the others must pass.
func TestCRSRegression(t *testing.T) {
	levels := ruleParanoiaLevels(t)
	tests, skipped := crsTests(t)
	// CRS tests expect albedo as the backend.
	backend := httptest.NewServer(albedo.Handler())
	defer backend.Close()
	for pl := 1; pl <= 4; pl++ {
		t.Run(fmt.Sprintf("paranoia-level-%d", pl), func(t *testing.T) {
			var run []*test.FTWTest
			left := 0
			for _, ft := range tests {
				kept := *ft
				kept.Tests = nil
				for _, tc := range ft.Tests {
					if levels[tc.RuleId] > pl {
						left++
						continue
					}
					kept.Tests = append(kept.Tests, tc)
				}
				if len(kept.Tests) > 0 {
					run = append(run, &kept)
				}
			}
			t.Logf("running %d test files at paranoia level %d, leaving out %d tests of higher levels and %d response-rule files", len(run), pl, left, skipped)
			runSuite(t, backend.URL, pl, run)
		})
	}
}

// crsTests loads the CRS regression tests, without the response rules'
// (and returns how many files those are).
func crsTests(t *testing.T) ([]*test.FTWTest, int) {
	var tests []*test.FTWTest
	skipped := 0
	err := doublestar.GlobWalk(crstests.FS, "**/*.yaml", func(path string, _ fs.DirEntry) error {
		if isResponseTest(path) {
			skipped++
			return nil
		}
		yaml, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		ftwt, err := test.GetTestFromYaml(yaml, path)
		if err != nil {
			return err
		}
		tests = append(tests, ftwt)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no tests found")
	}
	return tests, skipped
}

// runSuite runs tests through the standalone proxy at paranoia level pl.
func runSuite(t *testing.T, backendURL string, pl int, tests []*test.FTWTest) {
	logPath := filepath.Join(t.TempDir(), "error.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	var mu sync.Mutex
	logWriter := bufio.NewWriter(logFile)

	eval, err := coraza.New(coraza.Config{
		ParanoiaLevel:       pl,
		DirectivesBeforeCRS: testingConfig,
		OnMatch: func(mr types.MatchedRule) {
			mu.Lock()
			defer mu.Unlock()
			_, _ = io.WriteString(logWriter, mr.ErrorLog()+"\n")
			_ = logWriter.Flush()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream, _ := url.Parse(backendURL)
	handler, err := proxy.New(
		pipeline.New(eval, pipeline.Config{
			Mode: pipeline.ModeBlock,
			// Generous limits: this suite checks detection, not latency.
			Timeout:       10 * time.Second,
			MaxConcurrent: 1024,
		}),
		proxy.Config{
			Upstream: upstream,
			// Large enough that no CRS test body is truncated.
			MaxBodyBytes: 1 << 20,
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	engine := httptest.NewServer(handler)
	defer engine.Close()

	u, _ := url.Parse(engine.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	cfg, err := config.NewConfigFromFile(".ftw.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogFile = logPath
	cfg.TestOverride.Overrides.DestAddr = &host
	cfg.TestOverride.Overrides.Port = &port

	runnerCfg := config.NewRunnerConfiguration(cfg)
	runnerCfg.ReadTimeout = 5 * time.Second
	if err := runnerCfg.LoadPlatformOverrides(".ftw-overrides.yml"); err != nil {
		t.Fatal(err)
	}
	res, err := runner.Run(runnerCfg, tests, output.NewOutput("quiet", os.Stdout))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Stats.Ignored); n > 0 {
		t.Logf("%d ignored tests: %v", n, res.Stats.Ignored)
	}
	t.Logf("passed %d, failed %d, skipped %d, ignored %d",
		len(res.Stats.Success), len(res.Stats.Failed), len(res.Stats.Skipped), len(res.Stats.Ignored))
	if len(res.Stats.Success) == 0 {
		t.Error("no test passed")
	}
	if n := len(res.Stats.Failed); n > 0 {
		t.Errorf("%d failed tests: %v", n, res.Stats.Failed)
	}
}
