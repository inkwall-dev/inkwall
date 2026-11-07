// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package crs runs the OWASP CRS regression test suite through Inkwall's
// adapters, so detection is verified through the same code paths as
// production: each adapter's request translation, the inspection pipeline
// and the Coraza evaluator. The reverse proxy runs it at each paranoia
// level; ForwardAuth, ext_proc and SPOE, through a stand-in for their
// proxy (fronts_test.go), at level 4, and ext_proc also the response
// rules' tests. A test that passes through the reverse proxy must pass
// through every adapter, but for the differences listed with a reason.
//
// The harness is adapted from Coraza's (testing/coreruleset, Apache-2.0).
// It lives in its own module so go-ftw's dependencies stay out of the engine.
package crs

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// testingConfig is the setup the CRS test suite expects (see the CRS
// regression test README): detection only, fixed limits, and a marker rule
// that writes the X-CRS-Test header to the log so go-ftw can find the log
// lines of each test. The README's paranoia level 4 is not set here: the
// suite runs at each level, set per transaction as for a WAFPolicy.
//
// Coraza logs a response or reporting rule's match only with a default
// action that logs for phases 3 to 5, which the CRS's setup doesn't set
// (ModSecurity's does): without it, the response rules' tests find nothing
// in the log.
const testingConfig = `
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"

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

// isResponseTest reports a test of the response rules (95x): they run
// through the adapters that inspect responses (ext_proc).
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
	tests, skipped := crsTests(t, false)
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
			t.Logf("running %d test files at paranoia level %d, leaving out %d tests of higher levels and %d response-rule files (the reverse proxy inspects requests only)", len(run), pl, left, skipped)
			failed := runSuite(t, proxyAdapter, backend.URL, pl, run)
			if n := len(failed); n > 0 {
				t.Errorf("%d failed tests: %v", n, slices.Sorted(maps.Keys(failed)))
			}
		})
	}
}

// adapter is one way a proxy asks the engine: its front (fronts_test.go),
// and whether it inspects responses.
type adapter struct {
	name      string
	front     func(*testing.T, pipeline.ExchangeInspector, *url.URL) http.Handler
	responses bool
}

var proxyAdapter = adapter{"proxy", proxyFront, false}

// The other adapters, through a stand-in for their proxy (fronts_test.go).
var otherAdapters = []adapter{
	{"forwardauth", forwardAuthFront, false},
	{"extproc", extProcFront, true},
	{"spoe", spoeFront, false},
}

// differences are the tests an adapter fails while the reverse proxy
// passes them, by adapter and test ID, each with its reason. Any other
// failure fails the suite, and so does a listed one that passes.
var differences = map[string]map[string]string{
	"forwardauth": {
		"920180-1": emptyPost,
		"920180-3": emptyPost,
		"920181-1": "Traefik's subrequest carries its own Content-Length and Transfer-Encoding for the forwarded body, not the client's",
	},
	"extproc": {
		"920180-1": emptyPost,
		"920180-3": emptyPost,
		"920280-1": noAuthority,
		"920290-1": noAuthority,
		"920290-4": noAuthority,
	},
	"spoe": {
		"920180-1": emptyPost,
		"920180-3": emptyPost,
	},
}

const (
	emptyPost   = "an empty POST, PUT or PATCH without Content-Length gets Content-Length: 0 from the adapter (rule 920180 would score every empty POST from HTTP/2 clients and Traefik, which leave it out)"
	noAuthority = "Envoy answers a request without a Host (or with an empty one) itself, so ext_proc always has an :authority: the stand-in sends what Envoy never would"
)

// TestCRSAdapters runs the suite at paranoia level 4 (every test) through
// each other adapter, and the response rules' tests through the ones that
// inspect responses: a test the reverse proxy passes (TestCRSRegression)
// must pass through every adapter, but for the listed differences.
func TestCRSAdapters(t *testing.T) {
	backend := httptest.NewServer(albedo.Handler())
	defer backend.Close()
	for _, a := range otherAdapters {
		t.Run(a.name, func(t *testing.T) {
			tests, _ := crsTests(t, a.responses)
			t.Logf("%s: running %d test files at paranoia level 4 (response rules: %t)", a.name, len(tests), a.responses)
			failed := runSuite(t, a, backend.URL, 4, tests)
			var unexpected []string
			for id := range failed {
				if _, ok := differences[a.name][id]; !ok {
					unexpected = append(unexpected, id)
				}
			}
			slices.Sort(unexpected)
			if len(unexpected) > 0 {
				t.Errorf("%s: %d tests fail through it but pass through the reverse proxy (list a reason in differences if expected): %v", a.name, len(unexpected), unexpected)
			}
			for id, reason := range differences[a.name] {
				if !failed[id] {
					t.Errorf("%s: %s is a listed difference (%s) but passes: remove it", a.name, id, reason)
				}
			}
		})
	}
}

// crsTests loads the CRS regression tests, the response rules' only with
// responses (and returns how many files it left out).
func crsTests(t *testing.T, responses bool) ([]*test.FTWTest, int) {
	var tests []*test.FTWTest
	skipped := 0
	err := doublestar.GlobWalk(crstests.FS, "**/*.yaml", func(path string, _ fs.DirEntry) error {
		if isResponseTest(path) && !responses {
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
		// go-ftw stops the whole run on a retry_once test that fails
		// twice; the log is flushed on every match here, so the race it
		// works around doesn't happen, and a failure is recorded as any
		// other.
		for i := range ftwt.Tests {
			for j := range ftwt.Tests[i].Stages {
				ftwt.Tests[i].Stages[j].Output.RetryOnce = nil
			}
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

// runSuite runs tests through an adapter at paranoia level pl, and returns
// the IDs of those that failed.
func runSuite(t *testing.T, a adapter, backendURL string, pl int, tests []*test.FTWTest) map[string]bool {
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
	cfg := pipeline.Config{
		Mode: pipeline.ModeBlock,
		// Generous limits: this suite checks detection, not latency.
		Timeout:       10 * time.Second,
		MaxConcurrent: 1024,
	}
	if a.responses {
		cfg.Responses = pipeline.ResponseConfig{Inspect: true, MaxBytes: maxBody}
	}
	engine := httptest.NewServer(a.front(t, pipeline.New(eval, cfg), upstream))
	defer engine.Close()

	u, _ := url.Parse(engine.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ftwCfg, err := config.NewConfigFromFile(".ftw.yml")
	if err != nil {
		t.Fatal(err)
	}
	ftwCfg.LogFile = logPath
	ftwCfg.TestOverride.Overrides.DestAddr = &host
	ftwCfg.TestOverride.Overrides.Port = &port

	runnerCfg := config.NewRunnerConfiguration(ftwCfg)
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
	t.Logf("%s: passed %d, failed %d, skipped %d, ignored %d", a.name,
		len(res.Stats.Success), len(res.Stats.Failed), len(res.Stats.Skipped), len(res.Stats.Ignored))
	if len(res.Stats.Success) == 0 {
		t.Error("no test passed")
	}
	failed := map[string]bool{}
	for _, id := range res.Stats.Failed {
		failed[id] = true
	}
	return failed
}
