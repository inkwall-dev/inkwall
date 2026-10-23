// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command inkwallctl is the Inkwall command-line tool.
//
// Usage:
//
//	inkwallctl test [flags] URL
//	inkwallctl test [flags] --request FILE
//	inkwallctl test [flags] --har FILE
//
// The test subcommand shows the verdict and the matching rules for one or
// more requests, without sending them anywhere. A request is given like a
// curl command line (URL, -X, -H, -d), as raw HTTP in a file, or as a HAR
// file exported from a browser. By default the requests are inspected
// in-process with the OWASP Core Rule Set embedded in inkwallctl, the same
// code the engine runs; with --engine they are sent to a running engine's
// check API (inkwall-engine check).
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "test" && args[0] != "bench") {
		fmt.Fprintln(stderr, "usage: inkwallctl test [flags] URL")
		fmt.Fprintln(stderr, "       inkwallctl test [flags] --request FILE | --har FILE")
		fmt.Fprintln(stderr, "       inkwallctl bench [flags] [--request FILE | --har FILE]")
		fmt.Fprintln(stderr, "run 'inkwallctl <command> -h' for flags")
		return 2
	}
	var (
		cfg config
		err error
	)
	if args[0] == "test" {
		cfg, err = parseTestFlags(args[1:], stderr)
	} else {
		cfg, err = parseBenchFlags(args[1:], stderr)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if args[0] == "test" {
		return runTest(cfg, stdout, stderr)
	}
	return runBench(cfg, stdout, stderr)
}

// headerList collects repeated -H flags.
type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

type config struct {
	// Input: at most one of url, requestFile, harFile.
	url         string
	method      string
	headers     headerList
	data        string
	requestFile string
	harFile     string

	// Where requests are checked: a running engine, or in-process with the
	// rest of these settings.
	engine        string
	mode          pipeline.Mode
	timeout       time.Duration
	maxBodyBytes  int64
	paranoiaLevel int
	threshold     int
	rules         string
	rulesBefore   string
	disabled      []string

	// test
	expect string
	// test: one CheckResponse per line; bench: the report.
	json bool

	// bench
	duration    time.Duration
	warmup      time.Duration
	concurrency int
	rate        float64
}

// flagSet registers the flags test and bench share. finish validates them
// after parsing.
type flagSet struct {
	*flag.FlagSet
	cfg      *config
	mode     *string
	disabled *string
}

func newFlagSet(name string, cfg *config, stderr io.Writer, inputHelp string) flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.method, "X", "", "request method (default GET, or POST with -d)")
	fs.Var(&cfg.headers, "H", `request header "Name: value" (repeatable)`)
	fs.StringVar(&cfg.data, "d", "", "request body; @file reads it from a file")
	fs.StringVar(&cfg.requestFile, "request", "", "file with one or more raw HTTP/1.1 requests"+inputHelp)
	fs.StringVar(&cfg.harFile, "har", "", "HAR file"+inputHelp)
	fs.StringVar(&cfg.engine, "engine", "", "check API of a running engine (http://127.0.0.1:9002 or unix:/path); default is in-process")
	mode := fs.String("mode", "block", "enforcement mode for in-process checks: block or detect")
	fs.Int64Var(&cfg.maxBodyBytes, "max-body-bytes", 64<<10, "request body bytes to inspect, in-process")
	fs.IntVar(&cfg.paranoiaLevel, "paranoia-level", coraza.DefaultParanoiaLevel, "OWASP CRS paranoia level (1-4), in-process")
	fs.IntVar(&cfg.threshold, "anomaly-threshold", coraza.DefaultInboundAnomalyThreshold, "OWASP CRS inbound anomaly score threshold, in-process")
	fs.StringVar(&cfg.rules, "rules", "", "SecLang rules file loaded after CRS, in-process (as the engine's --rules)")
	fs.StringVar(&cfg.rulesBefore, "rules-before-crs", "", "SecLang file loaded before CRS, in-process (as the engine's --rules-before-crs)")
	disabled := fs.String("disable-rule-groups", "", "comma-separated CRS attack families to remove, in-process: "+strings.Join(coraza.RuleGroupNames(), ", "))
	return flagSet{FlagSet: fs, cfg: cfg, mode: mode, disabled: disabled}
}

// finish parses args and validates the shared flags. With inputRequired,
// exactly one input must be given; otherwise at most one.
func (fs flagSet) finish(args []string, inputRequired bool) error {
	cfg := fs.cfg
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := 0
	if fs.NArg() > 1 {
		return fmt.Errorf("one URL expected, got %d arguments", fs.NArg())
	}
	if fs.NArg() == 1 {
		cfg.url = fs.Arg(0)
		inputs++
	}
	if cfg.requestFile != "" {
		inputs++
	}
	if cfg.harFile != "" {
		inputs++
	}
	if inputs > 1 || (inputRequired && inputs == 0) {
		return errors.New("give exactly one of URL, --request or --har")
	}
	if cfg.url == "" && (cfg.method != "" || len(cfg.headers) > 0 || cfg.data != "") {
		return errors.New("-X, -H and -d apply only to a URL")
	}
	switch *fs.mode {
	case "block":
		cfg.mode = pipeline.ModeBlock
	case "detect":
		cfg.mode = pipeline.ModeDetect
	default:
		return fmt.Errorf("--mode must be block or detect, got %q", *fs.mode)
	}
	for _, g := range strings.Split(*fs.disabled, ",") {
		if g = strings.TrimSpace(g); g == "" {
			continue
		}
		if _, ok := coraza.RuleGroups[g]; !ok {
			return fmt.Errorf("--disable-rule-groups: unknown group %q", g)
		}
		cfg.disabled = append(cfg.disabled, g)
	}
	return nil
}

func parseTestFlags(args []string, stderr io.Writer) (config, error) {
	// One request at a time and no load: a long deadline keeps a slow
	// machine from turning a verdict into a timeout.
	cfg := config{timeout: 10 * time.Second}
	fs := newFlagSet("test", &cfg, stderr, "; every request in it is checked")
	fs.StringVar(&cfg.expect, "expect", "", "exit 1 unless every request gets this verdict: allow or deny")
	fs.BoolVar(&cfg.json, "json", false, "print each CheckResponse as a JSON line")
	if err := fs.finish(args, true); err != nil {
		return cfg, err
	}
	switch cfg.expect {
	case "", "allow", "deny":
	default:
		return cfg, fmt.Errorf("--expect must be allow or deny, got %q", cfg.expect)
	}
	return cfg, nil
}

func runTest(cfg config, stdout, stderr io.Writer) int {
	reqs, err := loadRequests(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	check, err := newChecker(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	mismatches := 0
	for _, in := range reqs {
		out, err := check(in)
		if err != nil {
			fmt.Fprintf(stderr, "error: %s %s: %v\n", in.GetMethod(), in.GetRawUri(), err)
			return 2
		}
		if cfg.json {
			b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(out)
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 2
			}
			fmt.Fprintln(stdout, string(b))
		} else {
			fmt.Fprintln(stdout, describe(in, out))
		}
		denied := out.GetAction() == enginev1.Action_ACTION_DENY
		if (cfg.expect == "deny" && !denied) || (cfg.expect == "allow" && denied) {
			mismatches++
		}
	}
	if mismatches > 0 {
		fmt.Fprintf(stderr, "%d of %d request(s) did not get the expected verdict %q\n", mismatches, len(reqs), cfg.expect)
		return 1
	}
	return 0
}

// describe formats one verdict as a line of text.
func describe(in *enginev1.CheckRequest, out *enginev1.CheckResponse) string {
	var b strings.Builder
	action := strings.ToLower(strings.TrimPrefix(out.GetAction().String(), "ACTION_"))
	fmt.Fprintf(&b, "%-5s", action)
	if out.GetStatus() != 0 {
		fmt.Fprintf(&b, " %d", out.GetStatus())
	} else {
		b.WriteString("    ")
	}
	fmt.Fprintf(&b, "  %s %s", in.GetMethod(), in.GetRawUri())
	if r := out.GetReason(); r != enginev1.Reason_REASON_NONE {
		fmt.Fprintf(&b, "  reason=%s", strings.ToLower(strings.TrimPrefix(r.String(), "REASON_")))
	}
	if ids := out.GetRuleIds(); len(ids) > 0 {
		s := make([]string, len(ids))
		for i, id := range ids {
			s[i] = fmt.Sprint(id)
		}
		fmt.Fprintf(&b, "  rules=%s", strings.Join(s, ","))
	}
	if id := out.GetInterruptingRuleId(); id != 0 {
		fmt.Fprintf(&b, "  interrupting=%d", id)
	}
	fmt.Fprintf(&b, "  %s", out.GetInspectionTime().AsDuration().Round(time.Microsecond))
	return b.String()
}

// checker returns the verdict for one request.
type checker func(*enginev1.CheckRequest) (*enginev1.CheckResponse, error)

func newChecker(cfg config) (checker, error) {
	if cfg.engine != "" {
		return remoteChecker(cfg.engine)
	}
	return localChecker(cfg)
}

// localChecker runs the engine's check API in-process, so verdicts are the
// engine's own.
func localChecker(cfg config) (checker, error) {
	rules, err := readOptional(cfg.rules)
	if err != nil {
		return nil, fmt.Errorf("read --rules: %w", err)
	}
	before, err := readOptional(cfg.rulesBefore)
	if err != nil {
		return nil, fmt.Errorf("read --rules-before-crs: %w", err)
	}
	eval, err := coraza.New(coraza.Config{
		ParanoiaLevel:           cfg.paranoiaLevel,
		InboundAnomalyThreshold: cfg.threshold,
		BodyLimit:               int(cfg.maxBodyBytes),
		DisabledRuleGroups:      cfg.disabled,
		DirectivesBeforeCRS:     before,
		Directives:              rules,
	})
	if err != nil {
		return nil, err
	}
	p := pipeline.New(eval, pipeline.Config{Mode: cfg.mode, Timeout: cfg.timeout})
	h, err := httpcheck.New(p, httpcheck.Config{MaxBodyBytes: cfg.maxBodyBytes, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		return nil, err
	}
	return func(in *enginev1.CheckRequest) (*enginev1.CheckResponse, error) {
		raw, err := proto.Marshal(in)
		if err != nil {
			return nil, err
		}
		r := httptest.NewRequest(http.MethodPost, httpcheck.Path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", httpcheck.ContentTypeProtobuf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return decode(w.Result())
	}, nil
}

// remoteChecker sends checks to a running engine.
func remoteChecker(engine string) (checker, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := strings.TrimSuffix(engine, "/") + httpcheck.Path
	if path, ok := strings.CutPrefix(engine, "unix:"); ok {
		if path == "" {
			return nil, errors.New("--engine unix: needs a socket path")
		}
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}
		endpoint = "http://engine" + httpcheck.Path
	} else if !strings.HasPrefix(engine, "http://") && !strings.HasPrefix(engine, "https://") {
		return nil, fmt.Errorf("--engine %q: want http://host:port or unix:/path", engine)
	}
	return func(in *enginev1.CheckRequest) (*enginev1.CheckResponse, error) {
		raw, err := proto.Marshal(in)
		if err != nil {
			return nil, err
		}
		resp, err := client.Post(endpoint, httpcheck.ContentTypeProtobuf, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		return decode(resp)
	}, nil
}

// decode reads a check API answer. The caller closes the body.
func decode(resp *http.Response) (*enginev1.CheckResponse, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check API answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out enginev1.CheckResponse
	if err := proto.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode check response: %w", err)
	}
	return &out, nil
}

func readOptional(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	// The path comes from the user's own command line.
	b, err := os.ReadFile(filepath.Clean(path))
	return string(b), err
}
