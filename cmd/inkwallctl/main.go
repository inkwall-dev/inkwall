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
// code the engine runs, configured by flags. With --policy they are
// inspected by WAFPolicy objects, resolved the way the operator does and
// compiled the way the engine does; with --bundle, by a bundle the operator
// built; with --engine they are sent to a running engine's check API
// (inkwall-engine check).
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

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "test" && args[0] != "bench") {
		fmt.Fprintln(stderr, "usage: inkwallctl test [flags] URL")
		fmt.Fprintln(stderr, "       inkwallctl test [flags] --request FILE | --har FILE")
		fmt.Fprintln(stderr, "       inkwallctl test --policy FILE [--rule-set FILE] [--ingress FILE] ... URL | --request FILE | --har FILE")
		fmt.Fprintln(stderr, "       inkwallctl test --bundle FILE [--bundle-key FILE] URL | --request FILE | --har FILE")
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

// listFlag collects a repeated flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type config struct {
	// Input: at most one of url, requestFile, harFile.
	url         string
	method      string
	headers     listFlag
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

	// test: WAF objects to resolve, or a bundle, instead of the flags
	// that define a policy.
	policies   listFlag
	ruleSets   listFlag
	configMaps listFlag
	ingresses  listFlag
	namespace  string
	bundle     string
	bundleKey  string

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
	const objects = "; a file (or a directory of .yaml, .yml and .json files) may hold several YAML documents or a kubectl List, of any of the kinds --policy, --rule-set, --configmap and --ingress read (repeatable)"
	fs.Var(&cfg.policies, "policy", "WAFPolicy YAML file: inspect with the policies, resolved as the operator does, instead of the flags that define a policy"+objects)
	fs.Var(&cfg.ruleSets, "rule-set", "WAFRuleSet or ClusterWAFRuleSet YAML file the policies use"+objects)
	fs.Var(&cfg.configMaps, "configmap", "ConfigMap YAML file rule sets read rules from (labeled "+resolver.RulesLabel+"=true)"+objects)
	fs.Var(&cfg.ingresses, "ingress", "Ingress YAML file the policies target, to route requests by host and path; without one, a single policy applies to every request"+objects)
	fs.StringVar(&cfg.namespace, "namespace", "default", "namespace of the objects in the files that don't name one, as kubectl apply -n")
	fs.StringVar(&cfg.bundle, "bundle", "", "bundle file: inspect with its policies instead of the flags that define a policy; the inkwall-bundle Secret's bundle.pb.gz (compressed or not), or the Secret as YAML or JSON")
	fs.StringVar(&cfg.bundleKey, "bundle-key", "", "with --bundle: check the bundle's signature with this ed25519 public key (raw 32 bytes, as the Secret's ed25519.pub, or base64)")
	if err := fs.finish(args, true); err != nil {
		return cfg, err
	}
	switch cfg.expect {
	case "", "allow", "deny":
	default:
		return cfg, fmt.Errorf("--expect must be allow or deny, got %q", cfg.expect)
	}
	if err := fs.checkPolicySource(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// policyFiles reports whether requests are inspected by WAF objects.
func (cfg *config) policyFiles() bool {
	return len(cfg.policies)+len(cfg.ruleSets)+len(cfg.configMaps)+len(cfg.ingresses) > 0
}

// checkPolicySource validates where test's policy comes from: the flags,
// WAF objects, a bundle or a running engine.
func (fs flagSet) checkPolicySource() error {
	cfg := fs.cfg
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	sources := 0
	for _, b := range []bool{cfg.policyFiles(), cfg.bundle != "", cfg.engine != ""} {
		if b {
			sources++
		}
	}
	switch {
	case sources > 1:
		return errors.New("give at most one of --policy (with --rule-set, --configmap, --ingress), --bundle and --engine")
	case cfg.bundleKey != "" && cfg.bundle == "":
		return errors.New("--bundle-key applies only to --bundle")
	case set["namespace"] && !cfg.policyFiles():
		return errors.New("--namespace applies only to --policy")
	case sources == 1 && cfg.engine != "":
		return nil
	case sources == 1:
		// As in the engine's bundle mode: the policies set these.
		var conflicts []string
		for _, name := range []string{"mode", "paranoia-level", "anomaly-threshold", "rules", "rules-before-crs", "disable-rule-groups"} {
			if set[name] {
				conflicts = append(conflicts, "--"+name)
			}
		}
		if len(conflicts) > 0 {
			return fmt.Errorf("%s: set by the policies with --policy or --bundle", strings.Join(conflicts, ", "))
		}
	}
	return nil
}

func runTest(cfg config, stdout, stderr io.Writer) int {
	reqs, err := loadRequests(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	check, err := newChecker(cfg, stderr)
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
	if p := out.GetPolicy(); p != "" {
		fmt.Fprintf(&b, "  policy=%s", p)
	}
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

// newChecker returns the checker cfg selects. Notes about the policies
// go to notes.
func newChecker(cfg config, notes io.Writer) (checker, error) {
	var b *bundlev1.Bundle
	var err error
	switch {
	case cfg.engine != "":
		return remoteChecker(cfg.engine)
	case cfg.policyFiles():
		b, err = policyBundle(cfg, notes)
	case cfg.bundle != "":
		b, err = fileBundle(cfg.bundle, cfg.bundleKey, notes)
	default:
		return flagChecker(cfg)
	}
	if err != nil {
		return nil, err
	}
	set, err := policy.Compile(withDeadline(b, cfg.timeout), policy.Options{BodyLimit: cfg.maxBodyBytes})
	if err != nil {
		return nil, fmt.Errorf("the engine would reject the bundle: %w", err)
	}
	// As the engine in bundle mode: each policy sets its body limit, up to
	// the CRD's maximum.
	return localChecker(set, max(cfg.maxBodyBytes, policy.MaxBodyBytes))
}

// flagChecker inspects with the pipeline the flags define, as the engine
// does without a bundle.
func flagChecker(cfg config) (checker, error) {
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
	return localChecker(p, cfg.maxBodyBytes)
}

// localChecker runs the engine's check API in-process with insp, so
// verdicts are the engine's own.
func localChecker(insp pipeline.Inspector, maxBodyBytes int64) (checker, error) {
	h, err := httpcheck.New(insp, httpcheck.Config{MaxBodyBytes: maxBodyBytes, Logger: slog.New(slog.DiscardHandler)})
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
