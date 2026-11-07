// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// suite is a test suite file (inkwallctl test --suite, #385): where the
// policies come from, and cases, each a request (and optionally its
// response) with the verdict expected. The format is experimental.
type suite struct {
	// The policy source, as the flags of the same name; paths are relative
	// to the suite file. Each takes a path or a list of paths.
	Policy    pathList `json:"policy,omitempty"`
	RuleSet   pathList `json:"ruleSet,omitempty"`
	ConfigMap pathList `json:"configMap,omitempty"`
	Ingress   pathList `json:"ingress,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Bundle    string   `json:"bundle,omitempty"`
	BundleKey string   `json:"bundleKey,omitempty"`

	Cases []suiteCase `json:"cases"`

	// dir is the suite file's directory, which relative paths start from.
	dir string
}

// suiteCase is one case: a request, or every request of a file, with an
// optional response, and what its verdict must be.
type suiteCase struct {
	Name     string         `json:"name"`
	Request  suiteRequest   `json:"request"`
	Response *suiteResponse `json:"response,omitempty"`
	Expect   expectation    `json:"expect"`
}

// suiteRequest is a request written inline (url, or uri with host), or a
// file of raw HTTP requests or a HAR file (.har).
type suiteRequest struct {
	File     string            `json:"file,omitempty"`
	URL      string            `json:"url,omitempty"`
	URI      string            `json:"uri,omitempty"`
	Host     string            `json:"host,omitempty"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	ClientIP string            `json:"clientIP,omitempty"`
}

// suiteResponse is the upstream's response to the case's request.
type suiteResponse struct {
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// expectation is what a case's verdict must be; unset fields aren't
// checked.
type expectation struct {
	// Action: allow, deny or log.
	Action string `json:"action,omitempty"`
	// Status: the denial's HTTP status.
	Status int `json:"status,omitempty"`
	// Rules must all match; ExactRules must be exactly the rules that
	// match (the request's and the response's); NotRules must not match.
	Rules      []uint32 `json:"rules,omitempty"`
	ExactRules []uint32 `json:"exactRules,omitempty"`
	NotRules   []uint32 `json:"notRules,omitempty"`
	// Policy: the policy that decided, namespace/name.
	Policy string `json:"policy,omitempty"`
	// Phase: request or response, the verdict's.
	Phase string `json:"phase,omitempty"`
}

// pathList is a path or a list of paths.
type pathList []string

func (p *pathList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*p = pathList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("want a path or a list of paths")
	}
	*p = many
	return nil
}

// loadSuite reads and validates a suite file.
func loadSuite(path string) (*suite, error) {
	// The path comes from the user's own command line.
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	s, err := parseSuite(b, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// parseSuite decodes a suite, strictly, and validates it. dir is where
// its relative paths start.
func parseSuite(b []byte, dir string) (*suite, error) {
	var s suite
	if err := yaml.UnmarshalStrict(b, &s); err != nil {
		return nil, err
	}
	s.dir = dir
	if len(s.Cases) == 0 {
		return nil, errors.New("no cases")
	}
	names := map[string]bool{}
	for i, c := range s.Cases {
		if c.Name == "" {
			return nil, fmt.Errorf("case %d: no name", i+1)
		}
		if names[c.Name] {
			return nil, fmt.Errorf("case %q: name used twice", c.Name)
		}
		names[c.Name] = true
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("case %q: %w", c.Name, err)
		}
	}
	return &s, nil
}

func (c *suiteCase) validate() error {
	r := c.Request
	given := 0
	for _, v := range []string{r.File, r.URL, r.URI} {
		if v != "" {
			given++
		}
	}
	switch {
	case given != 1:
		return errors.New("request: give exactly one of file, url and uri")
	case r.File != "" && (r.Host != "" || r.Method != "" || len(r.Headers) > 0 || r.Body != ""):
		return errors.New("request: host, method, headers and body don't apply to a file")
	case r.URL != "" && r.Host != "":
		return errors.New("request: host applies only to uri; a url has its own")
	case r.URI != "" && !strings.HasPrefix(r.URI, "/"):
		return fmt.Errorf("request: uri %q must start with /", r.URI)
	case r.Method != "" && !isToken(r.Method):
		return fmt.Errorf("request: invalid method %q", r.Method)
	}
	if r.ClientIP != "" {
		if _, err := netip.ParseAddr(r.ClientIP); err != nil {
			return fmt.Errorf("request: clientIP: %w", err)
		}
	}
	for name := range r.Headers {
		if !isToken(name) {
			return fmt.Errorf("request: invalid header name %q", name)
		}
	}
	if resp := c.Response; resp != nil {
		if resp.Status != 0 && (resp.Status < 100 || resp.Status > 999) {
			return fmt.Errorf("response: invalid status %d", resp.Status)
		}
		for name := range resp.Headers {
			if !isToken(name) {
				return fmt.Errorf("response: invalid header name %q", name)
			}
		}
	}
	e := c.Expect
	switch e.Action {
	case "", "allow", "deny", "log":
	default:
		return fmt.Errorf("expect: action must be allow, deny or log, got %q", e.Action)
	}
	switch e.Phase {
	case "", "request":
	case "response":
		if c.Response == nil {
			return errors.New("expect: phase response needs a response")
		}
	default:
		return fmt.Errorf("expect: phase must be request or response, got %q", e.Phase)
	}
	if e.Status != 0 && (e.Status < 100 || e.Status > 999) {
		return fmt.Errorf("expect: invalid status %d", e.Status)
	}
	if e.Action == "" && e.Status == 0 && e.Rules == nil && e.ExactRules == nil && e.NotRules == nil && e.Policy == "" && e.Phase == "" {
		return errors.New("expect: nothing expected")
	}
	if e.Rules != nil && e.ExactRules != nil {
		return errors.New("expect: give rules or exactRules, not both")
	}
	return nil
}

// isToken reports whether s is an HTTP token (a method or header name).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}
	return true
}

// hasResponses reports whether a case has a response.
func (s *suite) hasResponses() bool {
	return slices.ContainsFunc(s.Cases, func(c suiteCase) bool { return c.Response != nil })
}

// path resolves a path of the suite file.
func (s *suite) path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.dir, p)
}

// mergeSuiteSource adds the suite's policy source to cfg's flags.
func mergeSuiteSource(cfg *config, s *suite) error {
	if len(s.Policy)+len(s.RuleSet)+len(s.ConfigMap)+len(s.Ingress) > 0 || s.Bundle != "" {
		if cfg.policyFiles() || cfg.bundle != "" || cfg.engine != "" {
			return errors.New("the suite names its policies: drop --policy, --rule-set, --configmap, --ingress, --bundle and --engine")
		}
	}
	for _, l := range []struct {
		from pathList
		to   *listFlag
	}{{s.Policy, &cfg.policies}, {s.RuleSet, &cfg.ruleSets}, {s.ConfigMap, &cfg.configMaps}, {s.Ingress, &cfg.ingresses}} {
		for _, p := range l.from {
			*l.to = append(*l.to, s.path(p))
		}
	}
	if s.Namespace != "" {
		if !cfg.policyFiles() {
			return errors.New("the suite's namespace applies only to its policy")
		}
		cfg.namespace = s.Namespace
	}
	if s.Bundle != "" {
		cfg.bundle = s.path(s.Bundle)
	}
	if s.BundleKey != "" {
		if s.Bundle == "" {
			return errors.New("the suite's bundleKey applies only to its bundle")
		}
		cfg.bundleKey = s.path(s.BundleKey)
	}
	if s.hasResponses() {
		if cfg.engine != "" {
			return errors.New("response cases are checked in-process: --engine's check API has no response")
		}
		// The flags' pipeline inspects responses for them; a policy
		// decides with its spec.responses.
		cfg.inspectResponses = true
	}
	return nil
}

// requests returns the case's requests: one, or every request of its file.
func (s *suite) requests(c *suiteCase, defaultClientIP string) ([]*enginev1.CheckRequest, error) {
	r := c.Request
	var reqs []*enginev1.CheckRequest
	switch {
	case r.File != "":
		path := s.path(r.File)
		b, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(filepath.Ext(path), ".har") {
			reqs, err = fromHAR(b)
		} else {
			reqs, err = fromRawHTTP(strings.NewReader(string(b)))
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.File, err)
		}
	default:
		in, err := inlineRequest(r)
		if err != nil {
			return nil, err
		}
		reqs = []*enginev1.CheckRequest{in}
	}
	ip := cmp.Or(r.ClientIP, defaultClientIP)
	for _, in := range reqs {
		if ip != "" {
			in.ClientIp = ip
		}
	}
	return reqs, nil
}

// inlineRequest builds a request written in the suite, as curl would send
// it: curl's default headers unless given, and a form body by default.
func inlineRequest(r suiteRequest) (*enginev1.CheckRequest, error) {
	scheme, authority, rawURI := "http", cmp.Or(r.Host, "localhost"), r.URI
	if r.URL != "" {
		var err error
		if scheme, authority, rawURI, err = splitURL(r.URL); err != nil {
			return nil, err
		}
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
		if r.Body != "" {
			method = http.MethodPost
		}
	}
	headers := http.Header{}
	headers.Set("User-Agent", "inkwallctl")
	headers.Set("Accept", "*/*")
	if r.Body != "" {
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
		headers.Set("Content-Length", strconv.Itoa(len(r.Body)))
	}
	for name, value := range r.Headers {
		if strings.EqualFold(name, "Host") {
			authority = value
			continue
		}
		headers.Set(name, value)
	}
	in := &enginev1.CheckRequest{
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		RawUri:    rawURI,
		Headers:   toHeaders(headers),
		ClientIp:  "127.0.0.1",
	}
	if r.Body != "" {
		in.Body = []byte(r.Body)
	}
	return in, nil
}

// toResponse converts the case's response.
func (r *suiteResponse) toResponse() *request.Response {
	h := http.Header{}
	for name, value := range r.Headers {
		h.Set(name, value)
	}
	status := r.Status
	if status == 0 {
		status = http.StatusOK
	}
	return &request.Response{Status: status, Headers: h, Body: []byte(r.Body)}
}

// verdict is a request's outcome in a case: the request's verdict, the
// response's when it was inspected, and the one the case is judged on.
type verdict struct {
	in          *enginev1.CheckRequest
	req, res    *enginev1.CheckResponse
	final       *enginev1.CheckResponse
	phase       string
	uninspected bool // the case has a response that wasn't inspected
}

// judge returns the verdict a case is judged on: the response's when it
// was inspected and isn't an allow while the request's is not, else the
// request's.
func judge(in *enginev1.CheckRequest, req, res *enginev1.CheckResponse, hasResponse bool) verdict {
	v := verdict{in: in, req: req, res: res, final: req, phase: "request"}
	if res != nil && (res.GetAction() != enginev1.Action_ACTION_ALLOW || req.GetAction() == enginev1.Action_ACTION_ALLOW) {
		v.final, v.phase = res, "response"
	}
	v.uninspected = hasResponse && res == nil && req.GetAction() != enginev1.Action_ACTION_DENY
	return v
}

// actionName is allow, deny or log.
func actionName(a enginev1.Action) string {
	return strings.ToLower(strings.TrimPrefix(a.String(), "ACTION_"))
}

// mismatches returns how v misses e, empty when it doesn't.
func (e *expectation) mismatches(v verdict) []string {
	var out []string
	f := v.final
	if e.Action != "" && actionName(f.GetAction()) != e.Action {
		out = append(out, fmt.Sprintf("action %s, want %s", actionName(f.GetAction()), e.Action))
	}
	if e.Status != 0 && int(f.GetStatus()) != e.Status {
		out = append(out, fmt.Sprintf("status %d, want %d", f.GetStatus(), e.Status))
	}
	if e.Policy != "" && f.GetPolicy() != e.Policy {
		out = append(out, fmt.Sprintf("policy %q, want %q", f.GetPolicy(), e.Policy))
	}
	if e.Phase != "" && v.phase != e.Phase {
		msg := fmt.Sprintf("phase %s, want %s", v.phase, e.Phase)
		if v.uninspected {
			msg += " (the response wasn't inspected: with --policy or --bundle, the policy must set spec.responses.inspect)"
		}
		out = append(out, msg)
	}
	matched := v.rules()
	var missing, unwanted []uint32
	want := e.Rules
	if e.ExactRules != nil {
		want = e.ExactRules
	}
	for _, id := range want {
		if !slices.Contains(matched, id) {
			missing = append(missing, id)
		}
	}
	if e.ExactRules != nil {
		for _, id := range matched {
			if !slices.Contains(e.ExactRules, id) {
				unwanted = append(unwanted, id)
			}
		}
	}
	for _, id := range e.NotRules {
		if slices.Contains(matched, id) {
			unwanted = append(unwanted, id)
		}
	}
	if len(missing) > 0 {
		out = append(out, "rules "+ids(missing)+" didn't match")
	}
	if len(unwanted) > 0 {
		out = append(out, "rules "+ids(unwanted)+" matched")
	}
	return out
}

// rules returns the rules that matched the request and the response.
func (v verdict) rules() []uint32 {
	out := slices.Clone(v.req.GetRuleIds())
	for _, id := range v.res.GetRuleIds() {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func ids(l []uint32) string {
	s := make([]string, len(l))
	for i, id := range l {
		s[i] = strconv.FormatUint(uint64(id), 10)
	}
	return strings.Join(s, ",")
}

// lines describes v, a line for the request and one for the response.
func (v verdict) lines() []string {
	out := []string{"request   " + describe(v.in, v.req)}
	switch {
	case v.res != nil:
		out = append(out, "response  "+describe(v.in, v.res))
	case v.uninspected:
		out = append(out, "response  not inspected")
	}
	return out
}

// caseResult is the outcome of one case.
type caseResult struct {
	name     string
	failures []string // why it failed: empty when it passed
	err      error    // the case couldn't be checked
	lines    []string // the verdicts
	duration time.Duration
}

// runSuite runs the suite's cases: 0 when all pass, 1 when one fails, 2
// on an error.
func runSuite(cfg config, stdout, stderr io.Writer) int {
	s := cfg.suiteData
	var (
		check checker
		h     *httpcheck.Handler // in-process, for the response cases
		err   error
	)
	if cfg.engine != "" {
		check, err = remoteChecker(cfg.engine)
	} else if h, err = newLocalHandler(cfg, stderr); err == nil {
		check = localChecker(h)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	start := time.Now()
	results := make([]caseResult, 0, len(s.Cases))
	for i := range s.Cases {
		c := &s.Cases[i]
		t := time.Now()
		r := caseResult{name: c.Name}
		reqs, err := s.requests(c, cfg.clientIP)
		if err != nil {
			r.err = err
		}
		for j, in := range reqs {
			var v verdict
			if c.Response == nil {
				out, err := check(in)
				if err != nil {
					r.err = fmt.Errorf("%s %s: %w", in.GetMethod(), in.GetRawUri(), err)
					break
				}
				v = judge(in, out, nil, false)
			} else {
				req, res, err := h.CheckExchange(context.Background(), in, c.Response.toResponse())
				if err != nil {
					r.err = fmt.Errorf("%s %s: %w", in.GetMethod(), in.GetRawUri(), err)
					break
				}
				v = judge(in, req, res, true)
			}
			r.lines = append(r.lines, v.lines()...)
			for _, m := range c.Expect.mismatches(v) {
				if len(reqs) > 1 {
					m = fmt.Sprintf("request %d (%s %s): %s", j+1, in.GetMethod(), in.GetRawUri(), m)
				}
				r.failures = append(r.failures, m)
			}
		}
		r.duration = time.Since(t)
		results = append(results, r)

		switch {
		case r.err != nil:
			fmt.Fprintf(stdout, "ERROR %s: %v\n", r.name, r.err)
		case len(r.failures) > 0:
			fmt.Fprintf(stdout, "FAIL  %s: %s\n", r.name, strings.Join(r.failures, "; "))
		default:
			fmt.Fprintf(stdout, "ok    %s\n", r.name)
		}
		for _, l := range r.lines {
			fmt.Fprintf(stdout, "      %s\n", l)
		}
	}

	failed, errored := 0, 0
	for _, r := range results {
		switch {
		case r.err != nil:
			errored++
		case len(r.failures) > 0:
			failed++
		}
	}
	if cfg.junit != "" {
		if err := writeJUnit(cfg.junit, cfg.suite, results, start, time.Since(start)); err != nil {
			fmt.Fprintln(stderr, "error: --junit:", err)
			return 2
		}
	}
	fmt.Fprintf(stdout, "%d of %d case(s) passed", len(results)-failed-errored, len(results))
	if failed > 0 {
		fmt.Fprintf(stdout, ", %d failed", failed)
	}
	if errored > 0 {
		fmt.Fprintf(stdout, ", %d could not be checked", errored)
	}
	fmt.Fprintln(stdout)
	switch {
	case errored > 0:
		return 2
	case failed > 0:
		return 1
	}
	return 0
}

// JUnit XML, in the common schema (Apache Ant's JUnit report, as
// windyroad/JUnit-Schema's JUnit.xsd describes it) that Jenkins, GitLab
// and GitHub's test reporters read.
type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Package    string      `xml:"package,attr"`
	ID         int         `xml:"id,attr"`
	Name       string      `xml:"name,attr"`
	Timestamp  string      `xml:"timestamp,attr"`
	Hostname   string      `xml:"hostname,attr"`
	Tests      int         `xml:"tests,attr"`
	Failures   int         `xml:"failures,attr"`
	Errors     int         `xml:"errors,attr"`
	Time       string      `xml:"time,attr"`
	Properties struct{}    `xml:"properties"`
	Cases      []junitCase `xml:"testcase"`
	SystemOut  cdata       `xml:"system-out"`
	SystemErr  cdata       `xml:"system-err"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
}

type junitProblem struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",cdata"`
}

type cdata struct {
	Text string `xml:",cdata"`
}

func seconds(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', 3, 64) }

// writeJUnit writes the results as JUnit XML to path: a test case per
// case, a failure with what was expected and the actual verdicts, and
// every case's verdicts in the suite's system-out.
func writeJUnit(path, name string, results []caseResult, start time.Time, d time.Duration) error {
	js := junitSuite{Package: "inkwallctl", Name: name, Tests: len(results), Time: seconds(d),
		Timestamp: start.UTC().Format("2006-01-02T15:04:05"), Hostname: "localhost"}
	var out strings.Builder
	for _, r := range results {
		c := junitCase{Name: r.name, Classname: name, Time: seconds(r.duration)}
		switch {
		case r.err != nil:
			js.Errors++
			c.Error = &junitProblem{Message: r.err.Error(), Type: "error", Text: r.err.Error()}
		case len(r.failures) > 0:
			js.Failures++
			c.Failure = &junitProblem{Message: strings.Join(r.failures, "; "), Type: "verdict", Text: strings.Join(append(slices.Clone(r.failures), r.lines...), "\n")}
		}
		js.Cases = append(js.Cases, c)
		out.WriteString(r.name + "\n")
		for _, l := range r.lines {
			out.WriteString("  " + l + "\n")
		}
	}
	js.SystemOut.Text = out.String()
	b, err := xml.MarshalIndent(junitSuites{Suites: []junitSuite{js}}, "", "  ")
	if err != nil {
		return err
	}
	b = append([]byte(xml.Header), append(b, '\n')...)
	// The path comes from the user's own command line.
	return os.WriteFile(filepath.Clean(path), b, 0o600)
}
