// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSuite writes a suite and the files it names to a directory.
func writeSuite(t *testing.T, suite string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["suite.yaml"] = suite
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "suite.yaml")
}

// readJUnit decodes a JUnit report.
func readJUnit(t *testing.T, path string) junitSuites {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out junitSuites
	if err := xml.Unmarshal(b, &out); err != nil {
		t.Fatalf("JUnit report: %v\n%s", err, b)
	}
	if len(out.Suites) != 1 {
		t.Fatalf("%d test suites, want 1", len(out.Suites))
	}
	return out
}

const blockPolicy = `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: web, namespace: shop}
spec:
  targetRefs: [{group: gateway.networking.k8s.io, kind: HTTPRoute, name: web}]
  mode: Block
`

// The example suite passes (make test-examples runs it too), and its
// JUnit report has a test case per case.
func TestSuiteExample(t *testing.T) {
	junit := filepath.Join(t.TempDir(), "out.xml")
	code, stdout, stderr := runCLI(t, "test", "--suite", "../../examples/tests/suite.yaml", "--junit", junit)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	r := readJUnit(t, junit)
	s := r.Suites[0]
	if s.Tests == 0 || s.Tests != len(s.Cases) || s.Failures != 0 || s.Errors != 0 {
		t.Errorf("tests %d, cases %d, failures %d, errors %d", s.Tests, len(s.Cases), s.Failures, s.Errors)
	}
	if !strings.Contains(stdout, "response  deny  403") {
		t.Errorf("no denied response in the output:\n%s", stdout)
	}
}

// Every expectation is checked, and a failure says what was expected
// and what the verdict was, on the terminal and in the JUnit report.
func TestSuiteFailures(t *testing.T) {
	path := writeSuite(t, `policy: policy.yaml
cases:
  - name: right
    request: {uri: "`+sqli+`"}
    expect: {action: deny, status: 403, rules: [942100], notRules: [941100], policy: shop/web, phase: request}
  - name: wrong action
    request: {uri: /products/42}
    expect: {action: deny}
  - name: wrong status
    request: {uri: "`+sqli+`"}
    expect: {status: 418}
  - name: missing rule
    request: {uri: "`+sqli+`"}
    expect: {rules: [941100]}
  - name: unwanted rule
    request: {uri: "`+sqli+`"}
    expect: {notRules: [942100]}
  - name: not exactly
    request: {uri: "`+sqli+`"}
    expect: {exactRules: [942100]}
  - name: wrong policy
    request: {uri: /}
    expect: {policy: shop/other}
  - name: one request of the file
    request: {file: requests.http}
    expect: {action: allow}
`, map[string]string{"policy.yaml": blockPolicy, "requests.http": "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET " + sqli + " HTTP/1.1\r\nHost: a\r\n\r\n"})
	junit := filepath.Join(t.TempDir(), "out.xml")
	code, stdout, stderr := runCLI(t, "test", "--suite", path, "--junit", junit)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"ok    right\n",
		"FAIL  wrong action: action allow, want deny\n",
		"FAIL  wrong status: status 403, want 418\n",
		"FAIL  missing rule: rules 941100 didn't match\n",
		"FAIL  unwanted rule: rules 942100 matched\n",
		"FAIL  not exactly: rules 949110 matched\n",
		`FAIL  wrong policy: policy "shop/web", want "shop/other"`,
		"FAIL  one request of the file: request 2 (GET " + sqli + "): action deny, want allow\n",
		"1 of 8 case(s) passed, 7 failed\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	s := readJUnit(t, junit).Suites[0]
	if s.Tests != 8 || s.Failures != 7 || s.Errors != 0 {
		t.Errorf("tests %d, failures %d, errors %d", s.Tests, s.Failures, s.Errors)
	}
	if c := s.Cases[0]; c.Name != "right" || c.Failure != nil {
		t.Errorf("first case %+v", c)
	}
	f := s.Cases[1].Failure
	if f == nil || f.Message != "action allow, want deny" || !strings.Contains(f.Text, "allow      GET /products/42") {
		t.Errorf("failure %+v: want the expectation and the actual verdict", f)
	}
}

// Responses are inspected in-process: with the flags, as the engine with
// --inspect-responses; with a policy, as its spec.responses says.
func TestSuiteResponses(t *testing.T) {
	const cases = `cases:
  - name: SQL error leaked
    request: {uri: /item}
    response:
      status: 500
      headers: {Content-Type: text/html}
      body: "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>"
    expect: {action: deny, status: 403, rules: [951230], phase: response}
  - name: denied request, response not inspected
    request: {uri: "` + sqli + `"}
    response: {headers: {Content-Type: text/html}, body: "You have an error in your SQL syntax"}
    expect: {action: deny, phase: request}
`
	t.Run("flags", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "test", "--suite", writeSuite(t, cases, map[string]string{}))
		if code != 0 {
			t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
		}
	})
	t.Run("a policy that inspects responses", func(t *testing.T) {
		policy := blockPolicy + "  responses: {inspect: true}\n"
		code, stdout, stderr := runCLI(t, "test", "--suite", writeSuite(t, "policy: policy.yaml\n"+cases, map[string]string{"policy.yaml": policy}))
		if code != 0 {
			t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
		}
	})
	t.Run("a policy that doesn't", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "test", "--suite", writeSuite(t, "policy: policy.yaml\n"+cases, map[string]string{"policy.yaml": blockPolicy}))
		if code != 1 || !strings.Contains(stdout, "FAIL  SQL error leaked: action allow, want deny;") ||
			!strings.Contains(stdout, "phase request, want response (the response wasn't inspected") ||
			!strings.Contains(stdout, "response  not inspected") {
			t.Fatalf("exit %d, want 1 and the response not inspected\n%s%s", code, stdout, stderr)
		}
	})
}

// A suite that can't be run is an error (exit 2), before any case runs.
func TestSuiteErrors(t *testing.T) {
	request := "\n    request: {uri: /}\n    expect: {action: allow}\n"
	for _, tc := range []struct {
		name, suite string
		args        []string
		want        string
	}{
		{"no cases", "cases: []\n", nil, "no cases"},
		{"unknown field", "cases:\n  - name: a" + request + "    expected: {}\n", nil, "unknown field"},
		{"no name", "cases:\n  -" + request, nil, "case 1: no name"},
		{"same name", "cases:\n  - name: a" + request + "  - name: a" + request, nil, `case "a": name used twice`},
		{"no request", "cases:\n  - name: a\n    expect: {action: allow}\n", nil, "give exactly one of file, url and uri"},
		{"url and uri", "cases:\n  - name: a\n    request: {uri: /, url: http://a/}\n    expect: {action: allow}\n", nil, "give exactly one of file, url and uri"},
		{"relative uri", "cases:\n  - name: a\n    request: {uri: a}\n    expect: {action: allow}\n", nil, "must start with /"},
		{"file and body", "cases:\n  - name: a\n    request: {file: r.http, body: x}\n    expect: {action: allow}\n", nil, "don't apply to a file"},
		{"bad action", "cases:\n  - name: a\n    request: {uri: /}\n    expect: {action: block}\n", nil, "action must be allow, deny or log"},
		{"nothing expected", "cases:\n  - name: a\n    request: {uri: /}\n    expect: {}\n", nil, "nothing expected"},
		{"response phase without a response", "cases:\n  - name: a\n    request: {uri: /}\n    expect: {phase: response}\n", nil, "phase response needs a response"},
		{"rules and exactRules", "cases:\n  - name: a\n    request: {uri: /}\n    expect: {rules: [1], exactRules: [1]}\n", nil, "rules or exactRules"},
		{"bad client IP", "cases:\n  - name: a\n    request: {uri: /, clientIP: x}\n    expect: {action: allow}\n", nil, "clientIP"},
		{"responses with --engine", "cases:\n  - name: a\n    request: {uri: /}\n    response: {status: 200}\n    expect: {action: allow}\n", []string{"--engine", "http://127.0.0.1:1"}, "--engine's check API has no response"},
		{"a policy twice", "policy: p.yaml\ncases:\n  - name: a" + request, []string{"--policy", "p.yaml"}, "the suite names its policies"},
		{"--expect", "cases:\n  - name: a" + request, []string{"--expect", "deny"}, "don't apply to --suite"},
		{"a URL too", "cases:\n  - name: a" + request, []string{"http://a/"}, "give exactly one of URL, --request, --har and --suite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"test", "--suite", writeSuite(t, tc.suite, map[string]string{})}, tc.args...)
			code, stdout, stderr := runCLI(t, args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, want 2 and %q\n%s%s", code, tc.want, stdout, stderr)
			}
		})
	}
	if code, _, stderr := runCLI(t, "test", "--junit", "out.xml", "http://a/"); code != 2 || !strings.Contains(stderr, "--junit applies only to --suite") {
		t.Errorf("--junit without --suite: exit %d, %s", code, stderr)
	}
	// A case whose file is missing can't be checked: the others still run.
	path := writeSuite(t, "cases:\n  - name: missing\n    request: {file: nowhere.http}\n    expect: {action: allow}\n  - name: b"+request, map[string]string{})
	if code, stdout, _ := runCLI(t, "test", "--suite", path); code != 2 || !strings.Contains(stdout, "ERROR missing:") || !strings.Contains(stdout, "ok    b\n") {
		t.Errorf("missing file: exit %d\n%s", code, stdout)
	}
}
