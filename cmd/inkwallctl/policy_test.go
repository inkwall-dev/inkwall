// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// The sample objects: two policies of one host, routed by path.
var (
	samplePolicies   = filepath.Join("testdata", "policy", "wafpolicy.yaml")
	sampleRuleSets   = filepath.Join("testdata", "policy", "wafruleset.yaml")
	sampleConfigMaps = filepath.Join("testdata", "policy", "configmap.yaml")
	sampleIngresses  = filepath.Join("testdata", "policy", "ingress.yaml")
	sampleRequests   = filepath.Join("testdata", "policy", "requests.http")
	sampleObjects    = []string{"--policy", samplePolicies, "--rule-set", sampleRuleSets, "--configmap", sampleConfigMaps, "--ingress", sampleIngresses}
)

// inspectionTime matches the time at the end of a verdict line.
var inspectionTime = regexp.MustCompile(`(?m)  [0-9.]+(ns|µs|ms|s)$`)

// golden compares got, with inspection times taken out, to a file in
// testdata; -update rewrites it.
func golden(t *testing.T, name, got string) {
	t.Helper()
	got = inspectionTime.ReplaceAllString(got, "  <time>")
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (go test -update rewrites it):\ngot:\n%s\nwant:\n%s", path, got, want)
	}
}

// buildBundle builds the sample objects' bundle as the operator's builder
// does (resolve, version, sign) and returns it as stored in the bundle
// Secret's bundle.pb.gz, with the signed bundle and the public key.
func buildBundle(t *testing.T) ([]byte, *bundlev1.SignedBundle, ed25519.PublicKey) {
	t.Helper()
	in, _, err := loadObjects([]string{samplePolicies, sampleRuleSets, sampleConfigMaps, sampleIngresses}, "default", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	in.CheckRules = coraza.CheckUserRules
	res := resolver.Resolve(in)
	next, _, err := bundle.Next(nil, &bundlev1.Bundle{ClusterId: "test", Policies: res.Policies, RuleSets: res.RuleSets}, 6,
		time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := bundle.NewSigner(priv)
	signed, err := signer.Sign(next)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := bundle.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, signed, signer.Public()
}

func TestTestPolicy(t *testing.T) {
	code, out, errOut := runCLI(t, append([]string{"test", "--request", sampleRequests}, sampleObjects...)...)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	golden(t, "policy.golden", out)

	// A directory, as kept next to the application in Git, with every kind.
	code, out, errOut = runCLI(t, "test", "--request", sampleRequests, "--policy", filepath.Dir(samplePolicies))
	if code != 0 || errOut != "" {
		t.Fatalf("directory: exit %d, stderr %q", code, errOut)
	}
	golden(t, "policy.golden", out)

	// A bundle the operator built from the same objects gives the same
	// verdicts.
	encoded, signed, pub := buildBundle(t)
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := yaml.Marshal(&corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "inkwall-bundle", Namespace: "inkwall-system"},
		Data:       map[string][]byte{secretBundleKey: encoded, "ed25519.pub": pub},
	})
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writeFile(t, "ed25519.pub", string(pub))
	for _, tc := range []struct {
		name, bundle, key, note string
	}{
		{"bundle.pb.gz", string(encoded), keyFile, "note: bundle version 7, created 2026-10-01T12:00:00Z: 2 policies, signature verified\n"},
		{"uncompressed", string(raw), writeFile(t, "key.b64", base64.StdEncoding.EncodeToString(pub)+"\n"), "signature verified"},
		{"Secret", string(secret), "", "signature not checked (no --bundle-key)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"test", "--request", sampleRequests, "--bundle", writeFile(t, "bundle", tc.bundle)}
			if tc.key != "" {
				args = append(args, "--bundle-key", tc.key)
			}
			code, out, errOut := runCLI(t, args...)
			if code != 0 || !strings.Contains(errOut, tc.note) {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			golden(t, "policy.golden", out)
		})
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	code, _, errOut = runCLI(t, "test", "--request", sampleRequests, "--bundle", writeFile(t, "bundle", string(encoded)),
		"--bundle-key", writeFile(t, "other.pub", string(other.Public().(ed25519.PublicKey))))
	if code != 2 || !strings.Contains(errOut, "bad signature") {
		t.Fatalf("other key: exit %d, stderr %q", code, errOut)
	}
}

const singlePolicy = `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
spec:
  targetRefs: [{kind: Ingress, name: web}]
  mode: Block
`

func TestTestPolicyOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
		// out and errOut must be in stdout and stderr.
		out, errOut string
	}{
		{
			name:   "no --ingress: one policy applies to every request",
			args:   []string{"--policy", writeFile(t, "p.yaml", singlePolicy), "http://any.example.org" + sqli},
			out:    "deny  403  GET " + sqli + "  policy=default/web  reason=rule",
			errOut: "note: no --ingress: WAFPolicy default/web applies to every host and path\n",
		},
		{
			name:   "no --ingress, several targets",
			args:   []string{"--policy", writeFile(t, "p.yaml", strings.Replace(singlePolicy, "[{kind: Ingress, name: web}]", "[{kind: Ingress, name: a}, {kind: Ingress, name: b}, {kind: Ingress, name: c}]", 1)), "http://any.example.org" + sqli},
			out:    "deny  403  GET " + sqli + "  policy=default/web  reason=rule",
			errOut: "note: no --ingress: WAFPolicy default/web applies to every host and path\n",
		},
		{
			name:   "--namespace",
			args:   []string{"--namespace", "shop", "--policy", writeFile(t, "p.yaml", singlePolicy), "http://a/"},
			out:    "allow      GET /  policy=shop/web  ",
			errOut: "WAFPolicy shop/web applies",
		},
		{
			name: "--expect",
			args: append([]string{"--expect", "deny", "--request", sampleRequests}, sampleObjects...),
			code: 1, errOut: "5 of 7 request(s) did not get the expected verdict \"deny\"",
		},
		{
			name: "--json names the policy",
			args: append(append([]string{"--json"}, sampleObjects...), "http://shop.example.com/"),
			out:  `"policy":"shop/storefront"`,
		},
		{
			name: "a kubectl List with every kind, and other kinds skipped",
			args: []string{"--policy", writeFile(t, "list.json", `{"apiVersion":"v1","kind":"List","items":[
				{"apiVersion":"waf.inkwall.dev/v1alpha1","kind":"WAFPolicy","metadata":{"name":"web","namespace":"a","creationTimestamp":"2026-10-01T00:00:00Z"},
				 "spec":{"targetRefs":[{"kind":"Ingress","name":"web"}],"mode":"Block"},"status":{"bundleVersion":3}},
				{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"web","namespace":"a"},
				 "spec":{"rules":[{"host":"a.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"web","port":{"number":80}}}}]}}]}},
				{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web","namespace":"a"}}]}`),
				"http://b.example.com" + sqli},
			out:    "allow      GET " + sqli + "  reason=no_policy",
			errOut: "Deployment web skipped",
		},
		{
			name: "suspended",
			args: append(append([]string{"--policy", writeFile(t, "c.yaml", "apiVersion: waf.inkwall.dev/v1alpha1\nkind: InkwallConfig\nmetadata: {name: default}\nspec: {suspend: true}\n")},
				sampleObjects...), "http://shop.example.com"+sqli),
			out: "allow      GET " + sqli + "  reason=suspended",
		},
		{
			name:   "a missing target is a note",
			args:   []string{"--policy", writeFile(t, "p.yaml", strings.Replace(singlePolicy, "[{kind: Ingress, name: web}]", "[{kind: Ingress, name: web}, {kind: Ingress, name: gone}]", 1)), "--ingress", sampleIngresses, "http://a/"},
			out:    "allow      GET /  reason=no_policy",
			errOut: "note: WAFPolicy default/web: InvalidRef: Ingress web, Ingress gone not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, append([]string{"test"}, tc.args...)...)
			if code != tc.code || !strings.Contains(out, tc.out) || !strings.Contains(errOut, tc.errOut) {
				t.Fatalf("exit %d (want %d)\nstdout %q\nwant   %q\nstderr %q\nwant   %q", code, tc.code, out, tc.out, errOut, tc.errOut)
			}
		})
	}
}

func TestTestPolicyErrors(t *testing.T) {
	policy := writeFile(t, "p.yaml", singlePolicy)
	ruleSet := func(source string) string {
		return writeFile(t, "rs.yaml", "apiVersion: waf.inkwall.dev/v1alpha1\nkind: WAFRuleSet\nmetadata: {name: rs}\nspec:\n  source:\n"+source)
	}
	withRuleSet := strings.Replace(singlePolicy, "mode: Block", "ruleSets: [{ref: {kind: WAFRuleSet, name: rs}}]", 1)
	for _, tc := range []struct {
		name   string
		args   []string
		errOut string
	}{
		{"--policy and --rules", []string{"--policy", policy, "--rules", "x.conf"}, "--rules: set by the policies"},
		{"--bundle and --mode", []string{"--bundle", "b", "--mode", "detect"}, "--mode: set by the policies"},
		{"--policy and --bundle", []string{"--policy", policy, "--bundle", "b"}, "at most one of"},
		{"--ingress and --engine", []string{"--ingress", sampleIngresses, "--engine", "http://e"}, "at most one of"},
		{"--bundle-key alone", []string{"--bundle-key", "k"}, "--bundle-key applies only to --bundle"},
		{"--namespace alone", []string{"--namespace", "a"}, "--namespace applies only to --policy"},
		{"no policy", []string{"--rule-set", sampleRuleSets}, "no WAFPolicy in the files"},
		{"two policies, no routes", []string{"--policy", samplePolicies, "--rule-set", sampleRuleSets, "--configmap", sampleConfigMaps}, "give the Ingresses they target with --ingress"},
		{"missing rule set", []string{"--policy", writeFile(t, "p.yaml", withRuleSet)}, "WAFPolicy default/web: not enforced: InvalidRef: WAFRuleSet rs not found"},
		{"inline rules the webhook rejects", []string{"--policy", writeFile(t, "p.yaml", withRuleSet), "--rule-set", ruleSet("    seclang: SecRuleEngine Off\n")}, "WAFRuleSet default/rs: rejected by the validating webhook"},
		{"ConfigMap rules that don't compile", []string{"--policy", writeFile(t, "p.yaml", withRuleSet), "--rule-set", ruleSet("    configMapRef: {name: cm, key: r}\n"),
			"--configmap", writeFile(t, "cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm, labels: {waf.inkwall.dev/rules: \"true\"}}\ndata: {r: 'SecRule ARGS'}\n")},
			"WAFRuleSet default/rs: not accepted: RuleCompileError"},
		{"unlabeled ConfigMap", []string{"--policy", writeFile(t, "p.yaml", withRuleSet), "--rule-set", ruleSet("    configMapRef: {name: cm, key: r}\n"),
			"--configmap", writeFile(t, "cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm}\ndata: {r: ''}\n")},
			"is not labeled waf.inkwall.dev/rules=true"},
		{"misspelled field", []string{"--policy", writeFile(t, "p.yaml", singlePolicy+"  paranoiaLevl: 2\n")}, `WAFPolicy web: error unmarshaling JSON: while decoding JSON: json: unknown field "paranoiaLevl"`},
		{"wrong apiVersion", []string{"--policy", writeFile(t, "p.yaml", strings.Replace(singlePolicy, "v1alpha1", "v1", 1))}, `apiVersion "waf.inkwall.dev/v1", want "waf.inkwall.dev/v1alpha1"`},
		{"twice the same object", []string{"--policy", policy, "--ingress", policy}, "WAFPolicy default/web is also in"},
		{"empty directory", []string{"--policy", t.TempDir()}, "no .yaml, .yml or .json file"},
		{"no kind", []string{"--policy", writeFile(t, "p.yaml", "metadata: {name: x}\n")}, "an object without a kind"},
		{"not a bundle", []string{"--bundle", sampleRequests}, "not a signed bundle"},
		{"Secret without a bundle", []string{"--bundle", writeFile(t, "s.yaml", "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\n")}, "the Secret s has no bundle.pb.gz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, append([]string{"test"}, append(tc.args, "http://shop.example.com/")...)...)
			if code != 2 || !strings.Contains(errOut, tc.errOut) {
				t.Fatalf("exit %d, want 2; stderr %q, want %q", code, errOut, tc.errOut)
			}
		})
	}

	encoded, _, _ := buildBundle(t)
	code, _, errOut := runCLI(t, "test", "--bundle", writeFile(t, "b", string(encoded)), "--bundle-key", sampleRequests, "http://a/")
	if code != 2 || !strings.Contains(errOut, "want a raw 32-byte ed25519 key, or its base64") {
		t.Fatalf("bad key file: exit %d, stderr %q", code, errOut)
	}
}
