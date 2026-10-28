// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// The CRD schemas and CEL rules are the first line of validation (0004
// §3.1): these tests send objects, as a user would write them, to a real API
// server with the generated CRDs installed.

var env *testenv.Env

func TestMain(m *testing.M) {
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func newClient(t *testing.T) client.Client {
	t.Helper()
	testenv.Skip(t, env)
	c, err := client.New(env.Config, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func object(t *testing.T, doc string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil {
		t.Fatalf("bad test YAML: %v\n%s", err, doc)
	}
	return u
}

type validationCase struct {
	name string
	doc  string
	// wantErr is a substring of the API server's error; empty means the
	// object must be accepted.
	wantErr string
}

// check creates each object with a dry run, so cases don't interfere and a
// singleton can be tried many times.
func check(t *testing.T, cases []validationCase) {
	c := newClient(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Create(context.Background(), object(t, tc.doc), client.DryRunAll)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("accepted, want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func policy(spec string) string {
	return "apiVersion: waf.inkwall.dev/v1alpha1\nkind: WAFPolicy\nmetadata: {name: shop, namespace: default}\nspec:\n" + spec
}

const target = "  targetRefs: [{kind: Ingress, name: shop}]\n"

func TestWAFPolicyValidation(t *testing.T) {
	check(t, []validationCase{
		{name: "minimal", doc: policy(target)},
		{name: "full", doc: policy(`
  targetRefs:
  - {kind: Ingress, name: shop}
  - {group: networking.k8s.io, kind: Ingress, name: shop-admin}
  - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: shop-api}
  - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: shop-api, sectionName: checkout}
  - {group: traefik.io, kind: IngressRoute, name: shop}
  mode: Block
  failureMode: Closed
  timeout: 250ms
  skip:
    paths: ["/healthz", "/static/*"]
    bodyPaths: ["/upload"]
  ruleSets:
  - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
    paranoiaLevel: 2
    inboundAnomalyThreshold: 7
  - ref: {kind: WAFRuleSet, name: shop-custom, namespace: shop}
  exclusions:
  - ruleIDs: [942100]
    when: {path: "/api/search", argument: q}
  - ruleIDs: [920350, 913100]
  body:
    inspect: true
    maxBytes: 131072
    onOversize: Deny
`)},

		{name: "no targets", doc: policy("  targetRefs: []\n"), wantErr: "should have at least 1 items"},
		{name: "missing targets", doc: policy("  mode: Block\n"), wantErr: "spec.targetRefs: Required value"},
		{name: "unknown target kind", doc: policy("  targetRefs: [{kind: Service, name: shop}]\n"), wantErr: `Unsupported value: "Service"`},
		{name: "Ingress in the Gateway API group", doc: policy("  targetRefs: [{group: gateway.networking.k8s.io, kind: Ingress, name: shop}]\n"), wantErr: "target must be a networking.k8s.io Ingress"},
		{name: "HTTPRoute without its group", doc: policy("  targetRefs: [{kind: HTTPRoute, name: shop}]\n"), wantErr: "target must be a networking.k8s.io Ingress"},
		{name: "IngressRoute without its group", doc: policy("  targetRefs: [{kind: IngressRoute, name: shop}]\n"), wantErr: "or a traefik.io IngressRoute"},
		{name: "IngressRoute in another group", doc: policy("  targetRefs: [{group: networking.k8s.io, kind: IngressRoute, name: shop}]\n"), wantErr: "or a traefik.io IngressRoute"},
		{name: "sectionName on an IngressRoute", doc: policy("  targetRefs: [{group: traefik.io, kind: IngressRoute, name: shop, sectionName: a}]\n"), wantErr: "sectionName is only allowed for an HTTPRoute"},
		{name: "sectionName on an Ingress", doc: policy("  targetRefs: [{kind: Ingress, name: shop, sectionName: a}]\n"), wantErr: "sectionName is only allowed for an HTTPRoute"},
		{name: "repeated target", doc: policy("  targetRefs: [{kind: Ingress, name: shop}, {group: networking.k8s.io, kind: Ingress, name: shop}]\n"), wantErr: "targetRefs must not repeat a target"},

		{name: "unknown mode", doc: policy(target + "  mode: BlockHighConfidence\n"), wantErr: `Unsupported value: "BlockHighConfidence"`},
		{name: "unknown failure mode", doc: policy(target + "  failureMode: Auto\n"), wantErr: `Unsupported value: "Auto"`},

		{name: "timeout over 1s", doc: policy(target + "  timeout: 2s\n"), wantErr: "timeout must be more than 0s and at most 1s"},
		{name: "zero timeout", doc: policy(target + "  timeout: 0s\n"), wantErr: "timeout must be more than 0s and at most 1s"},
		{name: "timeout of 1s", doc: policy(target + "  timeout: 1s\n")},

		{name: "relative skip path", doc: policy(target + "  skip: {paths: [static/*]}\n"), wantErr: "spec.skip.paths[0]"},
		{name: "star inside a skip path", doc: policy(target + "  skip: {paths: [\"/a*/b\"]}\n"), wantErr: "spec.skip.paths[0]"},
		{name: "encoded skip path", doc: policy(target + "  skip: {paths: [\"/a%20b\"]}\n"), wantErr: "spec.skip.paths[0]"},
		{name: "query in a body path", doc: policy(target + "  skip: {bodyPaths: [\"/upload?x=1\"]}\n"), wantErr: "spec.skip.bodyPaths[0]"},

		{name: "namespace on a cluster rule set", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs, namespace: shop}}]\n"), wantErr: "namespace is only allowed for a WAFRuleSet"},
		{name: "paranoia level 5", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, paranoiaLevel: 5}]\n"), wantErr: "should be less than or equal to 4"},
		{name: "zero anomaly threshold", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, inboundAnomalyThreshold: 0}]\n"), wantErr: "should be greater than or equal to 1"},

		{name: "exclusion without rules", doc: policy(target + "  exclusions: [{ruleIDs: []}]\n"), wantErr: "should have at least 1 items"},
		{name: "exclusion of rule 0", doc: policy(target + "  exclusions: [{ruleIDs: [0]}]\n"), wantErr: "should be greater than or equal to 1"},
		{name: "empty exclusion match", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {}}]\n"), wantErr: "when needs a path, an argument, or both"},
		// The argument name ends up in a SecLang directive: quotes and
		// spaces could change the directive, so they are rejected.
		{name: "quote in an exclusion argument", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {argument: 'q\" \"id:1'}}]\n"), wantErr: "spec.exclusions[0].when.argument"},

		{name: "body over 10 MiB", doc: policy(target + "  body: {maxBytes: 10485761}\n"), wantErr: "should be less than or equal to 10485760"},
		{name: "unknown oversize action", doc: policy(target + "  body: {onOversize: InspectPrefix}\n"), wantErr: `Unsupported value: "InspectPrefix"`},
	})
}

func TestWAFPolicyDefaults(t *testing.T) {
	c := newClient(t)
	u := object(t, policy(target+"  body: {maxBytes: 1024}\n"))
	if err := c.Create(context.Background(), u, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	if mode, _, _ := unstructured.NestedString(u.Object, "spec", "mode"); mode != "Detect" {
		t.Errorf("mode defaulted to %q, want Detect", mode)
	}
	if inspect, _, _ := unstructured.NestedBool(u.Object, "spec", "body", "inspect"); !inspect {
		t.Error("body.inspect did not default to true")
	}
}

func inkwallConfig(name, spec string) string {
	return "apiVersion: waf.inkwall.dev/v1alpha1\nkind: InkwallConfig\nmetadata: {name: " + name + "}\nspec:\n" + spec
}

const controlPlane = "  controlPlane:\n    endpoint: grpcs://agents.inkwall.example.com:443\n    enrollmentSecretRef: {name: inkwall-enrollment, namespace: inkwall-system}\n"

func TestInkwallConfigValidation(t *testing.T) {
	check(t, []validationCase{
		{name: "empty", doc: inkwallConfig("default", "  {}\n")},
		{name: "full", doc: inkwallConfig("default", `
  mode: GitOps
  engine:
    image: ghcr.io/inkwall-dev/inkwall-engine:v0.1.0
    resources:
      requests: {cpu: 500m, memory: 256Mi}
      limits: {memory: 512Mi}
    socketDir: /var/run/inkwall
  integrations:
  - controller: traefik
    selector: {matchLabels: {app.kubernetes.io/name: traefik}}
    adapter: ForwardAuth
  - controller: envoy-gateway
    adapter: ExtProc
  suspend: false
`+controlPlane)},

		{name: "not named default", doc: inkwallConfig("prod", "  {}\n"), wantErr: "the InkwallConfig must be named default"},
		{name: "GitOps without a control plane", doc: inkwallConfig("default", "  mode: GitOps\n"), wantErr: "controlPlane is required in GitOps and Managed mode"},
		{name: "Managed without a control plane", doc: inkwallConfig("default", "  mode: Managed\n"), wantErr: "controlPlane is required in GitOps and Managed mode"},
		{name: "Managed", doc: inkwallConfig("default", "  mode: Managed\n"+controlPlane)},
		{name: "unknown mode", doc: inkwallConfig("default", "  mode: Hybrid\n"), wantErr: `Unsupported value: "Hybrid"`},
		{name: "plaintext control plane", doc: inkwallConfig("default", "  mode: GitOps\n  controlPlane:\n    endpoint: http://agents.example.com\n    enrollmentSecretRef: {name: e, namespace: inkwall-system}\n"), wantErr: "spec.controlPlane.endpoint"},
		{name: "relative socket dir", doc: inkwallConfig("default", "  engine: {socketDir: run/inkwall}\n"), wantErr: "socketDir must be an absolute path"},
		{name: "unknown adapter", doc: inkwallConfig("default", "  integrations: [{controller: traefik, adapter: Plugin}]\n"), wantErr: `Unsupported value: "Plugin"`},
		{name: "integration listed twice", doc: inkwallConfig("default", "  integrations: [{controller: traefik}, {controller: traefik}]\n"), wantErr: "Duplicate value"},
		{name: "empty selector", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {}}]\n"), wantErr: "selector must not be empty"},
		{name: "selector with empty labels", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {matchLabels: {}}}]\n"), wantErr: "selector must not be empty"},
		{name: "selector by expression", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {matchExpressions: [{key: app, operator: In, values: [edge]}]}}]\n")},
	})
}

func TestInkwallConfigDefaults(t *testing.T) {
	c := newClient(t)
	u := object(t, inkwallConfig("default", "  {}\n"))
	if err := c.Create(context.Background(), u, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	if mode, _, _ := unstructured.NestedString(u.Object, "spec", "mode"); mode != "Standalone" {
		t.Errorf("mode defaulted to %q, want Standalone", mode)
	}
}

func ruleSet(kind, source string) string {
	ns := "\n  namespace: default"
	if kind == "ClusterWAFRuleSet" {
		ns = ""
	}
	return "apiVersion: waf.inkwall.dev/v1alpha1\nkind: " + kind + "\nmetadata:\n  name: rules" + ns + "\nspec:\n  source:\n" + source
}

func TestRuleSetValidation(t *testing.T) {
	const seclang = "    seclang: |\n      SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \"id:100001,phase:1,deny,status:403\"\n"
	var cases []validationCase
	for _, kind := range []string{"WAFRuleSet", "ClusterWAFRuleSet"} {
		cases = append(cases,
			validationCase{name: kind + "/builtin", doc: ruleSet(kind, "    builtin: crs-v4\n")},
			validationCase{name: kind + "/seclang", doc: ruleSet(kind, seclang)},
			validationCase{name: kind + "/unknown builtin", doc: ruleSet(kind, "    builtin: crs-v3\n"), wantErr: `Unsupported value: "crs-v3"`},
			validationCase{name: kind + "/no source", doc: ruleSet(kind, "    {}\n"), wantErr: "set exactly one of builtin, seclang or configMapRef"},
			validationCase{name: kind + "/two sources", doc: ruleSet(kind, "    builtin: crs-v4\n"+seclang), wantErr: "set exactly one of builtin, seclang or configMapRef"},
			validationCase{name: kind + "/empty seclang", doc: ruleSet(kind, "    seclang: \"\"\n"), wantErr: "spec.source.seclang"},
		)
	}
	cases = append(cases,
		validationCase{name: "WAFRuleSet/configMapRef", doc: ruleSet("WAFRuleSet", "    configMapRef: {name: rules, key: rules.conf}\n")},
		validationCase{name: "ClusterWAFRuleSet/configMapRef", doc: ruleSet("ClusterWAFRuleSet", "    configMapRef: {name: rules, key: rules.conf, namespace: security}\n")},
		validationCase{name: "ClusterWAFRuleSet/configMapRef without namespace", doc: ruleSet("ClusterWAFRuleSet", "    configMapRef: {name: rules, key: rules.conf}\n"), wantErr: "spec.source.configMapRef.namespace: Required value"},
	)
	check(t, cases)
}

// TestSamples keeps operator/config/samples valid: they are what users try
// first.
func TestSamples(t *testing.T) {
	c := newClient(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "inkwall-demo"}}
	if err := c.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(testenv.SamplesDir(), "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no samples found (%v)", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			doc, err := os.ReadFile(f) // #nosec G304 -- test fixture
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Create(context.Background(), object(t, string(doc)), client.DryRunAll); err != nil {
				t.Fatal(err)
			}
		})
	}
}
