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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
  - {group: networking.istio.io, kind: VirtualService, name: shop}
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
  webSocket:
    allowedOrigins: ["https://app.example.com", "http://localhost:3000", "https://*.example.net"]
    allowMissingOrigin: true
    requiredHeaders: [Authorization, Sec-WebSocket-Protocol]
  responses:
    inspect: true
    maxBytes: 524288
    onOversize: Allow
`)},

		{name: "no targets", doc: policy("  targetRefs: []\n"), wantErr: "should have at least 1 items"},
		{name: "missing targets", doc: policy("  mode: Block\n"), wantErr: "spec.targetRefs: Required value"},
		{name: "unknown target kind", doc: policy("  targetRefs: [{kind: Service, name: shop}]\n"), wantErr: `Unsupported value: "Service"`},
		{name: "Ingress in the Gateway API group", doc: policy("  targetRefs: [{group: gateway.networking.k8s.io, kind: Ingress, name: shop}]\n"), wantErr: "target must be a networking.k8s.io Ingress"},
		{name: "HTTPRoute without its group", doc: policy("  targetRefs: [{kind: HTTPRoute, name: shop}]\n"), wantErr: "target must be a networking.k8s.io Ingress"},
		{name: "IngressRoute without its group", doc: policy("  targetRefs: [{kind: IngressRoute, name: shop}]\n"), wantErr: "a traefik.io IngressRoute or"},
		{name: "IngressRoute in another group", doc: policy("  targetRefs: [{group: networking.k8s.io, kind: IngressRoute, name: shop}]\n"), wantErr: "a traefik.io IngressRoute or"},
		{name: "VirtualService without its group", doc: policy("  targetRefs: [{kind: VirtualService, name: shop}]\n"), wantErr: "or a networking.istio.io VirtualService"},
		{name: "VirtualService in another group", doc: policy("  targetRefs: [{group: gateway.networking.k8s.io, kind: VirtualService, name: shop}]\n"), wantErr: "or a networking.istio.io VirtualService"},
		{name: "sectionName on a VirtualService", doc: policy("  targetRefs: [{group: networking.istio.io, kind: VirtualService, name: shop, sectionName: a}]\n"), wantErr: "sectionName is only allowed for an HTTPRoute"},
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
		{name: "rule set before the CRS", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}}, {ref: {kind: WAFRuleSet, name: tune}, placement: BeforeCRS}]\n")},
		{name: "rule set after the CRS", doc: policy(target + "  ruleSets: [{ref: {kind: WAFRuleSet, name: custom}, placement: AfterCRS}]\n")},
		{name: "unknown placement", doc: policy(target + "  ruleSets: [{ref: {kind: WAFRuleSet, name: tune}, placement: First}]\n"), wantErr: `Unsupported value: "First"`},

		{name: "exclusion without rules", doc: policy(target + "  exclusions: [{ruleIDs: []}]\n"), wantErr: "should have at least 1 items"},
		{name: "exclusion missing rules", doc: policy(target + "  exclusions: [{when: {path: /api/*}}]\n"), wantErr: "ruleIDs is required"},
		{name: "exclusion with null rules", doc: policy(target + "  exclusions: [{ruleIDs: null}]\n"), wantErr: "ruleIDs is required"},
		{name: "exclusion of rule 0", doc: policy(target + "  exclusions: [{ruleIDs: [0]}]\n"), wantErr: "should be greater than or equal to 1"},
		{name: "empty exclusion match", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {}}]\n"), wantErr: "when needs a path, or what in the request to stop looking at"},
		{name: "exclusion for a cookie", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {cookie: session}}]\n")},
		{name: "exclusion for a header on a path", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {path: /api/*, header: X-Token}}]\n")},
		{name: "exclusion for an argument name", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {argumentName: q}}]\n")},
		{name: "exclusion for an argument and a cookie", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {argument: q, cookie: session}}]\n"), wantErr: "at most one of argument, argumentName, cookie and header"},
		{name: "colon in an exclusion header", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {header: 'X-A:b'}}]\n"), wantErr: "spec.exclusions[0].when.header"},
		{name: "quote in an exclusion cookie", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {cookie: 'a\"b'}}]\n"), wantErr: "spec.exclusions[0].when.cookie"},
		// The argument name ends up in a SecLang directive: quotes and
		// spaces could change the directive, so they are rejected.
		{name: "quote in an exclusion argument", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {argument: 'q\" \"id:1'}}]\n"), wantErr: "spec.exclusions[0].when.argument"},

		{name: "body over 10 MiB", doc: policy(target + "  body: {maxBytes: 10485761}\n"), wantErr: "should be less than or equal to 10485760"},
		{name: "unknown oversize action", doc: policy(target + "  body: {onOversize: InspectPrefix}\n"), wantErr: `Unsupported value: "InspectPrefix"`},
		{name: "grpc Deny", doc: policy(target + "  body: {grpc: Deny}\n")},
		{name: "unknown grpc action", doc: policy(target + "  body: {grpc: Block}\n"), wantErr: `Unsupported value: "Block"`},
		// grpcStreams (#315): PerMessage needs the messages inspected.
		{name: "grpcStreams PerMessage", doc: policy(target + "  body: {grpcMessages: Inspect, grpcStreams: PerMessage}\n")},
		{name: "grpcStreams Buffer alone", doc: policy(target + "  body: {grpcStreams: Buffer}\n")},
		{name: "grpcStreams PerMessage without grpcMessages", doc: policy(target + "  body: {grpcStreams: PerMessage}\n"),
			wantErr: "grpcStreams: PerMessage needs grpcMessages: Inspect"},
		{name: "grpcStreams PerMessage with Skip", doc: policy(target + "  body: {grpcMessages: Skip, grpcStreams: PerMessage}\n"),
			wantErr: "grpcStreams: PerMessage needs grpcMessages: Inspect"},
		{name: "grpcStreams PerMessage without body inspection", doc: policy(target + "  body: {inspect: false, grpcMessages: Inspect, grpcStreams: PerMessage}\n"),
			wantErr: "grpcStreams: PerMessage needs grpcMessages: Inspect"},
		{name: "unknown grpcStreams", doc: policy(target + "  body: {grpcMessages: Inspect, grpcStreams: Stream}\n"), wantErr: `Unsupported value: "Stream"`},

		{name: "websocket required headers only", doc: policy(target + "  webSocket: {requiredHeaders: [X-Api-Key]}\n")},
		{name: "websocket origin with a path", doc: policy(target + "  webSocket: {allowedOrigins: [\"https://app.example.com/\"]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket origin without a scheme", doc: policy(target + "  webSocket: {allowedOrigins: [app.example.com]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket origin ws scheme", doc: policy(target + "  webSocket: {allowedOrigins: [\"wss://app.example.com\"]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket origin upper case", doc: policy(target + "  webSocket: {allowedOrigins: [\"https://App.example.com\"]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket wildcard inside an origin", doc: policy(target + "  webSocket: {allowedOrigins: [\"https://a.*.example.com\"]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket any origin", doc: policy(target + "  webSocket: {allowedOrigins: [\"*\"]}\n"), wantErr: "spec.webSocket.allowedOrigins[0]"},
		{name: "websocket repeated origin", doc: policy(target + "  webSocket: {allowedOrigins: [\"https://a.example\", \"https://a.example\"]}\n"), wantErr: "Duplicate value"},
		{name: "websocket header with a colon", doc: policy(target + "  webSocket: {requiredHeaders: [\"X-Api:\"]}\n"), wantErr: "spec.webSocket.requiredHeaders[0]"},
		{name: "websocket missing origin without origins", doc: policy(target + "  webSocket: {allowMissingOrigin: true}\n"), wantErr: "allowMissingOrigin needs allowedOrigins"},
		{name: "responses inspected", doc: policy(target + "  responses: {inspect: true}\n")},
		{name: "responses not inspected", doc: policy(target + "  responses: {inspect: false}\n")},
		{name: "response body over 10 MiB", doc: policy(target + "  responses: {inspect: true, maxBytes: 10485761}\n"), wantErr: "should be less than or equal to 10485760"},
		{name: "zero response body", doc: policy(target + "  responses: {inspect: true, maxBytes: 0}\n"), wantErr: "should be greater than or equal to 1"},
		{name: "unknown response oversize action", doc: policy(target + "  responses: {inspect: true, onOversize: Truncate}\n"), wantErr: `Unsupported value: "Truncate"`},
		// Limits without inspection would read as if responses were inspected.
		{name: "response limits without inspect", doc: policy(target + "  responses: {maxBytes: 1024}\n"), wantErr: "maxBytes, onOversize and streams need inspect: true"},
		{name: "response oversize without inspect", doc: policy(target + "  responses: {inspect: false, onOversize: Deny}\n"), wantErr: "maxBytes, onOversize and streams need inspect: true"},
		// Streams, event by event (#323).
		{name: "streams inspected", doc: policy(target + "  responses: {inspect: true, streams: Inspect}\n")},
		{name: "streams skipped", doc: policy(target + "  responses: {inspect: true, streams: Skip}\n")},
		{name: "streams without inspect", doc: policy(target + "  responses: {streams: Inspect}\n"), wantErr: "maxBytes, onOversize and streams need inspect: true"},
		{name: "unknown streams action", doc: policy(target + "  responses: {inspect: true, streams: Buffer}\n"), wantErr: `Unsupported value: "Buffer"`},

		// Rate limits (#705, design 0009 §3.5).
		{name: "rate limits", doc: policy(target + `  rateLimits:
  - name: login
    requests: 10
    period: 1m
    burst: 20
    key: {clientIP: {ipv6PrefixLength: 64}}
    match: {paths: ["/login", "/api/session/*"], methods: [POST]}
  - {name: api, requests: 600, period: 1m, key: {header: {name: X-Api-Key}}, mode: Detect}
  - {name: all, requests: 1000000, period: 1h}
  - {name: fast, requests: 1, period: 1s}
`)},
		{name: "rate limit repeated name", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s}, {name: a, requests: 2, period: 1s}]\n"), wantErr: "rateLimits must not repeat a name"},
		{name: "nine rate limits", doc: policy(target + "  rateLimits: [" + strings.TrimSuffix(strings.Repeat("{name: a, requests: 1, period: 1s},", 9), ",") + "]\n"), wantErr: "must have at most 8 items"},
		{name: "rate limit name not a DNS label", doc: policy(target + "  rateLimits: [{name: Login_1, requests: 1, period: 1s}]\n"), wantErr: "spec.rateLimits[0].name"},
		{name: "rate limit without requests", doc: policy(target + "  rateLimits: [{name: a, period: 1s}]\n"), wantErr: "spec.rateLimits[0].requests: Required value"},
		{name: "rate limit of 0 requests", doc: policy(target + "  rateLimits: [{name: a, requests: 0, period: 1s}]\n"), wantErr: "should be greater than or equal to 1"},
		{name: "rate limit over a million requests", doc: policy(target + "  rateLimits: [{name: a, requests: 1000001, period: 1s}]\n"), wantErr: "should be less than or equal to 1000000"},
		{name: "rate limit period under 1s", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 500ms}]\n"), wantErr: "period must be 1s to 1h"},
		{name: "rate limit period over 1h", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 2h}]\n"), wantErr: "period must be 1s to 1h"},
		{name: "rate limit burst of 0", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, burst: 0}]\n"), wantErr: "should be greater than or equal to 1"},
		{name: "rate limit with both keys", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {clientIP: {}, header: {name: X-Key}}}]\n"), wantErr: "key needs exactly one of clientIP and header"},
		{name: "rate limit with no key", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {}}]\n"), wantErr: "key needs exactly one of clientIP and header"},
		{name: "rate limit IPv6 prefix /16", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {clientIP: {ipv6PrefixLength: 16}}}]\n"), wantErr: "should be greater than or equal to 32"},
		{name: "rate limit by X-Forwarded-For", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {header: {name: x-forwarded-For}}}]\n"), wantErr: "count by clientIP, not by X-Forwarded-For, Forwarded or Host"},
		{name: "rate limit by Host", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {header: {name: HOST}}}]\n"), wantErr: "count by clientIP"},
		{name: "rate limit by a pseudo-header", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, key: {header: {name: \":authority\"}}}]\n"), wantErr: "spec.rateLimits[0].key.header.name"},
		{name: "rate limit relative path", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {paths: [login]}}]\n"), wantErr: "spec.rateLimits[0].match.paths[0]"},
		{name: "rate limit unknown method", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {methods: [PURGE]}}]\n"), wantErr: `Unsupported value: "PURGE"`},
		{name: "rate limit repeated method", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {methods: [GET, GET]}}]\n"), wantErr: "Duplicate value"},
		{name: "rate limit in Block mode", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, mode: Block}]\n"), wantErr: "a rate limit's mode can only be Detect"},
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
    logLevel: Warn
    policyMetrics: true
  integrations:
  - controller: traefik
    selector: {matchLabels: {app.kubernetes.io/name: traefik}}
    adapter: ForwardAuth
  - controller: envoy-gateway
    adapter: ExtProc
  suspend: false
  events:
    redact:
      headers: [X-Tenant-Secret]
      arguments: [email, "user[phone]"]
      snippets: false
`+controlPlane)},

		{name: "rate limit keys", doc: inkwallConfig("default", "  engine: {rateLimitKeys: 1048576}\n")},
		{name: "JSON denials", doc: inkwallConfig("default", "  engine: {denialFormat: JSON}\n")},
		{name: "text denials", doc: inkwallConfig("default", "  engine: {denialFormat: Text}\n")},
		{name: "unknown denial format", doc: inkwallConfig("default", "  engine: {denialFormat: HTML}\n"), wantErr: `Unsupported value: "HTML"`},
		// Deprecated: still accepted, alone or agreeing with denialFormat.
		{name: "deprecated jsonDenials", doc: inkwallConfig("default", "  engine: {jsonDenials: true}\n")},
		{name: "jsonDenials with denialFormat JSON", doc: inkwallConfig("default", "  engine: {jsonDenials: true, denialFormat: JSON}\n")},
		{name: "jsonDenials false with denialFormat Text", doc: inkwallConfig("default", "  engine: {jsonDenials: false, denialFormat: Text}\n")},
		{name: "jsonDenials contradicting denialFormat", doc: inkwallConfig("default", "  engine: {jsonDenials: true, denialFormat: Text}\n"), wantErr: "jsonDenials: true contradicts denialFormat: Text"},
		{name: "too few rate limit keys", doc: inkwallConfig("default", "  engine: {rateLimitKeys: 100}\n"), wantErr: "should be greater than or equal to 1024"},
		{name: "too many rate limit keys", doc: inkwallConfig("default", "  engine: {rateLimitKeys: 20000000}\n"), wantErr: "should be less than or equal to 16777216"},
		{name: "not named default", doc: inkwallConfig("prod", "  {}\n"), wantErr: "the InkwallConfig must be named default"},
		{name: "GitOps without a control plane", doc: inkwallConfig("default", "  mode: GitOps\n"), wantErr: "controlPlane is required in GitOps and Managed mode"},
		{name: "Managed without a control plane", doc: inkwallConfig("default", "  mode: Managed\n"), wantErr: "controlPlane is required in GitOps and Managed mode"},
		{name: "Managed", doc: inkwallConfig("default", "  mode: Managed\n"+controlPlane)},
		{name: "unknown mode", doc: inkwallConfig("default", "  mode: Hybrid\n"), wantErr: `Unsupported value: "Hybrid"`},
		{name: "enrollment Secret without a namespace", doc: inkwallConfig("default", "  mode: GitOps\n  controlPlane:\n    endpoint: grpcs://agents.example.com:443\n    enrollmentSecretRef: {name: e}\n")},
		{name: "enrollment Secret with an empty namespace", doc: inkwallConfig("default", "  mode: GitOps\n  controlPlane:\n    endpoint: grpcs://agents.example.com:443\n    enrollmentSecretRef: {name: e, namespace: \"\"}\n"), wantErr: "spec.controlPlane.enrollmentSecretRef.namespace"},
		{name: "rollout", doc: inkwallConfig("default", "  engine: {rollout: Automatic}\n")},
		// Warned by the webhook, refused by v1 only.
		{name: "controller that isn't a DNS label", doc: inkwallConfig("default", "  integrations: [{controller: Ingress_Nginx}]\n")},
		{name: "plaintext control plane", doc: inkwallConfig("default", "  mode: GitOps\n  controlPlane:\n    endpoint: http://agents.example.com\n    enrollmentSecretRef: {name: e, namespace: inkwall-system}\n"), wantErr: "spec.controlPlane.endpoint"},
		// Deprecated and ignored: any value stays accepted.
		{name: "deprecated socket dir", doc: inkwallConfig("default", "  engine: {socketDir: run/inkwall}\n")},
		{name: "unknown adapter", doc: inkwallConfig("default", "  integrations: [{controller: traefik, adapter: Plugin}]\n"), wantErr: `Unsupported value: "Plugin"`},
		{name: "integration listed twice", doc: inkwallConfig("default", "  integrations: [{controller: traefik}, {controller: traefik}]\n"), wantErr: "Duplicate value"},
		{name: "empty selector", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {}}]\n"), wantErr: "selector must not be empty"},
		{name: "selector with empty labels", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {matchLabels: {}}}]\n"), wantErr: "selector must not be empty"},
		{name: "unknown log level", doc: inkwallConfig("default", "  engine: {logLevel: verbose}\n"), wantErr: `Unsupported value: "verbose"`},
		{name: "redacted header with a space", doc: inkwallConfig("default", "  events: {redact: {headers: [\"X Tenant\"]}}\n"), wantErr: "spec.events.redact.headers[0]"},
		{name: "empty redacted argument", doc: inkwallConfig("default", "  events: {redact: {arguments: [\"\"]}}\n"), wantErr: "spec.events.redact.arguments[0]"},
		{name: "redacted argument pattern listed twice", doc: inkwallConfig("default", "  events: {redact: {arguments: [email, email]}}\n"), wantErr: "Duplicate value"},
		{name: "selector by expression", doc: inkwallConfig("default", "  integrations: [{controller: traefik, selector: {matchExpressions: [{key: app, operator: In, values: [edge]}]}}]\n")},
		{name: "client IP", doc: inkwallConfig("default", "  engine: {clientIP: {trustedProxies: [10.0.0.0/8, \"2001:db8::/32\", 192.0.2.1], trustedHops: 1}}\n")},
		{name: "client IP hops over 10", doc: inkwallConfig("default", "  engine: {clientIP: {trustedHops: 11}}\n"), wantErr: "should be less than or equal to 10"},
		{name: "client IP not a CIDR", doc: inkwallConfig("default", "  engine: {clientIP: {trustedProxies: [lb.example.com]}}\n"), wantErr: "spec.engine.clientIP.trustedProxies[0]"},
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
	// The blocks' defaults apply without the blocks (#712); logLevel stays
	// unset, which pinned engines before 0.5.0 need.
	for _, d := range []struct {
		path []string
		want any
	}{
		{[]string{"spec", "engine", "bootstrapMode"}, "AllowAll"},
		{[]string{"spec", "engine", "rollout"}, "Manual"},
		{[]string{"spec", "events", "redact", "snippets"}, true},
		{[]string{"spec", "engine", "logLevel"}, nil},
	} {
		got, _, _ := unstructured.NestedFieldNoCopy(u.Object, d.path...)
		if got != d.want {
			t.Errorf("%s defaulted to %v, want %v", strings.Join(d.path, "."), got, d.want)
		}
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
	// The samples' namespace; already there when the test runs again
	// (-count): the samples are only dry-run, nothing is left in it.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "inkwall-demo"}}
	if err := c.Create(context.Background(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
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

func ipListDoc(spec string) string {
	return "apiVersion: waf.inkwall.dev/v1alpha1\nkind: WAFIPList\nmetadata: {name: l, namespace: default}\nspec:\n" + spec
}

func TestWAFIPListValidation(t *testing.T) {
	check(t, []validationCase{
		{name: "entries", doc: ipListDoc("  entries: [{cidr: 203.0.113.0/24, description: abuse}, {cidr: \"2001:db8::/32\"}, {cidr: 192.0.2.1}]\n")},
		{name: "no entries", doc: ipListDoc("  entries: []\n"), wantErr: "should have at least 1 items"},
		{name: "missing entries", doc: ipListDoc("  {}\n"), wantErr: "entries is required"},
		{name: "null entries", doc: ipListDoc("  entries: null\n"), wantErr: "entries is required"},
		{name: "missing spec", doc: "apiVersion: waf.inkwall.dev/v1alpha1\nkind: WAFIPList\nmetadata: {name: l, namespace: default}\n", wantErr: "spec: Required value"},
		{name: "a host name", doc: ipListDoc("  entries: [{cidr: lb.example.com}]\n"), wantErr: "spec.entries[0].cidr"},
		{name: "policy lists", doc: policy(target + "  ipLists: {allow: [monitors], deny: [abusers]}\n")},
	})
}
