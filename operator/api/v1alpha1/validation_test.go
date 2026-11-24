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
		// grpcSchema (#316): read with the messages only.
		{name: "grpcSchema", doc: policy(target + "  body: {grpcMessages: Inspect, grpcSchema: {configMapRef: {name: s, key: set.binpb}}}\n")},
		{name: "grpcSchema without grpcMessages", doc: policy(target + "  body: {grpcSchema: {configMapRef: {name: s, key: set.binpb}}}\n"),
			wantErr: "grpcSchema needs grpcMessages: Inspect"},
		{name: "grpcSchema with Skip", doc: policy(target + "  body: {grpcMessages: Skip, grpcSchema: {configMapRef: {name: s, key: set.binpb}}}\n"),
			wantErr: "grpcSchema needs grpcMessages: Inspect"},
		{name: "grpcSchema without a ConfigMap", doc: policy(target + "  body: {grpcMessages: Inspect, grpcSchema: {}}\n"), wantErr: "configMapRef: Required"},
		{name: "grpcSchema without a key", doc: policy(target + "  body: {grpcMessages: Inspect, grpcSchema: {configMapRef: {name: s}}}\n"), wantErr: "key: Required"},

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
		{name: "response limits without inspect", doc: policy(target + "  responses: {maxBytes: 1024}\n"), wantErr: "maxBytes, onOversize and streams: Inspect need inspect: true"},
		{name: "response oversize without inspect", doc: policy(target + "  responses: {inspect: false, onOversize: Deny}\n"), wantErr: "maxBytes, onOversize and streams: Inspect need inspect: true"},
		// Streams, event by event (#323).
		{name: "streams inspected", doc: policy(target + "  responses: {inspect: true, streams: Inspect}\n")},
		{name: "streams skipped", doc: policy(target + "  responses: {inspect: true, streams: Skip}\n")},
		{name: "streams without inspect", doc: policy(target + "  responses: {streams: Inspect}\n"), wantErr: "maxBytes, onOversize and streams: Inspect need inspect: true"},
		{name: "streams Skip without inspect", doc: policy(target + "  responses: {streams: Skip}\n")},
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
		{name: "rate limit over a million requests", doc: policy(target + "  rateLimits: [{name: a, requests: 1000001, period: 1s}]\n"), wantErr: "requests and burst are at most 1000000"},
		{name: "rate limit burst over a million", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, burst: 1000001}]\n"), wantErr: "requests and burst are at most 1000000"},
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
		{name: "rate limit clean paths", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {paths: [/, \"/*\", /a/, \"/a/*\", /.well-known/x, /a/...b, /a.b, \"//*\"]}}]\n")},
		{name: "rate limit unknown method", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {methods: [PURGE]}}]\n"), wantErr: `Unsupported value: "PURGE"`},
		{name: "rate limit repeated method", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {methods: [GET, GET]}}]\n"), wantErr: "Duplicate value"},
		{name: "rate limit in Block mode", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, mode: Block}]\n"), wantErr: "a rate limit's mode can only be Detect"},

		// The CRS settings under crs (#714); the binding-level pair is
		// deprecated, still accepted alone or next to other crs settings.
		{name: "crs paranoia level and threshold", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, crs: {paranoiaLevel: 2, inboundAnomalyThreshold: 7}}]\n")},
		{name: "deprecated paranoia level beside crs", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, paranoiaLevel: 2, crs: {inboundAnomalyThreshold: 7}}]\n")},
		{name: "paranoia level twice", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, paranoiaLevel: 2, crs: {paranoiaLevel: 2}}]\n"), wantErr: "set crs.paranoiaLevel, not also the deprecated paranoiaLevel"},
		{name: "threshold twice", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, inboundAnomalyThreshold: 7, crs: {inboundAnomalyThreshold: 7}}]\n"), wantErr: "set crs.inboundAnomalyThreshold, not also the deprecated inboundAnomalyThreshold"},
		{name: "crs paranoia level over 4", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, crs: {paranoiaLevel: 5}}]\n"), wantErr: "should be less than or equal to 4"},
		{name: "crs threshold 0", doc: policy(target + "  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}, crs: {inboundAnomalyThreshold: 0}}]\n"), wantErr: "should be greater than or equal to 1"},

		// Repeats in the lists v1 makes sets, and a header with [ ], are
		// warned by the webhook and accepted until v1 (#717).
		{name: "skip path twice", doc: policy(target + "  skip: {paths: [/a, /a], bodyPaths: [/b, /b]}\n")},
		{name: "rule ID twice", doc: policy(target + "  exclusions: [{ruleIDs: [942100, 942100]}]\n")},
		{name: "exclusion header with brackets", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {header: \"X-A[0]\"}}]\n")},
		{name: "exclusion argument pattern", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {argument: \"user[name]\"}}]\n")},
		{name: "exclusion cookie with a space", doc: policy(target + "  exclusions: [{ruleIDs: [942100], when: {cookie: \"a b\"}}]\n"), wantErr: "spec.exclusions[0].when.cookie"},
		// New in 0.7.0, so a set already.
		{name: "rate limit path twice", doc: policy(target + "  rateLimits: [{name: a, requests: 1, period: 1s, match: {paths: [/login, /login]}}]\n"), wantErr: "Duplicate value"},
		// Geo blocking (design 0011 §2.4).
		{name: "geo deny", doc: policy(target + "  geo: {deny: [RU, KP], unknown: Deny, mode: Detect}\n")},
		{name: "geo allow", doc: policy(target + "  geo: {allow: [DE, AT, CH, XK, XA]}\n")},
		{name: "geo both lists", doc: policy(target + "  geo: {deny: [RU], allow: [DE]}\n"), wantErr: "geo needs exactly one of deny and allow"},
		{name: "geo no list", doc: policy(target + "  geo: {unknown: Deny}\n"), wantErr: "geo needs exactly one of deny and allow"},
		{name: "geo empty list", doc: policy(target + "  geo: {deny: []}\n"), wantErr: "should have at least 1 items"},
		{name: "geo lower case", doc: policy(target + "  geo: {deny: [de]}\n"), wantErr: "spec.geo.deny[0]"},
		{name: "geo three letters", doc: policy(target + "  geo: {deny: [DEU]}\n"), wantErr: "spec.geo.deny[0]"},
		{name: "geo repeated code", doc: policy(target + "  geo: {deny: [RU, RU]}\n"), wantErr: "Duplicate value"},
		{name: "geo 251 codes", doc: policy(target + "  geo: {deny: [" + geoCodes(251) + "]}\n"), wantErr: "must have at most 250 items"},
		{name: "geo unknown value", doc: policy(target + "  geo: {deny: [RU], unknown: Maybe}\n"), wantErr: `Unsupported value: "Maybe"`},
		{name: "geo Block mode", doc: policy(target + "  geo: {deny: [RU], mode: Block}\n"), wantErr: `Unsupported value: "Block"`},

		// Custom denials (#725).
		{name: "deny response HTML", doc: policy(target + "  denyResponse: {contentType: text/html, body: \"<h1>Blocked</h1><p>{{request_id}}</p>\"}\n")},
		{name: "deny response with charset", doc: policy(target + "  denyResponse: {contentType: \"Text/Plain; charset=UTF-8\", body: blocked}\n")},
		{name: "deny response problem JSON", doc: policy(target + "  denyResponse: {contentType: application/problem+json, body: '{\"title\":\"Forbidden\"}'}\n")},
		{name: "deny response JavaScript", doc: policy(target + "  denyResponse: {contentType: text/javascript, body: x}\n"), wantErr: "contentType must be text/html, text/plain, application/json or application/problem+json"},
		{name: "deny response another charset", doc: policy(target + "  denyResponse: {contentType: \"text/html; charset=iso-8859-1\", body: x}\n"), wantErr: "contentType must be"},
		{name: "deny response without a body", doc: policy(target + "  denyResponse: {contentType: text/html}\n"), wantErr: "spec.denyResponse.body: Required value"},
		{name: "deny response empty body", doc: policy(target + "  denyResponse: {contentType: text/html, body: \"\"}\n"), wantErr: "spec.denyResponse.body"},
		{name: "deny response of 8 KiB", doc: policy(target + "  denyResponse: {contentType: text/plain, body: " + strings.Repeat("a", 8192) + "}\n")},
		{name: "deny response over 8 KiB", doc: policy(target + "  denyResponse: {contentType: text/plain, body: " + strings.Repeat("a", 8193) + "}\n"), wantErr: "spec.denyResponse.body"},
		// Bytes of UTF-8, not characters: 2,731 euro signs are 8,193 bytes.
		{name: "deny response over 8 KiB of UTF-8", doc: policy(target + "  denyResponse: {contentType: text/plain, body: " + strings.Repeat("€", 2731) + "}\n"), wantErr: "body must be at most 8 KiB"},

		// LLM APIs (#277, design 0012 §3.5).
		{name: "llm", doc: policy(target + `  llm:
    endpoints:
    - {paths: ["/v1/chat/completions", "/openai/deployments/*"], format: OpenAIChat}
    - {paths: ["/v1/messages"], format: AnthropicMessages}
    - {paths: ["/v1/responses"], format: OpenAIResponses}
    - {paths: ["/v1/embeddings"], format: OpenAIEmbeddings}
    maxBodyBytes: 1048576
    ruleSetBody: Inspect
    request:
      models: ["llama-3.1-8b-instruct", "qwen2.5-*", "meta-llama/Llama-3.1-8B-Instruct", "llama3.2:3b"]
      maxPromptBytes: 262144
      maxMessages: 256
      maxOutputTokens: 4096
      requireOutputTokens: true
      maxChoices: 1
      clientRoles: [user, assistant]
      tools: {allow: Listed, names: [search_docs, get_weather, web_search_preview]}
      mode: Detect
`)},
		{name: "llm endpoints only", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/*], format: OpenAIChat}]}\n")},
		{name: "llm eight endpoints of 16 paths", doc: policy(target + "  llm: {endpoints: [" + llmEndpoints(8, 16) + "]}\n")},
		{name: "llm tools none", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/*], format: OpenAIChat}], request: {tools: {allow: None}}}\n")},
		{name: "llm without endpoints", doc: policy(target + "  llm: {maxBodyBytes: 2048}\n"), wantErr: "spec.llm.endpoints: Required value"},
		{name: "llm no endpoint", doc: policy(target + "  llm: {endpoints: []}\n"), wantErr: "spec.llm.endpoints"},
		{name: "llm nine endpoints", doc: policy(target + "  llm: {endpoints: [" + llmEndpoints(9, 1) + "]}\n"), wantErr: "must have at most 8 items"},
		{name: "llm path in two endpoints", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/a, /v1/b], format: OpenAIChat}, {paths: [/v1/b], format: AnthropicMessages}]}\n"), wantErr: "an endpoint path can't be in two endpoints"},
		{name: "llm path twice", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/a, /v1/a], format: OpenAIChat}]}\n"), wantErr: "Duplicate value"},
		{name: "llm endpoint without paths", doc: policy(target + "  llm: {endpoints: [{format: OpenAIChat}]}\n"), wantErr: "spec.llm.endpoints[0].paths: Required value"},
		{name: "llm relative path", doc: policy(target + "  llm: {endpoints: [{paths: [v1/chat], format: OpenAIChat}]}\n"), wantErr: "spec.llm.endpoints[0].paths[0]"},
		{name: "llm unknown format", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/a], format: Gemini}]}\n"), wantErr: `Unsupported value: "Gemini"`},
		{name: "llm body under 1 KiB", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], maxBodyBytes: 1023}\n"), wantErr: "should be greater than or equal to 1024"},
		{name: "llm body over 10 MiB", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], maxBodyBytes: 10485761}\n"), wantErr: "should be less than or equal to 10485760"},
		{name: "llm unknown ruleSetBody", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], ruleSetBody: Some}\n"), wantErr: `Unsupported value: "Some"`},
		{name: "llm model a lone *", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {models: [\"*\"]}}\n"), wantErr: "spec.llm.request.models[0]"},
		{name: "llm model * inside", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {models: [\"a*b\"]}}\n"), wantErr: "spec.llm.request.models[0]"},
		{name: "llm model with a space", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {models: [\"a b\"]}}\n"), wantErr: "spec.llm.request.models[0]"},
		{name: "llm model twice", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {models: [a, a]}}\n"), wantErr: "Duplicate value"},
		{name: "llm prompt cap 0", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {maxPromptBytes: 0}}\n"), wantErr: "should be greater than or equal to 1"},
		{name: "llm prompt cap over 10 MiB", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {maxPromptBytes: 10485761}}\n"), wantErr: "should be less than or equal to 10485760"},
		{name: "llm messages over 100000", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {maxMessages: 100001}}\n"), wantErr: "should be less than or equal to 100000"},
		{name: "llm output over 10 million", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {maxOutputTokens: 10000001}}\n"), wantErr: "should be less than or equal to 10000000"},
		{name: "llm choices over 128", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {maxChoices: 129}}\n"), wantErr: "should be less than or equal to 128"},
		{name: "llm unknown role", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {clientRoles: [root]}}\n"), wantErr: `Unsupported value: "root"`},
		{name: "llm role twice", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {clientRoles: [user, user]}}\n"), wantErr: "Duplicate value"},
		{name: "llm tools listed without names", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {tools: {allow: Listed}}}\n"), wantErr: "names is required with allow: Listed"},
		{name: "llm tool names without Listed", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {tools: {names: [a]}}}\n"), wantErr: "names is required with allow: Listed, and only allowed with it"},
		{name: "llm tool names with None", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {tools: {allow: None, names: [a]}}}\n"), wantErr: "only allowed with it"},
		{name: "llm tool name with a space", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {tools: {allow: Listed, names: [\"a b\"]}}}\n"), wantErr: "spec.llm.request.tools.names[0]"},
		// Token limits (design 0012 §6).
		{name: "token limit", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/*], format: OpenAIChat}]}\n  rateLimits: [{name: t, requests: 1000000000, burst: 1000000000, period: 1m, cost: LLMTokens, key: {header: {name: Authorization}}}]\n")},
		{name: "token limit over a billion", doc: policy(target + "  llm: {endpoints: [{paths: [/v1/*], format: OpenAIChat}]}\n  rateLimits: [{name: t, requests: 1000000001, period: 1m, cost: LLMTokens}]\n"), wantErr: "should be less than or equal to 1000000000"},
		{name: "token limit without spec.llm", doc: policy(target + "  rateLimits: [{name: t, requests: 1000, period: 1m, cost: LLMTokens}]\n"), wantErr: "a rate limit with cost: LLMTokens needs spec.llm"},
		{name: "request limit, cost Requests", doc: policy(target + "  rateLimits: [{name: r, requests: 10, period: 1m, cost: Requests}]\n")},
		{name: "unknown cost", doc: policy(target + "  rateLimits: [{name: r, requests: 10, period: 1m, cost: Bytes}]\n"), wantErr: `Unsupported value: "Bytes"`},
		{name: "llm checks in Block mode", doc: policy(target + "  llm: {endpoints: [{paths: [/a], format: OpenAIChat}], request: {mode: Block}}\n"), wantErr: "the LLM checks' mode can only be Detect"},
	})
}

// llmEndpoints is n endpoints of paths paths each, all different: the
// largest the CRD allows must stay within the CEL cost budget.
func llmEndpoints(n, paths int) string {
	var es []string
	for i := range n {
		var ps []string
		for j := range paths {
			ps = append(ps, fmt.Sprintf("/v%d/%s%d", i, strings.Repeat("p", 900), j))
		}
		es = append(es, "{paths: ["+strings.Join(ps, ", ")+"], format: OpenAIChat}")
	}
	return strings.Join(es, ", ")
}

// geoCodes is n distinct two-letter codes, comma-separated.
func geoCodes(n int) string {
	var codes []string
	for a := 'A'; a <= 'Z' && len(codes) < n; a++ {
		for b := 'A'; b <= 'Z' && len(codes) < n; b++ {
			codes = append(codes, string([]rune{a, b}))
		}
	}
	return strings.Join(codes, ", ")
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
	if timeout, _, _ := unstructured.NestedString(u.Object, "spec", "timeout"); timeout != "250ms" {
		t.Errorf("timeout defaulted to %q, want 250ms", timeout)
	}

	// The static defaults are in the API (#718); responses that aren't
	// inspected still take streams: Skip, the default. A list item's
	// field gets none: GitOps diffs would show every policy changed.
	u = object(t, policy(target+"  ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: crs}}]\n  responses: {inspect: false}\n"))
	if err := c.Create(context.Background(), u, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	rs, _, _ := unstructured.NestedSlice(u.Object, "spec", "ruleSets")
	if _, ok := rs[0].(map[string]any)["placement"]; len(rs) != 1 || ok {
		t.Errorf("ruleSets %v, want placement left unset", rs)
	}
	if streams, _, _ := unstructured.NestedString(u.Object, "spec", "responses", "streams"); streams != "Skip" {
		t.Errorf("responses.streams defaulted to %q, want Skip", streams)
	}
}

func inkwallConfig(name, spec string) string {
	return "apiVersion: waf.inkwall.dev/v1alpha1\nkind: InkwallConfig\nmetadata: {name: " + name + "}\nspec:\n" + spec
}

const controlPlane = "  controlPlane:\n    endpoint: grpcs://agents.inkwall.example.com:443\n    enrollmentSecretRef: {name: inkwall-enrollment, namespace: inkwall-system}\n"

func TestInkwallConfigValidation(t *testing.T) {
	check(t, []validationCase{
		{name: "empty", doc: inkwallConfig("default", "  {}\n")},
		{name: "geo file", doc: inkwallConfig("default", "  geo: {database: {file: /var/lib/inkwall/geo/GeoLite2-Country.mmdb}}\n")},
		{name: "geo file in a subdirectory", doc: inkwallConfig("default", "  geo: {database: {file: /var/lib/inkwall/geo/maxmind/country.mmdb}}\n")},
		{name: "geo secret", doc: inkwallConfig("default", "  geo: {database: {secretRef: {name: geo-db, key: country.mmdb}}}\n")},
		{name: "geo both sources", doc: inkwallConfig("default", "  geo: {database: {file: /var/lib/inkwall/geo/a.mmdb, secretRef: {name: geo-db, key: k}}}\n"), wantErr: "exactly one of file and secretRef"},
		{name: "geo no source", doc: inkwallConfig("default", "  geo: {database: {}}\n"), wantErr: "exactly one of file and secretRef"},
		{name: "geo file elsewhere", doc: inkwallConfig("default", "  geo: {database: {file: /var/run/secrets/kubernetes.io/serviceaccount/token}}\n"), wantErr: "spec.geo.database.file"},
		{name: "geo file escaping", doc: inkwallConfig("default", "  geo: {database: {file: /var/lib/inkwall/geo/../../../etc/passwd}}\n"), wantErr: "spec.geo.database.file"},
		{name: "geo file the directory", doc: inkwallConfig("default", "  geo: {database: {file: /var/lib/inkwall/geo/}}\n"), wantErr: "spec.geo.database.file"},
		{name: "geo file relative", doc: inkwallConfig("default", "  geo: {database: {file: GeoLite2-Country.mmdb}}\n"), wantErr: "spec.geo.database.file"},
		{name: "geo without a database", doc: inkwallConfig("default", "  geo: {}\n"), wantErr: "spec.geo.database: Required value"},
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
		{name: "deny response", doc: inkwallConfig("default", "  engine: {denyResponse: {contentType: application/json, body: '{\"id\":\"{{request_id}}\"}'}}\n")},
		{name: "deny response XML", doc: inkwallConfig("default", "  engine: {denyResponse: {contentType: application/xml, body: x}}\n"), wantErr: "contentType must be"},
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

func exportConfig(sinks string) string {
	return inkwallConfig("default", "  events:\n    export:\n      sinks:\n"+sinks)
}

// Every CEL rule and schema bound of design 0010 §4.5, accepted and refused.
func TestInkwallConfigExportValidation(t *testing.T) {
	otel := "      - {name: otel, otlp: {endpoint: \"grpc://otel.observability:4317\"}, insecure: true}\n"
	check(t, []validationCase{
		{name: "full", doc: inkwallConfig("default", `
  events:
    export:
      clusterName: prod-eu-1.example
      sinks:
      - name: collector
        otlp: {endpoint: "grpc://otel-collector.observability:4317"}
        insecure: true
      - name: splunk
        json:
          url: https://splunk.example.com:8088/services/collector/raw?sourcetype=_json
          framing: Lines
        headersSecretRef: {name: splunk-hec}
        tls:
          caSecretRef: {name: splunk-ca}
          clientCertificateSecretRef: {name: splunk-client}
          serverName: splunk.example.com
        compression: None
        batch: {maxEvents: 1000, maxDelay: 100ms, maxInFlight: 1}
        timeout: 60s
        filter:
          actions: [Deny]
          policyNamespaces: [shop, payments]
        omit: [Snippets, ClientIP, UserAgent, RequestID]
      - name: sumo
        json:
          urlSecretRef: {name: sumo-url, key: url}
          framing: Array
        batch: {maxEvents: 1, maxDelay: 60s, maxInFlight: 4}
        timeout: 1s
      - name: otlp-http
        otlp: {endpoint: "https://otlp.example.com/v1/logs"}
`)},
		{name: "no sinks", doc: inkwallConfig("default", "  events: {export: {clusterName: prod}}\n")},
		{name: "five sinks", doc: exportConfig(otel +
			"      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}}\n      - {name: b, otlp: {endpoint: \"grpcs://b:4317\"}}\n" +
			"      - {name: c, otlp: {endpoint: \"grpcs://c:4317\"}}\n      - {name: d, otlp: {endpoint: \"grpcs://d:4317\"}}\n"), wantErr: "must have at most 4 items"},
		{name: "repeated name", doc: exportConfig(otel + otel), wantErr: "sinks must not repeat a name"},
		{name: "name not a DNS label", doc: exportConfig("      - {name: Otel_1, otlp: {endpoint: \"grpcs://a:4317\"}}\n"), wantErr: "spec.events.export.sinks[0].name"},
		{name: "cluster name not a DNS subdomain", doc: inkwallConfig("default", "  events: {export: {clusterName: \"Prod EU\"}}\n"), wantErr: "spec.events.export.clusterName"},
		{name: "neither otlp nor json", doc: exportConfig("      - {name: a}\n"), wantErr: "a sink needs exactly one of otlp and json"},
		{name: "both otlp and json", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, json: {url: \"https://a\"}}\n"), wantErr: "a sink needs exactly one of otlp and json"},
		{name: "json without url", doc: exportConfig("      - {name: a, json: {framing: Lines}}\n"), wantErr: "json needs exactly one of url and urlSecretRef"},
		{name: "json with url and urlSecretRef", doc: exportConfig("      - {name: a, json: {url: \"https://a\", urlSecretRef: {name: s, key: url}}}\n"), wantErr: "json needs exactly one of url and urlSecretRef"},
		{name: "grpc endpoint with a path", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317/v1/logs\"}}\n"), wantErr: "spec.events.export.sinks[0].otlp.endpoint"},
		{name: "otlp user info", doc: exportConfig("      - {name: a, otlp: {endpoint: \"https://user:pass@a/v1/logs\"}}\n"), wantErr: "spec.events.export.sinks[0].otlp.endpoint"},
		{name: "json user info", doc: exportConfig("      - {name: a, json: {url: \"https://user:pass@a/in\"}}\n"), wantErr: "spec.events.export.sinks[0].json.url"},
		{name: "json not http", doc: exportConfig("      - {name: a, json: {url: \"ftp://a/in\"}}\n"), wantErr: "spec.events.export.sinks[0].json.url"},
		{name: "otlp unknown scheme", doc: exportConfig("      - {name: a, otlp: {endpoint: \"tcp://a:4317\"}}\n"), wantErr: "spec.events.export.sinks[0].otlp.endpoint"},
		{name: "json url with a space", doc: exportConfig("      - {name: a, json: {url: \"https://a/in put\"}}\n"), wantErr: "spec.events.export.sinks[0].json.url"},
		{name: "json url too long", doc: exportConfig("      - {name: a, json: {url: \"https://a/" + strings.Repeat("x", 2048) + "\"}}\n"), wantErr: "spec.events.export.sinks[0].json.url"},
		{name: "plaintext grpc without insecure", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpc://a:4317\"}}\n"), wantErr: "needs insecure: true"},
		{name: "plaintext http otlp without insecure", doc: exportConfig("      - {name: a, otlp: {endpoint: \"http://a:4318/v1/logs\"}}\n"), wantErr: "needs insecure: true"},
		{name: "plaintext json without insecure", doc: exportConfig("      - {name: a, json: {url: \"http://a/in\"}}\n"), wantErr: "needs insecure: true"},
		{name: "plaintext json with insecure", doc: exportConfig("      - {name: a, json: {url: \"http://a/in\"}, insecure: true}\n")},
		{name: "plaintext with headers", doc: exportConfig("      - {name: a, otlp: {endpoint: \"http://a:4318/v1/logs\"}, insecure: true, headersSecretRef: {name: h}}\n"), wantErr: "can't have headersSecretRef"},
		{name: "plaintext json with headers", doc: exportConfig("      - {name: a, json: {url: \"http://a/in\"}, insecure: true, headersSecretRef: {name: h}}\n"), wantErr: "can't have headersSecretRef"},
		{name: "URL Secret with insecure", doc: exportConfig("      - {name: a, json: {urlSecretRef: {name: s, key: url}}, insecure: true}\n"), wantErr: "a URL from a Secret holds a credential"},
		{name: "URL Secret with headers", doc: exportConfig("      - {name: a, json: {urlSecretRef: {name: s, key: url}}, headersSecretRef: {name: h}}\n")},
		{name: "TLS with headers", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, headersSecretRef: {name: h}}\n")},
		{name: "unknown framing", doc: exportConfig("      - {name: a, json: {url: \"https://a\", framing: CSV}}\n"), wantErr: `Unsupported value: "CSV"`},
		{name: "unknown compression", doc: exportConfig("      - {name: a, json: {url: \"https://a\"}, compression: Zstd}\n"), wantErr: `Unsupported value: "Zstd"`},
		{name: "secret key with a slash", doc: exportConfig("      - {name: a, json: {urlSecretRef: {name: s, key: a/b}}}\n"), wantErr: "spec.events.export.sinks[0].json.urlSecretRef.key"},
		{name: "server name with a port", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, tls: {serverName: \"a:443\"}}\n"), wantErr: "spec.events.export.sinks[0].tls.serverName"},
		{name: "max events 0", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxEvents: 0}}\n"), wantErr: "should be greater than or equal to 1"},
		{name: "max events over 1000", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxEvents: 1001}}\n"), wantErr: "should be less than or equal to 1000"},
		{name: "max in flight 0", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxInFlight: 0}}\n"), wantErr: "should be greater than or equal to 1"},
		{name: "max in flight over 4", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxInFlight: 5}}\n"), wantErr: "should be less than or equal to 4"},
		{name: "max delay under 100ms", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxDelay: 99ms}}\n"), wantErr: "maxDelay must be from 100ms to 60s"},
		{name: "max delay over 60s", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, batch: {maxDelay: 61s}}\n"), wantErr: "maxDelay must be from 100ms to 60s"},
		{name: "timeout under 1s", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, timeout: 999ms}\n"), wantErr: "timeout must be from 1s to 60s"},
		{name: "timeout over 60s", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, timeout: 2m}\n"), wantErr: "timeout must be from 1s to 60s"},
		{name: "unknown action", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, filter: {actions: [Allow]}}\n"), wantErr: `Unsupported value: "Allow"`},
		{name: "action twice", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, filter: {actions: [Deny, Deny]}}\n"), wantErr: "Duplicate value"},
		{name: "policy namespace not a DNS label", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, filter: {policyNamespaces: [Shop]}}\n"), wantErr: "spec.events.export.sinks[0].filter.policyNamespaces[0]"},
		{name: "policy namespace twice", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, filter: {policyNamespaces: [shop, shop]}}\n"), wantErr: "Duplicate value"},
		{name: "unknown omit", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, omit: [Path]}\n"), wantErr: `Unsupported value: "Path"`},
		{name: "omit twice", doc: exportConfig("      - {name: a, otlp: {endpoint: \"grpcs://a:4317\"}, omit: [ClientIP, ClientIP]}\n"), wantErr: "Duplicate value"},
	})
}

// A sink's unset compression and framing stay unset (Gzip and Lines): a
// default inside a list item would make GitOps diffs show every sink
// changed.
func TestInkwallConfigExportDefaults(t *testing.T) {
	c := newClient(t)
	u := object(t, exportConfig("      - {name: a, json: {url: \"https://a/in\"}}\n"))
	if err := c.Create(context.Background(), u, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	sinks, _, _ := unstructured.NestedSlice(u.Object, "spec", "events", "export", "sinks")
	if len(sinks) != 1 {
		t.Fatalf("sinks = %v", sinks)
	}
	s := sinks[0].(map[string]any)
	framing, _, _ := unstructured.NestedString(s, "json", "framing")
	compression, _, _ := unstructured.NestedString(s, "compression")
	if framing != "" || compression != "" {
		t.Errorf("framing %q, compression %q, want both unset", framing, compression)
	}
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
		// Warned by the webhook, refused by v1 only (#717).
		{name: "a CIDR twice", doc: ipListDoc("  entries: [{cidr: 203.0.113.0/24}, {cidr: 203.0.113.0/24, description: again}]\n")},
	})
}
