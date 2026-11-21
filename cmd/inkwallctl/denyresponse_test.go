// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestTestPolicyDenyResponse: a policy's spec.denyResponse shows on its
// denials, and --json has the body with the request ID in it (#725).
func TestTestPolicyDenyResponse(t *testing.T) {
	policy := writeFile(t, "wafpolicy.yaml", `apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: api, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: api}]
  mode: Block
  denyResponse:
    contentType: application/json
    body: '{"error":"blocked","request_id":"{{request_id}}"}'
`)
	requests := writeFile(t, "requests.http",
		"GET /api/a?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"+
			"GET /api/a HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
	code, out, errOut := runCLI(t, "test", "--request", requests, "--policy", policy, "--ingress", sampleIngresses)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `denial="application/json",`) || strings.Contains(lines[1], "denial=") {
		t.Errorf("output:\n%s", out)
	}
	code, out, errOut = runCLI(t, "test", "--json", "--request", requests, "--policy", policy, "--ingress", sampleIngresses)
	if code != 0 || errOut != "" {
		t.Fatalf("--json: exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, `"deny_content_type":"application/json"`) || !strings.Contains(out, `"deny_body":"{\"error\":\"blocked\",\"request_id\":\"`) {
		t.Errorf("--json output:\n%s", out)
	}
}
