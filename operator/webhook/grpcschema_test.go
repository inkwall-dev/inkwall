// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// An exclusion naming a message field by numbers, on a policy with a gRPC
// schema, draws a warning; by name, or without a schema, none.
func TestGRPCSchemaWarnings(t *testing.T) {
	exclusion := func(argument string) wafv1alpha1.Exclusion {
		return wafv1alpha1.Exclusion{RuleIDs: []int32{942100}, When: &wafv1alpha1.ExclusionMatch{Argument: wafv1alpha1.ArgumentPattern(argument)}}
	}
	p := &wafv1alpha1.WAFPolicy{Spec: wafv1alpha1.WAFPolicySpec{
		Body: &wafv1alpha1.BodySpec{GRPCMessages: wafv1alpha1.GRPCMessagesInspect,
			GRPCSchema: &wafv1alpha1.GRPCSchema{ConfigMapRef: wafv1alpha1.ConfigMapKeyRef{Name: "s", Key: "k"}}},
		Exclusions: []wafv1alpha1.Exclusion{exclusion("2.1"), exclusion("user.name"), exclusion("7"), {RuleIDs: []int32{1}}},
	}}
	w := grpcSchemaWarnings(p)
	if len(w) != 2 || !strings.Contains(w[0], "spec.exclusions[0].when.argument") || !strings.Contains(w[1], "spec.exclusions[2].when.argument") {
		t.Fatalf("warnings %q", w)
	}
	p.Spec.Body.GRPCSchema = nil
	if w := grpcSchemaWarnings(p); w != nil {
		t.Fatalf("without a schema: %q", w)
	}
}
