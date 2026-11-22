// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// fieldNumbers is a gRPC message field named by its numbers ("2.1"), as
// messages read without a schema name them.
var fieldNumbers = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// grpcSchemaWarnings warns of the exclusions of a policy with a gRPC schema
// whose argument names a message field by numbers (design 0013 §12): with
// the schema, a described field is named by its path (user.name), so the
// exclusion matches only fields the schema doesn't describe.
func grpcSchemaWarnings(p *wafv1alpha1.WAFPolicy) admission.Warnings {
	if b := p.Spec.Body; b == nil || b.GRPCSchema == nil {
		return nil
	}
	var warnings admission.Warnings
	for i, e := range p.Spec.Exclusions {
		if e.When == nil || !fieldNumbers.MatchString(string(e.When.Argument)) {
			continue
		}
		path := field.NewPath("spec", "exclusions").Index(i).Child("when", "argument")
		warnings = append(warnings, fmt.Sprintf("%s: %q names a gRPC message field by numbers, but with spec.body.grpcSchema the fields "+
			"the schema describes are named by their paths (user.name): it matches only fields the schema doesn't describe. "+
			"Read the policy's events in Detect mode for the names (docs/grpc.md)", path, e.When.Argument))
	}
	return warnings
}
