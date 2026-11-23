// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"crypto/sha256"
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// grpcSchema compiles the descriptor set c's spec.body.grpcSchema names
// (design 0013 §5.1), from a ConfigMap in the policy's namespace, and names
// it in c's policy. A ConfigMap or key that isn't there is InvalidRef, a set
// that doesn't compile InvalidGRPCSchema: c then fails, and keeps its
// previous version. A schema without grpcMessages: Inspect (which the CRD
// refuses) reads nothing, and isn't read.
func (r *resolution) grpcSchema(c *candidate) {
	b := c.obj.Spec.Body
	if b == nil || b.GRPCSchema == nil || b.GRPCMessages != wafv1alpha1.GRPCMessagesInspect || c.policy.GetBody() == nil {
		return
	}
	ref := b.GRPCSchema.ConfigMapRef
	key := types.NamespacedName{Namespace: c.key.Namespace, Name: ref.Name}
	cm, ok := r.configMaps[key]
	if !ok {
		c.fail(ReasonInvalidRef, fmt.Sprintf("spec.body.grpcSchema: ConfigMap %s not found, or not labeled %s=true", key, RulesLabel))
		return
	}
	data, ok := cm.BinaryData[ref.Key]
	if !ok {
		text, inData := cm.Data[ref.Key]
		if !inData {
			c.fail(ReasonInvalidRef, fmt.Sprintf("spec.body.grpcSchema: ConfigMap %s has no key %q", key, ref.Key))
			return
		}
		data = []byte(text)
	}
	source := key.String() + "/" + ref.Key
	s, cacheKey, err := r.in.GRPCSchemas.Compile(data, source)
	if r.schemaKeys == nil {
		r.schemaKeys = map[[sha256.Size]byte]bool{}
	}
	r.schemaKeys[cacheKey] = true
	if err != nil {
		c.fail(ReasonInvalidGRPCSchema, fmt.Sprintf("spec.body.grpcSchema: ConfigMap %s key %q: %v", key, ref.Key, err))
		return
	}
	if r.schemas == nil {
		r.schemas = map[string]*bundlev1.GRPCSchema{}
	}
	// Policies that name the same ConfigMap key share its entry (the id
	// covers the source).
	r.schemas[s.GetId()] = s
	c.policy.Body.GrpcSchemaId = s.GetId()
}
