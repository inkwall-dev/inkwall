// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// explain policy compiles the policy's gRPC schema as the operator does,
// and says what it describes or why it doesn't compile (#316).
func TestExplainPolicyGRPCSchema(t *testing.T) {
	set, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto),
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(statusScheme()).WithObjects(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "schema"}, BinaryData: map[string][]byte{"set.binpb": set, "bad": []byte("nope")}},
	).Build()
	policy := func(cm, key string) *wafv1alpha1.WAFPolicy {
		return &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"}, Spec: wafv1alpha1.WAFPolicySpec{
			Body: &wafv1alpha1.BodySpec{GRPCMessages: wafv1alpha1.GRPCMessagesInspect,
				GRPCSchema: &wafv1alpha1.GRPCSchema{ConfigMapRef: wafv1alpha1.ConfigMapKeyRef{Name: cm, Key: key}}}}}
	}
	for _, tc := range []struct{ cm, key, want string }{
		{"schema", "set.binpb", "gRPC schema: shop/schema/set.binpb, 3 methods, "},
		{"schema", "bad", "gRPC schema: shop/schema/bad: not a FileDescriptorSet"},
		{"schema", "missing", `gRPC schema: shop/schema/missing: ConfigMap shop/schema has no key "missing"`},
		{"nope", "set.binpb", "gRPC schema: shop/nope/set.binpb: read ConfigMap shop/nope"},
	} {
		pe := &PolicyExplanation{GRPCSchema: grpcSchemaExplain(context.Background(), c, policy(tc.cm, tc.key))}
		var out bytes.Buffer
		printPolicyExplanation(&out, pe)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s/%s: %q lacks %q", tc.cm, tc.key, out.String(), tc.want)
		}
	}
	if grpcSchemaExplain(context.Background(), c, &wafv1alpha1.WAFPolicy{}) != nil {
		t.Error("a policy without a schema has one")
	}
}
