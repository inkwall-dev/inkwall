// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

// testGRPCSchema follows a policy's gRPC schema (#316) from its ConfigMap
// to the bundle and the policy's status, through a set that doesn't
// compile, which keeps the previous version in force.
func testGRPCSchema(ctx context.Context, t *testing.T, c client.Client) {
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "grpc"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, o := range []client.Object{&wafv1alpha1.WAFPolicy{}, &corev1.ConfigMap{}, &networkingv1.Ingress{}} {
			if err := c.DeleteAllOf(ctx, o, client.InNamespace("grpc")); err != nil {
				t.Error(err)
			}
		}
	})
	set, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto),
	}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "grpc", Name: "api"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "grpc.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "api", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "grpc", Name: "schema", Labels: map[string]string{resolver.RulesLabel: "true"}},
		BinaryData: map[string][]byte{"set.binpb": set},
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "grpc", Name: "api"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "api"}},
			Body: &wafv1alpha1.BodySpec{
				GRPCMessages: wafv1alpha1.GRPCMessagesInspect,
				GRPCSchema:   &wafv1alpha1.GRPCSchema{ConfigMapRef: wafv1alpha1.ConfigMapKeyRef{Name: "schema", Key: "set.binpb"}},
			},
		},
	}
	for _, o := range []client.Object{ing, cm, pol} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// schemaOf returns the schema the bundle's policy names, or why not.
	schemaOf := func(b *bundlev1.Bundle) (*bundlev1.GRPCSchema, string) {
		p := findPolicy(b, "grpc/api")
		if p == nil {
			return nil, "not in the bundle"
		}
		id := p.GetBody().GetGrpcSchemaId()
		for _, s := range b.GetGrpcSchemas() {
			if s.GetId() == id {
				return s, ""
			}
		}
		return nil, fmt.Sprintf("names schema %q, which the bundle's %d schemas don't hold", id, len(b.GetGrpcSchemas()))
	}
	wantAccepted := func(what string, status metav1.ConditionStatus, reason, msg string) {
		t.Helper()
		eventually(t, what, func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &got); err != nil {
				return err.Error()
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionAccepted)
			if cond == nil || cond.Status != status || cond.Reason != reason || !strings.Contains(cond.Message, msg) || cond.ObservedGeneration != got.Generation {
				return fmt.Sprintf("Accepted %v", cond)
			}
			return ""
		})
	}

	var first *bundlev1.GRPCSchema
	eventually(t, "schema published", func() string {
		s, why := schemaOf(current(ctx, t, c))
		if s == nil {
			return why
		}
		if s.GetSource() != "grpc/schema/set.binpb" || len(s.GetMethods()) == 0 || s.GetMethods()[0].GetPath() != "/grpc.health.v1.Health/Check" {
			return "unexpected schema: " + s.String()
		}
		first = s
		return ""
	})
	wantAccepted("accepted", metav1.ConditionTrue, resolver.ReasonAccepted, resolver.PolicyValid)

	// A set that doesn't compile: InvalidGRPCSchema, and the bundle keeps
	// the previous version with its schema.
	update(ctx, t, c, cm, func(cm *corev1.ConfigMap) { cm.BinaryData["set.binpb"] = []byte("not a descriptor set") })
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
	wantAccepted("bad set reported", metav1.ConditionFalse, resolver.ReasonInvalidGRPCSchema, "the previous version of the policy stays in force")
	b := current(ctx, t, c)
	if s, why := schemaOf(b); s == nil || !proto.Equal(s, first) {
		t.Fatalf("the previous schema isn't in force: %s %v", why, s)
	}
	if findPolicy(b, "grpc/api").GetMode() == bundlev1.Mode_MODE_BLOCK {
		t.Fatal("the edit with a bad set took effect")
	}

	// A missing key: InvalidRef. Fixed: accepted and published again.
	update(ctx, t, c, cm, func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"other": set} })
	wantAccepted("missing key reported", metav1.ConditionFalse, resolver.ReasonInvalidRef, `has no key "set.binpb"`)
	update(ctx, t, c, cm, func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"set.binpb": set} })
	wantAccepted("fixed set accepted", metav1.ConditionTrue, resolver.ReasonAccepted, resolver.PolicyValid)
	eventually(t, "fixed set published", func() string {
		b := current(ctx, t, c)
		if s, why := schemaOf(b); s == nil {
			return why
		}
		if findPolicy(b, "grpc/api").GetMode() != bundlev1.Mode_MODE_BLOCK {
			return "the edit isn't in force"
		}
		return ""
	})
}
