// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"strings"
	"testing"

	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/grpcschematest"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
)

// healthSet is grpc.health.v1's descriptor set.
func healthSet(t *testing.T) []byte {
	t.Helper()
	b, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func schemaConfigMap(name, key string, data []byte) corev1.ConfigMap {
	return corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, Labels: map[string]string{RulesLabel: "true"}},
		BinaryData: map[string][]byte{key: data},
	}
}

func schemaPolicy(name string, age int, cm, key string) wafv1alpha1.WAFPolicy {
	p := policy(name, age, name)
	p.Spec.Body = &wafv1alpha1.BodySpec{
		GRPCMessages: wafv1alpha1.GRPCMessagesInspect,
		GRPCSchema:   &wafv1alpha1.GRPCSchema{ConfigMapRef: wafv1alpha1.ConfigMapKeyRef{Name: cm, Key: key}},
	}
	return p
}

func TestGRPCSchema(t *testing.T) {
	cache := compile.NewCache()
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "schema", "set.binpb"), schemaPolicy("b", 1, "schema", "set.binpb")},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		ConfigMaps:  []corev1.ConfigMap{schemaConfigMap("schema", "set.binpb", healthSet(t))},
		GRPCSchemas: cache,
	}
	res := Resolve(in)
	wantStatus(t, res, "a", true, ReasonAccepted, PolicyValid)
	if len(res.GRPCSchemas) != 1 {
		t.Fatalf("%d schemas, want the two policies' one", len(res.GRPCSchemas))
	}
	s := res.GRPCSchemas[0]
	if s.GetSource() != "shop/schema/set.binpb" || len(s.GetMethods()) == 0 {
		t.Fatalf("schema %v", s)
	}
	for _, id := range []string{"shop/a", "shop/b"} {
		if got := findPolicy(res, id).GetBody().GetGrpcSchemaId(); got != s.GetId() {
			t.Fatalf("%s names schema %q, want %q", id, got, s.GetId())
		}
	}
	if cache.Len() != 1 {
		t.Fatalf("%d cached sets", cache.Len())
	}

	// Gzipped (by its magic bytes) and in data: the same schema.
	gz := in
	gz.ConfigMaps = []corev1.ConfigMap{{ObjectMeta: in.ConfigMaps[0].ObjectMeta, Data: map[string]string{"set.binpb": string(healthSet(t))}}}
	if got := Resolve(gz); len(got.GRPCSchemas) != 1 || got.GRPCSchemas[0].GetId() != s.GetId() {
		t.Fatalf("a set in data: %v", got.GRPCSchemas)
	}

	// Without grpcMessages: Inspect (refused by the CRD), nothing is read.
	off := in
	off.Policies = []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "missing", "x")}
	off.Policies[0].Spec.Body.GRPCMessages = ""
	got := Resolve(off)
	wantStatus(t, got, "a", true, ReasonAccepted, PolicyValid)
	if len(got.GRPCSchemas) != 0 || findPolicy(got, "shop/a").GetBody().GetGrpcSchemaId() != "" {
		t.Fatal("a schema without grpcMessages is read")
	}
	// A set no policy names any more leaves the cache.
	if cache.Len() != 0 {
		t.Fatalf("%d cached sets after no policy names one", cache.Len())
	}
}

// Policies of two namespaces with the same set: an entry each, naming its
// own ConfigMap, never the other namespace's.
func TestGRPCSchemaPerSource(t *testing.T) {
	other := schemaPolicy("b", 1, "schema", "set.binpb")
	other.Namespace = "web"
	cm := schemaConfigMap("schema", "set.binpb", healthSet(t))
	webCM := *cm.DeepCopy()
	webCM.Namespace = "web"
	webIng := ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix)))
	webIng.Namespace = "web"
	res := Resolve(Input{
		Policies:   []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "schema", "set.binpb"), other},
		Ingresses:  []networkingv1.Ingress{ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))), webIng},
		ConfigMaps: []corev1.ConfigMap{cm, webCM},
	})
	if len(res.GRPCSchemas) != 2 {
		t.Fatalf("%d schemas, want one per source", len(res.GRPCSchemas))
	}
	for _, id := range []string{"shop/a", "web/b"} {
		p := findPolicy(res, id)
		ns, _, _ := strings.Cut(id, "/")
		found := false
		for _, s := range res.GRPCSchemas {
			if s.GetId() == p.GetBody().GetGrpcSchemaId() {
				found = s.GetSource() == ns+"/schema/set.binpb"
			}
		}
		if !found {
			t.Errorf("%s doesn't name its own namespace's schema", id)
		}
	}
}

func TestGRPCSchemaFailures(t *testing.T) {
	good := healthSet(t)
	base := Input{
		Policies:   []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "schema", "set.binpb")},
		Ingresses:  []networkingv1.Ingress{ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix)))},
		ConfigMaps: []corev1.ConfigMap{schemaConfigMap("schema", "set.binpb", good)},
	}
	first := Resolve(base)
	prev := &bundlev1.Bundle{Version: 3, Policies: first.Policies, RuleSets: first.RuleSets, GrpcSchemas: first.GRPCSchemas}
	noService, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto)}})

	cases := []struct {
		name       string
		configMaps []corev1.ConfigMap
		reason     string
		msg        string
	}{
		{"no ConfigMap", nil, ReasonInvalidRef, "ConfigMap shop/schema not found, or not labeled"},
		{"no key", []corev1.ConfigMap{schemaConfigMap("schema", "other", good)}, ReasonInvalidRef, `has no key "set.binpb"`},
		{"not a set", []corev1.ConfigMap{schemaConfigMap("schema", "set.binpb", []byte("garbage!"))}, ReasonInvalidGRPCSchema, "not a FileDescriptorSet"},
		{"no service", []corev1.ConfigMap{schemaConfigMap("schema", "set.binpb", noService)}, ReasonInvalidGRPCSchema, "no service"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			in.ConfigMaps = c.configMaps
			// Never resolved: left out.
			res := Resolve(in)
			wantStatus(t, res, "a", false, c.reason, c.msg)
			if len(res.Policies) != 0 || len(res.GRPCSchemas) != 0 {
				t.Fatalf("a policy whose schema fails is left out: %v %v", res.Policies, res.GRPCSchemas)
			}
			// Resolved before: the previous version stays, with its schema.
			in.Previous = prev
			in.Policies = []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "schema", "set.binpb")}
			in.Policies[0].Spec.Mode = wafv1alpha1.PolicyBlock
			res = Resolve(in)
			wantStatus(t, res, "a", false, c.reason, "the previous version of the policy stays in force")
			wantProto(t, findPolicy(res, "shop/a"), prev.Policies[0])
			if len(res.GRPCSchemas) != 1 || !proto.Equal(res.GRPCSchemas[0], prev.GrpcSchemas[0]) {
				t.Fatalf("the previous schema must stay: %v", res.GRPCSchemas)
			}
		})
	}

	// A previous bundle that names a schema it doesn't carry (only a bug
	// writes one): the previous version reads without a schema.
	broken := proto.CloneOf(prev)
	broken.GrpcSchemas = nil
	in := base
	in.ConfigMaps, in.Previous = nil, broken
	res := Resolve(in)
	if p := findPolicy(res, "shop/a"); p == nil || p.GetBody().GetGrpcSchemaId() != "" || len(res.GRPCSchemas) != 0 {
		t.Fatalf("a previous version without its schema: %v, %v", p, res.GRPCSchemas)
	}
}

// TestGRPCSchemaOverBound: a set compiled to just under the bound without
// its id and source, named by a long key, is over it as the bundle carries
// it, which engines refuse: only its policy fails, InvalidGRPCSchema, and
// the bundle ships the others.
func TestGRPCSchemaOverBound(t *testing.T) {
	key := strings.Repeat("k", 253)
	in := Input{
		Policies: []wafv1alpha1.WAFPolicy{schemaPolicy("a", 0, "big", key), schemaPolicy("b", 1, "schema", "set.binpb")},
		Ingresses: []networkingv1.Ingress{
			ingress("a", rule("a.example.com", ipath("/", networkingv1.PathTypePrefix))),
			ingress("b", rule("b.example.com", ipath("/", networkingv1.PathTypePrefix))),
		},
		ConfigMaps: []corev1.ConfigMap{
			schemaConfigMap("big", key, grpcschematest.AtBound(t, len("shop/big/")+len(key)-1)),
			schemaConfigMap("schema", "set.binpb", healthSet(t)),
		},
		GRPCSchemas: compile.NewCache(),
	}
	res := Resolve(in)
	wantStatus(t, res, "a", false, ReasonInvalidGRPCSchema, "over")
	wantStatus(t, res, "b", true, ReasonAccepted, PolicyValid)
	if len(res.GRPCSchemas) != 1 || res.GRPCSchemas[0].GetSource() != "shop/schema/set.binpb" {
		t.Fatalf("schemas %v, want b's alone", res.GRPCSchemas)
	}
	for _, s := range res.GRPCSchemas {
		if _, err := load.Load(s); err != nil {
			t.Fatalf("the bundle carries a schema engines refuse: %v", err)
		}
	}
}
