// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// TestMiddlewareBodyLimit: Traefik's ForwardAuth allocates maxBodySize+1
// bytes for every request, with a body or not (forward.go, v3.7): at 10 MiB
// that added 8 ms to each request (#625). From Traefik v3.7, a Buffering
// Middleware bounds the body instead, reading only what comes, and the
// ForwardAuth after it has no limit of its own.
func TestMiddlewareBodyLimit(t *testing.T) {
	ms := ourMiddlewares("shop", false)
	if len(ms) != 3 {
		t.Fatalf("%d Middlewares, want the body limit, the ForwardAuth and their chain", len(ms))
	}
	for _, m := range ms {
		if m.GetNamespace() != "shop" || m.GetLabels()["app.kubernetes.io/managed-by"] != "inkwall-operator" || m.GroupVersionKind() != integrations.TraefikMiddlewareGVK {
			t.Errorf("metadata: %v", m.Object)
		}
	}
	body, auth, chain := ms[0], ms[1], ms[2]
	if chain.GetName() != MiddlewareName || Middleware("shop").GetName() != MiddlewareName {
		t.Errorf("routes refer to %s, want the chain", MiddlewareName)
	}
	refs, _, _ := unstructured.NestedSlice(chain.Object, "spec", "chain", "middlewares")
	if len(refs) != 2 || refs[0].(map[string]any)["name"] != body.GetName() || refs[1].(map[string]any)["name"] != auth.GetName() {
		t.Errorf("chain %v, want the body limit, then the ForwardAuth", refs)
	}

	b, _, _ := unstructured.NestedMap(body.Object, "spec", "buffering")
	// Bodies up to the largest body.maxBytes stay in memory (Traefik
	// writes a body as large as memRequestBodyBytes to a file): one byte
	// more reaches the engine as oversized; larger ones get 413.
	if b["maxRequestBodyBytes"] != int64(policy.MaxBodyBytes+1) || b["memRequestBodyBytes"] != int64(policy.MaxBodyBytes+1) {
		t.Errorf("buffering %v, want bodies of up to 10 MiB + 1 in memory", b)
	}
	// Responses stream: Server-Sent Events, downloads.
	if b["disableResponseBuffer"] != true || len(b) != 3 {
		t.Errorf("buffering %v, want responses not buffered", b)
	}

	fa, _, _ := unstructured.NestedMap(auth.Object, "spec", "forwardAuth")
	if fa["address"] != "http://127.0.0.1:9001/v1/forward-auth" || fa["trustForwardHeader"] != false || fa["forwardBody"] != true {
		t.Errorf("forwardAuth %v", fa)
	}
	if fa["maxBodySize"] != int64(-1) {
		t.Errorf("maxBodySize %v, want -1: the Buffering Middleware bounds the body", fa["maxBodySize"])
	}
	if fa["maxResponseBodySize"] != int64(64<<10) {
		t.Errorf("maxResponseBodySize %v, want 64 KiB", fa["maxResponseBodySize"])
	}

	// Before Traefik v3.7, Buffering always buffers responses: ForwardAuth
	// bounds the body itself, alone, as before.
	legacy := ourMiddlewares("shop", true)
	if len(legacy) != 1 || legacy[0].GetName() != MiddlewareName {
		t.Fatalf("legacy Middlewares %v, want ForwardAuth only", legacy)
	}
	fa, _, _ = unstructured.NestedMap(legacy[0].Object, "spec", "forwardAuth")
	if fa["maxBodySize"] != int64(policy.MaxBodyBytes) || fa["forwardBody"] != true || fa["trustForwardHeader"] != false {
		t.Errorf("legacy forwardAuth %v", fa)
	}
	if _, ok := fa["maxResponseBodySize"]; ok {
		t.Error("legacy forwardAuth has maxResponseBodySize, which its CRD drops")
	}
}

// TestMiddlewareSpecMatches: a Middleware read back from the API server
// matches, one changed by hand doesn't.
func TestMiddlewareSpecMatches(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, m := range ourMiddlewares("shop", legacy) {
			raw, _ := json.Marshal(m.Object)
			var back unstructured.Unstructured
			if err := back.UnmarshalJSON(raw); err != nil {
				t.Fatal(err)
			}
			if !SpecMatches(&back, m) {
				t.Errorf("round-tripped %s doesn't match", m.GetName())
			}
		}
	}
	auth := ourMiddlewares("shop", false)[1]
	changed := auth.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, true, "spec", "forwardAuth", "trustForwardHeader")
	if SpecMatches(changed, auth) {
		t.Error("trustForwardHeader: true matched")
	}
	// A Middleware an older operator made: corrected.
	if SpecMatches(ourMiddlewares("shop", true)[0], Middleware("shop")) {
		t.Error("the legacy ForwardAuth matched the chain")
	}
}

// TestEnsureMiddleware runs against an API server with Traefik v3.7's
// CRDs, and one with an older CRD that drops the fields v3.7 added.
func TestEnsureMiddleware(t *testing.T) {
	ctx := context.Background()
	// What operators before 0.6.0 made: ForwardAuth alone, with a 10 MiB
	// maxBodySize, and maxResponseBodySize since 0.5.0.
	before := func(responseLimit bool) *unstructured.Unstructured {
		m := ourMiddlewares("shop", true)[0]
		if responseLimit {
			_ = unstructured.SetNestedField(m.Object, int64(64<<10), "spec", "forwardAuth", "maxResponseBodySize")
		}
		return m
	}
	for _, tc := range []struct {
		name       string
		drops      bool
		oldTraefik bool
		existing   *unstructured.Unstructured
		writes     int // Creates and Updates over three reconciles
		legacy     bool
	}{
		{name: "new", writes: 3},
		{name: "from 0.5", existing: before(true), writes: 3},
		{name: "from 0.4", existing: before(false), writes: 3},
		// The body Middleware is written first, then removed.
		{name: "new, fields dropped", drops: true, writes: 2, legacy: true},
		{name: "from 0.5, fields dropped", drops: true, existing: before(true), writes: 2, legacy: true},
		{name: "from 0.4, fields dropped", drops: true, existing: before(false), writes: 1, legacy: true},
		// Traefik's pods run an older Traefik than its CRDs.
		{name: "old Traefik", oldTraefik: true, writes: 1, legacy: true},
		{name: "from 0.6, old Traefik", oldTraefik: true, existing: Middleware("shop"), writes: 1, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			drop := func(obj client.Object) {
				writes++
				if u, ok := obj.(*unstructured.Unstructured); ok && tc.drops {
					unstructured.RemoveNestedField(u.Object, "spec", "forwardAuth", "maxResponseBodySize")
					unstructured.RemoveNestedField(u.Object, "spec", "buffering", "disableResponseBuffer")
				}
			}
			b := fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					drop(obj)
					return c.Create(ctx, obj, opts...)
				},
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					drop(obj)
					return c.Update(ctx, obj, opts...)
				},
			})
			if tc.existing != nil {
				b = b.WithObjects(tc.existing)
			}
			c := b.Build()
			r := &Traefik{Client: c, APIReader: c}
			for range 3 {
				if err := r.ensureMiddleware(ctx, "shop", tc.oldTraefik); err != nil {
					t.Fatal(err)
				}
			}
			if writes != tc.writes {
				t.Errorf("%d writes, want %d", writes, tc.writes)
			}
			for _, m := range ourMiddlewares("shop", tc.legacy) {
				got := &unstructured.Unstructured{}
				got.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
				if err := c.Get(ctx, client.ObjectKeyFromObject(m), got); err != nil {
					t.Fatal(err)
				}
				if !SpecMatches(got, m) {
					t.Errorf("stored %s isn't the operator's: %v", m.GetName(), got.Object["spec"])
				}
			}
			if tc.legacy {
				// The unused Middlewares of Traefik v3.7 aren't left behind.
				for _, name := range []string{bodyMiddlewareName, authMiddlewareName} {
					got := &unstructured.Unstructured{}
					got.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
					if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: name}, got); !apierrors.IsNotFound(err) {
						t.Errorf("%s: %v, want it deleted", name, err)
					}
				}
			}
		})
	}
}

// TestEnsureMiddlewareNotOurs: a Middleware of one of the operator's names
// that it didn't create is left alone, and nothing is written.
func TestEnsureMiddlewareNotOurs(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{MiddlewareName, bodyMiddlewareName, authMiddlewareName} {
		theirs := &unstructured.Unstructured{}
		theirs.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
		theirs.SetNamespace("shop")
		theirs.SetName(name)
		theirs.Object["spec"] = map[string]any{"headers": map[string]any{}}
		c := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(theirs).Build()
		r := &Traefik{Client: c, APIReader: c}
		if err := r.ensureMiddleware(ctx, "shop", false); err == nil {
			t.Errorf("%s: no error", name)
		}
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(integrations.TraefikMiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
		if err := c.List(ctx, list); err != nil || len(list.Items) != 1 {
			t.Errorf("%s: %d Middlewares (%v), want only theirs", name, len(list.Items), err)
		}
	}
}

func TestOldTraefik(t *testing.T) {
	pod := func(images ...string) corev1.Pod {
		var p corev1.Pod
		for _, im := range images {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Image: im})
		}
		return p
	}
	for _, tc := range []struct {
		images []string
		old    bool
	}{
		{[]string{"traefik:v3.7.17"}, false},
		{[]string{"docker.io/library/traefik:v3.8.0", "ghcr.io/inkwall-dev/inkwall-engine:0.6.0"}, false},
		{[]string{"traefik:v4.0"}, false},
		{[]string{"traefik:v3.6.2"}, true},
		{[]string{"traefik:3.6"}, true},
		{[]string{"registry.example.com:5000/mirror/traefik:v3.3.0"}, true},
		{[]string{"traefik:v2.11.0"}, true},
		// Unknown versions trust the CRDs.
		{[]string{"traefik@sha256:0123"}, false},
		{[]string{"traefik:latest"}, false},
		{[]string{"example.com/edge-proxy:v3.0.0"}, false},
	} {
		if got := oldTraefik([]corev1.Pod{pod(tc.images...)}); got != tc.old {
			t.Errorf("oldTraefik(%v) = %v, want %v", tc.images, got, tc.old)
		}
	}
}
