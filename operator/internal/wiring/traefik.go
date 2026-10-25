// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package wiring sends a proxy's protected routes to the engine (0004
// §4.4). For Traefik: an operator-owned ForwardAuth Middleware in each
// namespace with protected Ingresses, attached to those Ingresses through
// Traefik's router.middlewares annotation.
package wiring

import (
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// Names of the Traefik wiring.
const (
	// MiddlewareName is the operator's Middleware in each protected
	// namespace; not "inkwall", so it can't take over one made by hand.
	MiddlewareName = "inkwall-waf"
	// MiddlewaresAnnotation lists an Ingress router's Middlewares.
	MiddlewaresAnnotation = "traefik.ingress.kubernetes.io/router.middlewares"
	// WiredAnnotation marks an Ingress the operator wired, with the
	// Middleware it added, so it removes exactly that.
	WiredAnnotation = "waf.inkwall.dev/wired"
	// legacyClassAnnotation is the class before ingressClassName.
	legacyClassAnnotation  = "kubernetes.io/ingress.class"
	defaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"

	// forwardAuthAddress is the injected engine, in Traefik's pod.
	forwardAuthAddress = "http://127.0.0.1:9001/v1/forward-auth"
)

// MiddlewareGVK is Traefik's Middleware.
var MiddlewareGVK = schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "Middleware"}

// MiddlewareRef is how an Ingress in namespace refers to the operator's
// Middleware there.
func MiddlewareRef(namespace string) string {
	return namespace + "-" + MiddlewareName + "@kubernetescrd"
}

// Middleware returns the operator's Middleware for namespace.
func Middleware(namespace string) *unstructured.Unstructured {
	m := &unstructured.Unstructured{}
	m.SetGroupVersionKind(MiddlewareGVK)
	m.SetNamespace(namespace)
	m.SetName(MiddlewareName)
	m.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"})
	m.Object["spec"] = map[string]any{"forwardAuth": forwardAuth()}
	return m
}

func forwardAuth() map[string]any {
	return map[string]any{
		"address": forwardAuthAddress,
		// Must be false: with true, Traefik keeps a client's own
		// X-Forwarded-Uri, and the engine would inspect that instead of
		// the real URI (0002 §6.3).
		"trustForwardHeader": false,
		// Without it, bodies reach the application uninspected.
		"forwardBody": true,
		// The largest body a policy can inspect: smaller bodies reach the
		// engine, whose policy decides; Traefik refuses larger ones (401)
		// itself.
		"maxBodySize":         int64(policy.MaxBodyBytes),
		"authResponseHeaders": []any{"X-Request-Id"},
	}
}

// ForwardAuthMatches reports whether a Middleware's spec is the operator's.
func ForwardAuthMatches(m *unstructured.Unstructured) bool {
	got, ok, _ := unstructured.NestedMap(m.Object, "spec", "forwardAuth")
	if !ok {
		return false
	}
	want := forwardAuth()
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		switch v := v.(type) {
		case []any:
			g, ok := got[k].([]any)
			if !ok || len(g) != len(v) || g[0] != v[0] {
				return false
			}
		case int64:
			// JSON numbers decode as int64 or float64.
			switch g := got[k].(type) {
			case int64:
				if g != v {
					return false
				}
			case float64:
				if int64(g) != v {
					return false
				}
			default:
				return false
			}
		default:
			if got[k] != v {
				return false
			}
		}
	}
	return true
}

// WithMiddleware returns the annotation value with ref added (first, so the
// engine sees the request before other Middlewares change it), unchanged if
// present.
func WithMiddleware(current, ref string) string {
	items := splitMiddlewares(current)
	for _, it := range items {
		if it == ref {
			return current
		}
	}
	return strings.Join(append([]string{ref}, items...), ",")
}

// WithoutMiddleware returns the annotation value without ref.
func WithoutMiddleware(current, ref string) string {
	var out []string
	for _, it := range splitMiddlewares(current) {
		if it != ref {
			out = append(out, it)
		}
	}
	return strings.Join(out, ",")
}

func splitMiddlewares(s string) []string {
	var out []string
	for _, it := range strings.Split(s, ",") {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out
}

// Controller returns the controller of the IngressClass serving ing, or ""
// when it can't be told. classes maps class names to their controllers;
// defaultClass is the class marked default, if any.
func Controller(ing *networkingv1.Ingress, classes map[string]string, defaultClass string) string {
	name := ""
	if ing.Spec.IngressClassName != nil {
		name = *ing.Spec.IngressClassName
	} else if a := ing.Annotations[legacyClassAnnotation]; a != "" {
		name = a
	} else {
		name = defaultClass
	}
	if c, ok := classes[name]; ok {
		return c
	}
	// The legacy annotation names Traefik's default class without an
	// IngressClass object.
	if name == "traefik" {
		return integrations.Traefik.Controller
	}
	return ""
}

// IsDefaultClass reports whether an IngressClass is the cluster default.
func IsDefaultClass(ic *networkingv1.IngressClass) bool {
	return ic.Annotations[defaultClassAnnotation] == "true"
}
