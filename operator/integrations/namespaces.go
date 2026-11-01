// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// AnyNamespace among the proxy namespaces makes every namespace one.
const AnyNamespace = "*"

// DefaultNamespaces are the proxy namespaces unless configured: Traefik's
// own, or kube-system, where k3s and RKE2 run it.
var DefaultNamespaces = Namespaces{"traefik", "kube-system"}

// Namespaces are the proxy namespaces (0004 §4.3): the namespaces whose
// pods the proxy pods' selector may select. Only their pods get the
// engine, the trust ConfigMap and read access to the bundle. A selector's
// labels prove nothing, as whoever may create a pod may set them; the
// namespace, where only the proxy's operators create pods, does. nil, or
// AnyNamespace among them, is every namespace.
type Namespaces []string

// ParseNamespaces parses a comma-separated list of namespaces, or "*".
func ParseNamespaces(s string) (Namespaces, error) {
	var out Namespaces
	for n := range strings.SplitSeq(s, ",") {
		n = strings.TrimSpace(n)
		switch n {
		case "":
			continue
		case AnyNamespace:
		default:
			if errs := validation.IsDNS1123Label(n); len(errs) > 0 {
				return nil, fmt.Errorf("namespace %q: %s", n, strings.Join(errs, ", "))
			}
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no namespace: list the proxies' namespaces, or * for every namespace")
	}
	return out, nil
}

// Any reports whether every namespace is a proxy namespace.
func (n Namespaces) Any() bool {
	return n == nil || slices.Contains(n, AnyNamespace)
}

// Has reports whether ns is a proxy namespace.
func (n Namespaces) Has(ns string) bool {
	return n.Any() || slices.Contains(n, ns)
}

// LabelSelector selects the proxy namespaces by name, for the Pod
// webhook's namespaceSelector; empty, which selects every namespace, when
// every namespace is one (the API server's default).
func (n Namespaces) LabelSelector() *metav1.LabelSelector {
	if n.Any() {
		return &metav1.LabelSelector{}
	}
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: corev1.LabelMetadataName, Operator: metav1.LabelSelectorOpIn, Values: slices.Sorted(slices.Values(n)),
	}}}
}

// String lists the namespaces, for flags and logs.
func (n Namespaces) String() string {
	if n.Any() {
		return AnyNamespace
	}
	return strings.Join(n, ",")
}
