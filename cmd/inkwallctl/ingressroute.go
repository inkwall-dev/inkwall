// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// ingressRoute holds the fields of Traefik's IngressRoute (traefik.io/v1alpha1,
// as of Traefik v3.7), so that one is read strictly, as the other kinds
// are: a misspelled field is an error. Inside the routes, only what the
// resolver reads (match and kind) is checked; services, middlewares, tls
// and the other fields Traefik reads and the resolver doesn't are taken as
// they are.
type ingressRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              struct {
		Routes           []ingressRouteRoute `json:"routes"`
		EntryPoints      []string            `json:"entryPoints,omitempty"`
		IngressClassName string              `json:"ingressClassName,omitempty"`
		ParentRefs       json.RawMessage     `json:"parentRefs,omitempty"`
		TLS              json.RawMessage     `json:"tls,omitempty"`
	} `json:"spec"`
}

type ingressRouteRoute struct {
	Match         *string         `json:"match"`
	Kind          string          `json:"kind,omitempty"`
	Priority      int64           `json:"priority,omitempty"`
	Syntax        string          `json:"syntax,omitempty"`
	Services      json.RawMessage `json:"services,omitempty"`
	Middlewares   json.RawMessage `json:"middlewares,omitempty"`
	Observability json.RawMessage `json:"observability,omitempty"`
}

// readIngressRoute reads an IngressRoute strictly, and checks what its CRD
// requires of the fields the resolver reads. Traefik's types aren't a
// dependency: the object is returned unstructured, as the operator reads
// it.
func readIngressRoute(doc []byte) (unstructured.Unstructured, error) {
	var o unstructured.Unstructured
	var ir ingressRoute
	if err := yaml.UnmarshalStrict(doc, &ir); err != nil {
		return o, err
	}
	if ir.Spec.Routes == nil {
		return o, errors.New("spec.routes: required")
	}
	for i, r := range ir.Spec.Routes {
		switch {
		case r.Match == nil:
			return o, fmt.Errorf("spec.routes[%d].match: required", i)
		case r.Kind != "" && r.Kind != "Rule":
			return o, fmt.Errorf("spec.routes[%d].kind: %q, want Rule", i, r.Kind)
		}
	}
	j, err := yaml.YAMLToJSON(doc)
	if err == nil {
		err = o.UnmarshalJSON(j)
	}
	return o, err
}
