// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package crdwatch

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var gvk = schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRoute"}

// failing answers every mapping with err.
type failing struct {
	meta.RESTMapper
	err error
}

func (f failing) RESTMapping(schema.GroupKind, ...string) (*meta.RESTMapping, error) {
	return nil, f.err
}

func TestInstalled(t *testing.T) {
	served := meta.NewDefaultRESTMapper(nil)
	served.Add(gvk, meta.RESTScopeNamespace)
	gv := gvk.GroupVersion()
	for _, tc := range []struct {
		name    string
		mapper  meta.RESTMapper
		want    bool
		wantErr bool
	}{
		{"served", served, true, false},
		{"not in a served group", meta.NewDefaultRESTMapper(nil), false, false},
		// The group isn't served at all (Traefik not installed), as
		// controller-runtime's mapper reports it.
		{"group not served", failing{err: &apiutil.ErrResourceDiscoveryFailed{gv: apierrors.NewNotFound(gv.WithResource("").GroupResource(), "")}}, false, false},
		{"discovery failed", failing{err: errors.New("connection refused")}, false, true},
	} {
		ok, err := Installed(tc.mapper, gvk)
		if ok != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: %v, %v", tc.name, ok, err)
		}
	}
}
