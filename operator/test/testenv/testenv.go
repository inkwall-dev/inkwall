// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package testenv starts a local API server (envtest) with the Inkwall CRDs
// installed, for operator tests. The kube-apiserver and etcd binaries come
// from KUBEBUILDER_ASSETS, which `make test` sets; without it the tests
// that need the server are skipped.
package testenv

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// CRDDir is the directory of the generated CRDs.
func CRDDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "config", "crd", "bases")
}

// Start starts an API server, typically from TestMain, and returns its
// configuration and a function that stops it. The configuration is nil
// when KUBEBUILDER_ASSETS is not set; Skip then skips the tests.
func Start() (cfg *rest.Config, stop func(), err error) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		return nil, func() {}, nil
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{CRDDir()},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err = env.Start()
	if err != nil {
		return nil, func() {}, err
	}
	return cfg, func() { _ = env.Stop() }, nil
}

// Skip skips t when there is no API server.
func Skip(t testing.TB, cfg *rest.Config) {
	t.Helper()
	if cfg == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set (make test sets it)")
	}
}
