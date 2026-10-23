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

// configDir is operator/config.
func configDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "config")
}

// CRDDir is the directory of the generated CRDs.
func CRDDir() string { return filepath.Join(configDir(), "crd", "bases") }

// SamplesDir is the directory of the sample objects.
func SamplesDir() string { return filepath.Join(configDir(), "samples") }

// Env is a running API server.
type Env struct {
	// Config reaches the API server.
	Config *rest.Config
	// WebhookPort is where the API server calls the webhooks, on
	// localhost, when they are installed.
	WebhookPort int
}

// Options configures Start.
type Options struct {
	// Webhooks installs the operator's webhook configuration, pointed at
	// https://localhost:<WebhookPort>.
	Webhooks bool
}

// Start starts an API server, typically from TestMain, and returns it and a
// function that stops it. The Env is nil when KUBEBUILDER_ASSETS is not
// set; Skip then skips the tests.
func Start(o Options) (*Env, func(), error) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		return nil, func() {}, nil
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{CRDDir()},
		ErrorIfCRDPathMissing: true,
	}
	if o.Webhooks {
		env.WebhookInstallOptions = envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join(configDir(), "webhook")},
			// A name, not an IP, in the webhook URLs, so a certificate
			// issued for "localhost" is valid.
			LocalServingHostExternalName: "localhost",
		}
	}
	cfg, err := env.Start()
	if err != nil {
		return nil, func() {}, err
	}
	e := &Env{Config: cfg, WebhookPort: env.WebhookInstallOptions.LocalServingPort}
	return e, func() { _ = env.Stop() }, nil
}

// Skip skips t when there is no API server.
func Skip(t testing.TB, e *Env) {
	t.Helper()
	if e == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set (make test sets it)")
	}
}
