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
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

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

// testWebhookTimeout replaces the webhooks' 2s timeout in tests: under the
// race detector, compiling the Core Rule Set takes several times longer,
// and a busy CI runner can push the first compile past 2s.
const testWebhookTimeout = 10

// webhooks reads the generated webhook configurations, with the test
// timeout.
func webhooks() ([]*admissionv1.MutatingWebhookConfiguration, []*admissionv1.ValidatingWebhookConfiguration, error) {
	raw, err := os.ReadFile(filepath.Join(configDir(), "webhook", "manifests.yaml"))
	if err != nil {
		return nil, nil, err
	}
	var (
		mutating   []*admissionv1.MutatingWebhookConfiguration
		validating []*admissionv1.ValidatingWebhookConfiguration
	)
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			return nil, nil, err
		}
		switch meta.Kind {
		case "MutatingWebhookConfiguration":
			var c admissionv1.MutatingWebhookConfiguration
			if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
				return nil, nil, err
			}
			for i := range c.Webhooks {
				c.Webhooks[i].TimeoutSeconds = ptr.To(int32(testWebhookTimeout))
			}
			mutating = append(mutating, &c)
		case "ValidatingWebhookConfiguration":
			var c admissionv1.ValidatingWebhookConfiguration
			if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
				return nil, nil, err
			}
			for i := range c.Webhooks {
				c.Webhooks[i].TimeoutSeconds = ptr.To(int32(testWebhookTimeout))
			}
			validating = append(validating, &c)
		}
	}
	return mutating, validating, nil
}

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
		// The Inkwall CRDs, and a stand-in for Traefik's Middleware.
		CRDDirectoryPaths:     []string{CRDDir(), filepath.Join(filepath.Dir(configDir()), "test", "testenv", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	if o.Webhooks {
		mutating, validating, err := webhooks()
		if err != nil {
			return nil, func() {}, err
		}
		env.WebhookInstallOptions = envtest.WebhookInstallOptions{
			MutatingWebhooks:   mutating,
			ValidatingWebhooks: validating,
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

// InstallLater installs the CRDs a test adds while the operator runs
// (testenv/later: Traefik's IngressRoute), and waits until they are served.
func InstallLater(e *Env) error {
	_, err := envtest.InstallCRDs(e.Config, envtest.CRDInstallOptions{
		Paths:              []string{filepath.Join(filepath.Dir(configDir()), "test", "testenv", "later")},
		ErrorIfPathMissing: true,
	})
	return err
}

// Skip skips t when there is no API server.
func Skip(t testing.TB, e *Env) {
	t.Helper()
	if e == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set (make test sets it)")
	}
}
