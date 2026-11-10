// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// The secure metrics' authentication and authorization delegate to the
// API server: a scraper's bearer token is checked with a TokenReview, and
// its permission to get /metrics with a SubjectAccessReview
// (docs/design/0004-operator.md, Metrics over HTTPS).
//
// The ClusterRole these need is the chart's, rendered only with
// metrics.secure.enabled, not a kubebuilder:rbac marker: the default
// install doesn't grant them.

// metricsServerOptions are the metrics server's: plain HTTP by default, or
// HTTPS behind the TokenReview and SubjectAccessReview filter with
// MetricsSecure, with the certificate in MetricsCertDir (which must hold
// it: a self-signed one instead would fail a scraper that verifies it, and
// only after the operator is running) or, without it, a self-signed one.
func metricsServerOptions(o Options) (metricsserver.Options, error) {
	m := metricsserver.Options{BindAddress: o.MetricsAddr}
	if !o.MetricsSecure {
		if o.MetricsCertDir != "" {
			return m, errors.New("--metrics-cert-dir needs --metrics-secure")
		}
		return m, nil
	}
	m.SecureServing = true
	m.FilterProvider = metricsfilters.WithAuthenticationAndAuthorization
	if o.MetricsCertDir != "" {
		for _, f := range []string{"tls.crt", "tls.key"} {
			if _, err := os.Stat(filepath.Join(o.MetricsCertDir, f)); err != nil {
				return m, fmt.Errorf("the metrics certificate: %w", err)
			}
		}
		m.CertDir = o.MetricsCertDir
	}
	return m, nil
}
