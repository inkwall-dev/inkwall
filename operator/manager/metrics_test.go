// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"

	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// By default the metrics are served as before: plain HTTP, no filter.
func TestMetricsServerOptionsDefault(t *testing.T) {
	m, err := metricsServerOptions(Options{MetricsAddr: ":8080"})
	if err != nil {
		t.Fatal(err)
	}
	if m.BindAddress != ":8080" || m.SecureServing || m.FilterProvider != nil || m.CertDir != "" {
		t.Errorf("default metrics options %+v: want plain HTTP on :8080", m)
	}
}

// With MetricsSecure: HTTPS, behind the TokenReview and
// SubjectAccessReview filter; MetricsCertDir must hold the certificate, or
// the operator doesn't start (rather than serve a self-signed one that
// Prometheus, told to verify it, would refuse).
func TestMetricsServerOptionsSecure(t *testing.T) {
	m, err := metricsServerOptions(Options{MetricsAddr: ":8080", MetricsSecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if !m.SecureServing || m.FilterProvider == nil || m.CertDir != "" {
		t.Errorf("secure metrics options %+v: want HTTPS, a filter, a self-signed certificate", m)
	}
	dir := t.TempDir()
	if _, err := metricsServerOptions(Options{MetricsAddr: ":8080", MetricsSecure: true, MetricsCertDir: dir}); err == nil {
		t.Error("an empty --metrics-cert-dir: want an error")
	}
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, err = metricsServerOptions(Options{MetricsAddr: ":8080", MetricsSecure: true, MetricsCertDir: dir})
	if err != nil || m.CertDir != dir {
		t.Errorf("--metrics-cert-dir with the files: cert dir %q, %v", m.CertDir, err)
	}
	if _, err := metricsServerOptions(Options{MetricsCertDir: dir}); err == nil {
		t.Error("--metrics-cert-dir without --metrics-secure: want an error")
	}
}

// The secure metrics against the API server: no token is 401, a service
// account without the metrics reader's permission 403, one with it reads
// the metrics; plain HTTP gets nothing.
func TestSecureMetrics(t *testing.T) {
	testenv.Skip(t, env)
	addr := freeAddr(t)
	m, err := metricsServerOptions(Options{MetricsAddr: addr, MetricsSecure: true})
	if err != nil {
		t.Fatal(err)
	}
	skip := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Metrics:                m,
		HealthProbeBindAddress: "0",
		Controller:             ctrlconfig.Controller{SkipNameValidation: &skip},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("manager stopped with %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("manager did not stop after 20s")
		}
	})

	c, err := client.New(env.Config, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	ns := testenv.Namespace(t, c, "metrics")
	token := func(name string) string {
		t.Helper()
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
		if err := c.Create(ctx, sa); err != nil {
			t.Fatal(err)
		}
		tr, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return tr.Status.Token
	}
	reader, other := token("prometheus"), token("other")
	// What the chart's metrics reader ClusterRole grants.
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: ns + "-metrics-reader"},
		Rules:      []rbacv1.PolicyRule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: ns + "-metrics-reader"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "prometheus", Namespace: ns}},
	}
	for _, o := range []client.Object{role, binding} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	testenv.DeleteOnCleanup(t, c, binding, role)

	insecure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // the self-signed certificate under test
	}}
	scrape := func(scheme, token string) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr+"/metrics", nil)
		if err != nil {
			return 0, "", err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := insecure.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), err
	}

	// The authorized scrape, retried until the server listens (and RBAC's
	// cache has the binding).
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, body, err := scrape("https", reader)
		if err == nil && code == http.StatusOK && strings.Contains(body, "# TYPE ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("authorized scrape: %d, %v\n%s", code, err, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code, _, err := scrape("https", ""); err != nil || code != http.StatusUnauthorized {
		t.Errorf("no token: %d, %v; want 401", code, err)
	}
	// A token the TokenReview rejects (with an error, as a malformed one is)
	// is unauthenticated, not a server error (#562).
	if code, _, err := scrape("https", "not-a-token"); err != nil || code != http.StatusUnauthorized {
		t.Errorf("an invalid token: %d, %v; want 401", code, err)
	}
	if code, _, err := scrape("https", other); err != nil || code != http.StatusForbidden {
		t.Errorf("a service account without the role: %d, %v; want 403", code, err)
	}
	if code, _, err := scrape("http", reader); err == nil && code == http.StatusOK {
		t.Error("plain HTTP serves the metrics")
	}
}
