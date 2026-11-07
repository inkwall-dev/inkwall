// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package helmcheck renders the Helm chart against an API server (envtest),
// for what the chart looks up in the cluster. make helm-lint runs it with
// CHART set; without CHART, helm or KUBEBUILDER_ASSETS it is skipped.
package helmcheck

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// An upgrade stops, instead of leaving routes uninspected, when pods that
// run the engine are in a namespace injection.proxyNamespaces doesn't list.
func TestProxyNamespacesCheck(t *testing.T) {
	chart, cfg, kubeconfig := apiServer(t)
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// The operator granted the bundle to Traefik's ServiceAccounts in three
	// namespaces: in ingress, a pod runs the engine (a native sidecar); in
	// annotated, one has the webhook's marker; in idle, none has the engine.
	pod := func(ns string, annotations map[string]string, init ...corev1.Container) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "traefik", Annotations: annotations},
			Spec:       corev1.PodSpec{InitContainers: init, Containers: []corev1.Container{{Name: "traefik", Image: "traefik"}}},
		}
	}
	objs := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "inkwall-system"}}}
	var subjects []rbacv1.Subject
	for _, ns := range []string{"ingress", "annotated", "idle", "traefik"} {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
		subjects = append(subjects, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: "traefik"})
	}
	objs = append(objs,
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: "inkwall-bundle-reader"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "inkwall-bundle-reader"},
			Subjects:   subjects,
		},
		pod("ingress", nil, corev1.Container{Name: "inkwall-engine", Image: "inkwall-engine"}),
		pod("annotated", map[string]string{"waf.inkwall.dev/injected": "true"}),
		pod("idle", nil),
		pod("traefik", nil, corev1.Container{Name: "inkwall-engine", Image: "inkwall-engine"}),
	)
	ctx := context.Background()
	for _, o := range objs {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	render := func(args ...string) (string, error) {
		args = append([]string{"template", "inkwall", chart, "--namespace", "inkwall-system", "--dry-run=server", "--kubeconfig", kubeconfig}, args...)
		out, err := exec.Command("helm", args...).CombinedOutput()
		return string(out), err
	}
	out, err := render()
	if err == nil || !strings.Contains(out, "pods with the Inkwall engine run in namespace(s) annotated,ingress, which injection.proxyNamespaces doesn't list") {
		t.Errorf("default proxy namespaces: want the render to fail naming annotated and ingress, got %v: %s", err, out)
	}
	for _, set := range []string{"injection.proxyNamespaces={traefik,ingress,annotated}", "injection.proxyNamespaces={*}"} {
		if out, err := render("--set", set); err != nil {
			t.Errorf("%s: %v: %s", set, err, out)
		}
	}
}

// apiServer starts envtest and returns the chart, the API server's config
// and a kubeconfig for helm, or skips the test without them.
func apiServer(t *testing.T) (string, *rest.Config, string) {
	t.Helper()
	chart := os.Getenv("CHART")
	if chart == "" || os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("CHART or KUBEBUILDER_ASSETS not set: run make helm-lint")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("no helm")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	admin, err := env.AddUser(envtest.User{Name: "admin", Groups: []string{"system:masters"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kc, err := admin.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, kc, 0o600); err != nil {
		t.Fatal(err)
	}
	return chart, cfg, kubeconfig
}

// helm upgrade --reuse-values from the 0.4 releases passes the strict
// values.schema.json (#386): it renders with the old release's values,
// without the keys added since, which the schema must not require. #143
// broke such an upgrade. The releases come from the chart registry
// (REUSE_FROM overrides them, space-separated).
func TestReuseValuesUpgrade(t *testing.T) {
	if os.Getenv("CHART") == "" {
		t.Skip("CHART not set: run make helm-lint")
	}
	dir := t.TempDir()
	for _, v := range strings.Fields(cmp.Or(os.Getenv("REUSE_FROM"), "0.4.0 0.4.1")) {
		t.Run(v, func(t *testing.T) {
			// An API server each: the releases' webhook configurations
			// have the same names.
			chart, _, kubeconfig := apiServer(t)
			helm := func(args ...string) error {
				out, err := exec.Command("helm", append(args, "--kubeconfig", kubeconfig)...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("helm %s: %w: %s", strings.Join(args, " "), err, out)
				}
				return nil
			}
			if out, err := exec.Command("helm", "pull", "oci://ghcr.io/inkwall-dev/charts/inkwall", "--version", v, "-d", dir).CombinedOutput(); err != nil {
				t.Fatalf("helm pull %s: %v: %s", v, err, out)
			}
			// The release with values users set: a string where a bool
			// is expected (--set-string), auto, proxy namespaces.
			if err := helm("install", "inkwall", filepath.Join(dir, "inkwall-"+v+".tgz"), "--namespace", "inkwall-system", "--create-namespace",
				"--set-string", "rbac.integrations.traefik=true", "--set", "rbac.integrations.istio=auto",
				"--set", "injection.proxyNamespaces={traefik,ingress}", "--set", "operator.replicas=1"); err != nil {
				t.Fatal(err)
			}
			upgrade := func(set ...string) error {
				args := []string{"upgrade", "inkwall", chart, "--namespace", "inkwall-system", "--reuse-values"}
				for _, s := range set {
					args = append(args, "--set", s)
				}
				return helm(args...)
			}
			if err := upgrade(); err != nil {
				t.Error(err)
			}
			// A value added since, on top.
			if err := upgrade("global.imageRegistry=registry.example.com", "operator.extraEnv[0].name=A", "operator.extraEnv[0].value=b"); err != nil {
				t.Error(err)
			}
			// A typo still fails.
			if err := upgrade("operator.replica=2"); err == nil || !strings.Contains(err.Error(), "additional properties 'replica' not allowed") {
				t.Errorf("with a typo: want the schema's error, got %v", err)
			}
		})
	}
}
