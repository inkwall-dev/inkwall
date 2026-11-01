// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package helmcheck renders the Helm chart against an API server (envtest),
// for what the chart looks up in the cluster. make helm-lint runs it with
// CHART set; without CHART, helm or KUBEBUILDER_ASSETS it is skipped.
package helmcheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// An upgrade stops, instead of leaving routes uninspected, when pods that
// run the engine are in a namespace injection.proxyNamespaces doesn't list.
func TestProxyNamespacesCheck(t *testing.T) {
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
	defer func() { _ = env.Stop() }()
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
