// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/test/fakeengine"
)

// testInjection creates proxy pods as Traefik's Deployment would: the Pod
// webhook adds the engine, and the operator provides the trust ConfigMap
// and the RBAC grant the engine needs. A pod with Traefik's labels outside
// the proxy namespaces gets none of it, and can't connect as an engine.
func testInjection(ctx context.Context, t *testing.T, c client.Client) {
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "proxy"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "traefik"}},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	podIn := func(namespace, name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
			Spec: corev1.PodSpec{
				ServiceAccountName: "traefik",
				Containers:         []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}},
			},
		}
	}
	pod := func(name string, labels map[string]string) *corev1.Pod { return podIn("proxy", name, labels) }
	traefik := pod("traefik-1", map[string]string{"app.kubernetes.io/name": "traefik"})
	other := pod("shop-1", map[string]string{"app": "shop"})
	// Not in a proxy namespace: not a proxy pod, whatever its labels.
	fake := podIn("tenant", "traefik-1", map[string]string{"app.kubernetes.io/name": "traefik"})
	for _, p := range []*corev1.Pod{fake, traefik, other} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(fake), fake); err != nil {
		t.Fatal(err)
	}
	if len(fake.Spec.InitContainers) != 0 {
		t.Error("a pod outside the proxy namespaces got the engine")
	}

	// The webhook answered at creation: the engine is in the Traefik pod.
	if err := c.Get(ctx, client.ObjectKeyFromObject(traefik), traefik); err != nil {
		t.Fatal(err)
	}
	if len(traefik.Spec.InitContainers) != 1 || traefik.Spec.InitContainers[0].Name != injection.ContainerName ||
		traefik.Spec.InitContainers[0].Image != "inkwall-engine:test" {
		t.Fatalf("the engine was not injected: %+v", traefik.Spec.InitContainers)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(other), other); err != nil {
		t.Fatal(err)
	}
	if len(other.Spec.InitContainers) != 0 {
		t.Fatal("a pod that isn't a proxy got the engine")
	}

	eventually(t, "the trust ConfigMap", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: injection.TrustConfigMap}, &cm); err != nil {
			return err.Error()
		}
		if cm.Data["ca.crt"] == "" || len(cm.BinaryData["ed25519.pub"]) != 32 {
			return "incomplete"
		}
		// Between rotations, the one key, also as the set engines trust.
		if !bytes.Equal(cm.BinaryData["trusted-keys.pub"], cm.BinaryData["ed25519.pub"]) {
			return "trusted-keys.pub is not the signing key"
		}
		return ""
	})
	eventually(t, "the RBAC grant", func() string {
		var rb rbacv1.RoleBinding
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: injection.GrantName}, &rb); err != nil {
			return err.Error()
		}
		if slices.ContainsFunc(rb.Subjects, func(s rbacv1.Subject) bool { return s.Namespace == "tenant" }) {
			t.Fatalf("a ServiceAccount outside the proxy namespaces is granted the bundle: %v", rb.Subjects)
		}
		for _, s := range rb.Subjects {
			if s.Namespace == "proxy" && s.Name == "traefik" {
				return ""
			}
		}
		return "Traefik's ServiceAccount not granted"
	})
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: injection.TrustConfigMap}, &cm); !apierrors.IsNotFound(err) {
		t.Errorf("trust ConfigMap outside the proxy namespaces: %v, want not found", err)
	}

	// The grant is what the distribution server accepts engines on: the
	// proxy's engine connects, the other pod's can't.
	engine := func(namespace string) *fakeengine.Engine {
		var certs, keys corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "inkwall-operator-webhook-tls"}, &certs); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(certs.Data["ca.crt"])
		_, port, _ := net.SplitHostPort(distAddr)
		return &fakeengine.Engine{
			ID:         namespace + "-traefik-1",
			Addr:       "localhost:" + port,
			TLS:        &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			Token:      token(ctx, t, namespace, "traefik"),
			PublicKeys: []ed25519.PublicKey{keys.Data[bundle.PublicKeyKey]},
			Heartbeat:  200 * time.Millisecond,
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := engine("tenant").Run(rctx)
	cancel()
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("an engine outside the proxy namespaces: got %v, want PermissionDenied", err)
	}
	proxy := engine("proxy")
	ectx, stopEngine := context.WithCancel(ctx)
	go func() { _ = proxy.Run(ectx) }()
	eventually(t, "the proxy's engine gets the bundle", func() string {
		if proxy.Applied() == nil {
			return fmt.Sprintf("no bundle (%v)", proxy.Err())
		}
		return ""
	})
	stopEngine()

	// The proxy's last pod gone: the trust ConfigMap goes too.
	if err := c.Delete(ctx, traefik, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the trust ConfigMap removed", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: injection.TrustConfigMap}, &cm); !apierrors.IsNotFound(err) {
			return "still there"
		}
		return ""
	})
}
