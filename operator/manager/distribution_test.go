// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/test/fakeengine"
)

// token issues a ServiceAccount token for the operator's audience, as the
// projected volume of an engine's pod would.
func token(ctx context.Context, t *testing.T, namespace, sa string) string {
	t.Helper()
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{Audiences: []string{distribution.Audience}, ExpirationSeconds: ptr.To(int64(600))},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return tr.Status.Token
}

// testDistribution connects fake engines to the operator: they must be
// allowed to read the bundle Secret, get the bundle over TLS, and their
// acks and nacks become each policy's Enforced condition.
func testDistribution(ctx context.Context, t *testing.T, c client.Client) {
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "edge"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "traefik"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "intruder"}},
		// What injection grants an ingress controller's ServiceAccount
		// (0004 §4.3): reading the bundle Secret, in the operator's
		// namespace (default here).
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "inkwall-bundle-reader"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{bundle.BundleSecret}, Verbs: []string{"get"}}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "inkwall-bundle-reader"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "inkwall-bundle-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "edge", Name: "traefik"}},
		},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	var certs, keys corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "inkwall-operator-webhook-tls"}, &certs); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certs.Data["ca.crt"]) {
		t.Fatal("no CA in the certificate Secret")
	}
	_, port, _ := net.SplitHostPort(distAddr)
	engine := func(id, sa string) *fakeengine.Engine {
		return &fakeengine.Engine{
			ID:        id,
			Addr:      "localhost:" + port,
			TLS:       &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			Token:     token(ctx, t, "edge", sa),
			PublicKey: ed25519.PublicKey(keys.Data[bundle.PublicKeyKey]),
			Heartbeat: 200 * time.Millisecond,
		}
	}
	run := func(e *fakeengine.Engine) context.CancelFunc {
		ectx, cancel := context.WithCancel(ctx)
		go func() { _ = e.Run(ectx) }()
		return cancel
	}

	// Without the RBAC grant, or without a token, no bundle.
	for _, tc := range []struct {
		name string
		e    *fakeengine.Engine
		code codes.Code
	}{
		{"no access to the bundle", engine("intruder", "intruder"), codes.PermissionDenied},
		{"no token", func() *fakeengine.Engine { e := engine("anonymous", "traefik"); e.Token = ""; return e }(), codes.Unauthenticated},
	} {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := tc.e.Run(rctx)
		cancel()
		if status.Code(err) != tc.code {
			t.Errorf("%s: got %v, want %s", tc.name, err, tc.code)
		}
	}

	// A policy for the engines to enforce.
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "web"}}); err != nil {
		t.Fatal(err)
	}
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "web"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "web.example.com", IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}}}}},
		}}}},
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "web"},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}},
	}
	for _, o := range []client.Object{ing, pol} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	wantEnforced := func(what string, st metav1.ConditionStatus, reason, msg string) {
		t.Helper()
		eventually(t, what, func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &got); err != nil {
				return err.Error()
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionEnforced)
			if cond == nil {
				return "no Enforced condition"
			}
			if cond.Status != st || cond.Reason != reason || !strings.Contains(cond.Message, msg) {
				return "Enforced " + string(cond.Status) + " " + cond.Reason + ": " + cond.Message
			}
			return ""
		})
	}
	wantEnforced("no engines yet", metav1.ConditionFalse, distribution.ReasonNoEngines, "no engine")

	// An allowed engine gets the bundle with the policy, and acks it.
	good := engine("traefik-1", "traefik")
	stopGood := run(good)
	defer stopGood()
	eventually(t, "the engine runs the bundle with the policy", func() string {
		b := good.Applied()
		for _, p := range b.GetPolicies() {
			if p.GetId() == "web/web" {
				return ""
			}
		}
		if err := good.Err(); err != nil {
			return err.Error()
		}
		return "policy not received"
	})
	wantEnforced("one engine", metav1.ConditionTrue, distribution.ReasonEnforced, "1/1 engines on bundle")

	// An edit reaches the running engine without reconnecting.
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
	eventually(t, "the edit pushed", func() string {
		for _, p := range good.Applied().GetPolicies() {
			if p.GetId() == "web/web" && p.GetMode() == bundlev1.Mode_MODE_BLOCK {
				return ""
			}
		}
		return "still in detect mode"
	})
	wantEnforced("edit enforced", metav1.ConditionTrue, distribution.ReasonEnforced, "1/1 engines")

	// An engine that rejects the bundle shows up, until it goes away.
	bad := engine("traefik-2", "traefik")
	bad.Reject = func(*bundlev1.Bundle) error { return errors.New("line 1: rule does not compile") }
	stopBad := run(bad)
	wantEnforced("a rejecting engine", metav1.ConditionFalse, distribution.ReasonEngineNack, "1/2 engines rejected bundle")
	stopBad()
	wantEnforced("the rejecting engine gone", metav1.ConditionTrue, distribution.ReasonEnforced, "1/1 engines")

	stopGood()
	wantEnforced("all engines gone", metav1.ConditionFalse, distribution.ReasonNoEngines, "no engine")
}
