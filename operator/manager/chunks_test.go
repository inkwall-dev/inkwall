// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// testBundleChunks publishes a bundle too large for one Secret: it is split
// into chunks, a new engine reads them from the API server with the grant
// injection gives, and once the bundle fits again the chunks are deleted.
func testBundleChunks(ctx context.Context, t *testing.T, c client.Client) {
	// Rule sets of random comments: about 190 KiB each, compressed.
	const ruleSets = 6
	var objs []client.Object
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: "big"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "big"}},
			Mode:       wafv1alpha1.PolicyDetect,
		},
	}
	for i := range ruleSets {
		name := fmt.Sprintf("noise-%d", i)
		objs = append(objs, &wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: noiseRules(t, 250<<10)}},
		})
		pol.Spec.RuleSets = append(pol.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
	}
	prefix := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "big", Name: "big"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "big.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "big", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	objs = append([]client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "big"}}, ing}, append(objs, pol)...)
	for _, o := range objs {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	var version uint64
	eventually(t, "the bundle published in chunks", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		if s.Data[bundle.ManifestKey] == nil || s.Data[bundle.BundleKey] != nil {
			return "not in chunks"
		}
		b := current(ctx, t, c)
		if findPolicy(b, "big/big") == nil {
			return "big/big not in the bundle"
		}
		version = b.GetVersion()
		return ""
	})
	if n := len(chunkSecrets(ctx, t, c)); n < 2 {
		t.Fatalf("%d chunk Secrets, want 2 or more", n)
	}

	// A new engine, the operator unreachable, reads the chunks with what
	// injection grants (the inkwall-bundle-reader Role).
	for _, o := range []client.Object{
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "chunk-reader"},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
				ResourceNames: append([]string{bundle.BundleSecret}, bundlesecret.ChunkNames(bundle.BundleSecret)...)}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "chunk-reader"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "chunk-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "edge", Name: "traefik"}},
		},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var keys corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"ed25519.pub": keys.Data[bundle.PublicKeyKey],
		"kube-token":  []byte(apiToken(ctx, t, "edge", "traefik")),
		"kube-ca.crt": env.Config.CAData,
		"ca.crt":      env.Config.CAData,
		"token":       []byte("unused"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	holder := &policy.Holder{}
	adm := pipeline.NewAdmission(4)
	a, err := agent.New(agent.Config{
		Addr:          "127.0.0.1:1",
		CAFile:        filepath.Join(dir, "ca.crt"),
		TokenFile:     filepath.Join(dir, "token"),
		PublicKeyFile: filepath.Join(dir, "ed25519.pub"),
		Secret: &agent.SecretSource{Namespace: "default", Name: bundle.BundleSecret, APIServer: env.Config.Host,
			CAFile: filepath.Join(dir, "kube-ca.crt"), TokenFile: filepath.Join(dir, "kube-token")},
		EngineID: "cold-engine",
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			return policy.Compile(b, policy.Options{Admission: adm, BodyLimit: 65536})
		},
		Holder:    holder,
		Admission: adm,
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(actx); close(done) }()
	eventually(t, "the engine applies the chunked bundle", func() string {
		if v := a.Version(); v != version {
			return fmt.Sprintf("version %d, want %d", v, version)
		}
		return ""
	})
	cancel()
	<-done

	// A deleted chunk: the bundle is published again, as a new version.
	chunks := chunkSecrets(ctx, t, c)
	if err := c.Delete(ctx, &chunks[len(chunks)-1]); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the bundle published again", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		signed, err := bundle.Read(ctx, c, &s)
		if err != nil {
			return err.Error()
		}
		var b bundlev1.Bundle
		if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil || b.GetVersion() <= version || findPolicy(&b, "big/big") == nil {
			return fmt.Sprintf("version %d, %v", b.GetVersion(), err)
		}
		return ""
	})

	// Small again: one Secret, the chunks deleted.
	for _, o := range objs[1:] {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the chunks deleted", func() string {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.BundleSecret}, &s); err != nil {
			return err.Error()
		}
		if s.Data[bundle.BundleKey] == nil {
			return "not in one Secret"
		}
		if n := len(chunkSecrets(ctx, t, c)); n != 0 {
			return fmt.Sprintf("%d chunk Secrets left", n)
		}
		return ""
	})
}

// noiseRules returns SecLang comments of n random bytes, which don't
// compress.
func noiseRules(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n*3/4)
	_, _ = rand.Read(raw)
	enc := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	for len(enc) > 0 {
		k := min(len(enc), 100)
		b.WriteString("# " + enc[:k] + "\n")
		enc = enc[k:]
	}
	return b.String()[:min(b.Len(), n)]
}

func chunkSecrets(ctx context.Context, t *testing.T, c client.Client) []corev1.Secret {
	t.Helper()
	var l corev1.SecretList
	if err := c.List(ctx, &l, client.InNamespace("default"), client.MatchingLabels{bundle.ChunkLabel: bundle.BundleSecret}); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

// apiToken issues a ServiceAccount token for the API server, as the
// engine's second projected token.
func apiToken(ctx context.Context, t *testing.T, namespace, sa string) string {
	t.Helper()
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return tr.Status.Token
}
