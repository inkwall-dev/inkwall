// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/test/fakecontrolplane"
)

const ns = "inkwall-system"

type env struct {
	cp     *fakecontrolplane.Server
	client client.Client
	conn   *Connector
}

// newEnv starts a fake control plane and a cluster with an InkwallConfig in
// mode, pointing at it, and the token in the enrollment Secret.
func newEnv(t *testing.T, mode wafv1alpha1.ClusterMode, token string) *env {
	t.Helper()
	cp, err := fakecontrolplane.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cp.Stop)
	cp.HeartbeatInterval = 50 * time.Millisecond
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, cp.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}

	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &wafv1alpha1.InkwallConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec: wafv1alpha1.InkwallConfigSpec{Mode: mode, ControlPlane: &wafv1alpha1.ControlPlane{
			Endpoint:            cp.Endpoint(),
			EnrollmentSecretRef: wafv1alpha1.SecretReference{Namespace: ns, Name: "enrollment"},
		}},
	}
	objs := []client.Object{
		cfg,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "uid-1"}},
	}
	if token != "" {
		objs = append(objs, tokenSecret(token))
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&wafv1alpha1.InkwallConfig{}).Build()
	return &env{cp: cp, client: c, conn: &Connector{
		Client: c, APIReader: c, Namespace: ns, Replica: "op-0", OperatorVersion: "0.2.0-test",
		KubernetesVersion: func() string { return "v1.37.0" },
		CAFile:            ca,
		Poll:              50 * time.Millisecond, MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
	}}
}

func tokenSecret(token string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "enrollment"}, Data: map[string][]byte{TokenKey: []byte(token)}}
}

func (e *env) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = e.conn.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func (e *env) condition() *metav1.Condition {
	var cfg wafv1alpha1.InkwallConfig
	if err := e.client.Get(context.Background(), types.NamespacedName{Name: "default"}, &cfg); err != nil {
		return nil
	}
	return meta.FindStatusCondition(cfg.Status.Conditions, wafv1alpha1.ConditionControlPlaneConnected)
}

func (e *env) waitReason(t *testing.T, reason string) *metav1.Condition {
	t.Helper()
	var c *metav1.Condition
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c = e.condition(); c != nil && c.Reason == reason {
			return c
		}
	}
	t.Fatalf("condition never reached %s: %+v", reason, c)
	return nil
}

func (e *env) identity(t *testing.T) *identity {
	t.Helper()
	id, err := loadIdentity(context.Background(), e.client, ns)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// waitFor waits up to a minute for cond: a loaded machine has taken more
// than 10s to forward a large batch under the race detector.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestEnrollAndConnect(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.run(t)

	c := e.waitReason(t, ReasonConnected)
	if c.Status != metav1.ConditionTrue {
		t.Errorf("condition %+v", c)
	}
	id := e.identity(t)
	if id == nil || id.clusterID != "cluster-1" || id.tokenHash != tokenHash("token-1") {
		t.Fatalf("identity %+v", id)
	}
	waitFor(t, "heartbeats", func() bool { return e.cp.Stats().Heartbeats >= 2 })
	h := e.cp.Stats().Hellos[0]
	if h.GetRole() != controlplanev1.StreamRole_STREAM_ROLE_PRIMARY || h.GetMode() != controlplanev1.ClusterMode_CLUSTER_MODE_GITOPS ||
		h.GetClusterUid() != "uid-1" || h.GetReplica() != "op-0" || h.GetKubernetesVersion() != "v1.37.0" ||
		len(h.GetCapabilities()) != 1 || h.GetCapabilities()[0] != "waf.inkwall.dev/v1alpha1" {
		t.Errorf("hello %v", h)
	}
}

// A lost Enroll response: the retry sends the same key and gets the same
// certificate, so the token isn't wasted.
func TestEnrollRetryAfterLostResponse(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.cp.DropEnrollResponses(1)
	e.run(t)

	e.waitReason(t, ReasonConnected)
	st := e.cp.Stats()
	if st.EnrollCalls < 2 || st.Clusters != 1 {
		t.Errorf("enroll calls %d, clusters %d: want a retry of the same enrollment", st.EnrollCalls, st.Clusters)
	}
}

func TestTokenRejectedThenReplaced(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeManaged, "wrong")
	e.cp.AddToken("token-2")
	e.run(t)

	e.waitReason(t, ReasonTokenRejected)
	calls := e.cp.Stats().EnrollCalls
	time.Sleep(200 * time.Millisecond)
	if e.cp.Stats().EnrollCalls != calls {
		t.Error("a rejected token was sent again")
	}

	// A new token: enrolled.
	if err := e.client.Update(context.Background(), tokenSecret("token-2")); err != nil {
		t.Fatal(err)
	}
	e.waitReason(t, ReasonConnected)
	if m := e.cp.Stats().Hellos[0].GetMode(); m != controlplanev1.ClusterMode_CLUSTER_MODE_MANAGED {
		t.Errorf("mode %s", m)
	}
}

func TestRenewal(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.cp.CertLifetime = 2 * time.Second
	e.run(t)

	e.waitReason(t, ReasonConnected)
	first := e.identity(t)
	waitFor(t, "a renewal", func() bool { return e.cp.Stats().Renewals >= 1 })
	waitFor(t, "the renewed certificate stored", func() bool {
		id := e.identity(t)
		return id != nil && id.cert.Leaf.SerialNumber.Cmp(first.cert.Leaf.SerialNumber) != 0
	})
	next := e.identity(t)
	if next.clusterID != first.clusterID || next.cert.PrivateKey == first.cert.PrivateKey || !next.notAfter.After(first.notAfter) {
		t.Errorf("renewed identity %+v", next)
	}
	if st := e.cp.Stats(); st.EnrollCalls != 1 {
		t.Errorf("renewal enrolled again: %d calls", st.EnrollCalls)
	}
}

// UNAUTHENTICATED: the certificate is dropped, and the operator waits for a
// new token, then enrolls with it.
func TestCertificateRejected(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.run(t)
	e.waitReason(t, ReasonConnected)

	e.cp.FailConnect(status.Error(codes.Unauthenticated, "certificate revoked"))
	bumpGeneration(t, e) // a new stream
	e.waitReason(t, ReasonCertificateRejected)
	waitFor(t, "the identity deleted", func() bool { return e.identity(t) == nil })

	e.cp.FailConnect(nil)
	e.cp.AddToken("token-2")
	if err := e.client.Update(context.Background(), tokenSecret("token-2")); err != nil {
		t.Fatal(err)
	}
	e.waitReason(t, ReasonConnected)
	if id := e.identity(t); id.clusterID != "cluster-2" {
		t.Errorf("re-enrolled as %s", id.clusterID)
	}
}

// PERMISSION_DENIED on Connect: the operator stops until the configuration
// changes.
func TestClusterDisabled(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.cp.FailConnect(status.Error(codes.PermissionDenied, "cluster disabled"))
	e.run(t)

	e.waitReason(t, ReasonClusterDisabled)
	calls := e.cp.Stats().ConnectCalls
	time.Sleep(300 * time.Millisecond)
	if n := e.cp.Stats().ConnectCalls; n != calls {
		t.Errorf("reconnected %d times to a disabled cluster", n-calls)
	}
	e.cp.FailConnect(nil)
	bumpGeneration(t, e)
	e.waitReason(t, ReasonConnected)
}

func TestStandaloneDoesNothing(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeStandalone, "token-1")
	e.cp.AddToken("token-1")
	e.run(t)
	time.Sleep(300 * time.Millisecond)
	if st := e.cp.Stats(); st.EnrollCalls != 0 || st.ConnectCalls != 0 {
		t.Errorf("Standalone contacted the control plane: %+v", st)
	}
	if c := e.condition(); c != nil {
		t.Errorf("condition in Standalone: %+v", c)
	}
}

func TestTokenOutsideTheOperatorNamespace(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "")
	var cfg wafv1alpha1.InkwallConfig
	ctx := context.Background()
	if err := e.client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Spec.ControlPlane.EnrollmentSecretRef.Namespace = "default"
	if err := e.client.Update(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	e.run(t)
	e.waitReason(t, ReasonTokenSecretElsewhere)

	// And a missing token in the right namespace.
	if err := e.client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Spec.ControlPlane.EnrollmentSecretRef.Namespace = ns
	if err := e.client.Update(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	e.waitReason(t, ReasonTokenSecretMissing)
}

func TestParseEndpoint(t *testing.T) {
	for _, tc := range []struct{ in, target, host string }{
		{"grpcs://cp-gateway:8443", "cp-gateway:8443", "cp-gateway"},
		{"grpcs://[::1]:8443", "[::1]:8443", "::1"},
	} {
		target, host, err := parseEndpoint(tc.in)
		if err != nil || target != tc.target || host != tc.host {
			t.Errorf("%s: %s %s %v", tc.in, target, host, err)
		}
	}
	for _, bad := range []string{"https://cp:8443", "grpcs://cp", "grpcs://:8443"} {
		if _, _, err := parseEndpoint(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// bumpGeneration changes the InkwallConfig, as an edit would: the connector
// opens a new stream.
func bumpGeneration(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	var cfg wafv1alpha1.InkwallConfig
	if err := e.client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Spec.Suspend = !cfg.Spec.Suspend
	cfg.Generation++
	if err := e.client.Update(ctx, &cfg); err != nil && !apierrors.IsConflict(err) {
		t.Fatal(err)
	}
}

// A certificate that expired while the operator was down: the identity is
// dropped and the operator asks for a new token.
func TestCertificateExpired(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	e.cp.AddToken("token-1")
	e.cp.CertLifetime = 100 * time.Millisecond
	// Enroll once, without the connector running (so nothing renews).
	ctx := context.Background()
	e.conn.defaults()
	var cfg wafv1alpha1.InkwallConfig
	if err := e.client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	target, host, _ := parseEndpoint(cfg.Spec.ControlPlane.Endpoint)
	if _, err := e.conn.enroll(ctx, &cfg, target, host); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	e.run(t)
	c := e.waitReason(t, ReasonCertificateExpired)
	if c.Status != metav1.ConditionFalse || e.identity(t) != nil {
		t.Errorf("condition %+v, identity kept: %v", c, e.identity(t) != nil)
	}
	if st := e.cp.Stats(); st.ConnectCalls != 0 || st.EnrollCalls != 1 {
		t.Errorf("used an expired certificate or a used token: %+v", st)
	}
}

// A certificate the control plane never issued: rejected in the RPC
// (UNAUTHENTICATED), not in the TLS handshake, so the operator asks for a
// new token instead of retrying as if the network were down.
func TestForeignCertificate(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "token-1")
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "cluster-x"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newIdentity("cluster-x", [][]byte{der}, key, tokenHash("token-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeIdentity(context.Background(), e.client, ns, id); err != nil {
		t.Fatal(err)
	}
	e.run(t)
	e.waitReason(t, ReasonCertificateRejected)
	waitFor(t, "the identity deleted", func() bool { return e.identity(t) == nil })
}
