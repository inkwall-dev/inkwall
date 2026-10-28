// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/test/fakecontrolplane"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// apiServer is an API server with the Inkwall CRDs (no webhooks), for the
// tests that need its validation and dry runs; nil without envtest.
var apiServer *testenv.Env

func TestMain(m *testing.M) {
	log.SetLogger(logr.Discard())
	var (
		stop func()
		err  error
	)
	apiServer, stop, err = testenv.Start(testenv.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

const app = "shop"

// cluster is the API server in mode, with the operator's and the app's
// namespaces and an identity Secret; cleaned up after the test.
func cluster(t *testing.T, mode wafv1alpha1.ClusterMode, endpoint string) client.Client {
	t.Helper()
	testenv.Skip(t, apiServer)
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	c, err := client.New(apiServer.Config, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, n := range []string{ns, app} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	if endpoint == "" {
		endpoint = "grpcs://cp.example:443"
	}
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wafv1alpha1.InkwallConfigSpec{
		Mode: mode, ControlPlane: &wafv1alpha1.ControlPlane{Endpoint: endpoint, EnrollmentSecretRef: wafv1alpha1.SecretReference{Namespace: ns, Name: "enrollment"}},
	}}
	if err := c.Create(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Delete(ctx, cfg)
		_ = c.DeleteAllOf(ctx, &corev1.Secret{}, client.InNamespace(ns))
		_ = c.DeleteAllOf(ctx, &wafv1alpha1.WAFPolicy{}, client.InNamespace(app))
		_ = c.DeleteAllOf(ctx, &wafv1alpha1.WAFRuleSet{}, client.InNamespace(app))
		_ = c.DeleteAllOf(ctx, &wafv1alpha1.ClusterWAFRuleSet{})
	})
	return c
}

// withIdentity adds a placeholder identity Secret, which records the
// policy version.
func withIdentity(t *testing.T, c client.Client) {
	t.Helper()
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: IdentitySecret}}
	if err := c.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func newApplier(c client.Client) *applier {
	return &applier{client: c, reader: c, namespace: ns, backoff: defaultApplyBackoff}
}

func obj(kind, namespace, name, spec string, labels map[string]string) *controlplanev1.Object {
	return &controlplanev1.Object{ApiVersion: "waf.inkwall.dev/v1alpha1", Kind: kind, Namespace: namespace, Name: name, Labels: labels, Spec: []byte(spec)}
}

func policyObj(name, mode string) *controlplanev1.Object {
	return obj("WAFPolicy", app, name, `{"targetRefs":[{"kind":"Ingress","name":"`+name+`"}],"mode":"`+mode+`"}`, nil)
}

func snapshot(v uint64, objs ...*controlplanev1.Object) *controlplanev1.PolicySnapshot {
	return &controlplanev1.PolicySnapshot{Version: v, Objects: objs}
}

// wantAck applies snap and fails unless it is acknowledged.
func wantAck(t *testing.T, a *applier, snap *controlplanev1.PolicySnapshot) {
	t.Helper()
	msg, err := a.apply(context.Background(), snap)
	if err != nil {
		t.Fatalf("snapshot %d: %v", snap.GetVersion(), err)
	}
	if ack := msg.GetPolicyAck(); ack == nil || ack.GetVersion() != snap.GetVersion() {
		t.Fatalf("snapshot %d: got %v, want PolicyAck", snap.GetVersion(), msg)
	}
}

// wantNack applies snap and fails unless it is refused with an error
// containing want, and returns the refusal.
func wantNack(t *testing.T, a *applier, snap *controlplanev1.PolicySnapshot, want string) *controlplanev1.PolicyNack {
	t.Helper()
	msg, err := a.apply(context.Background(), snap)
	if err != nil {
		t.Fatalf("snapshot %d: %v", snap.GetVersion(), err)
	}
	n := msg.GetPolicyNack()
	if n == nil || n.GetVersion() != snap.GetVersion() {
		t.Fatalf("snapshot %d: got %v, want PolicyNack", snap.GetVersion(), msg)
	}
	all := n.GetError()
	for _, o := range n.GetObjects() {
		all += "; " + o.GetName() + ": " + o.GetError()
	}
	if !strings.Contains(all, want) {
		t.Fatalf("snapshot %d refused with %q, want %q", snap.GetVersion(), all, want)
	}
	return n
}

func exists(t *testing.T, c client.Client, o client.Object, namespace, name string) bool {
	t.Helper()
	err := c.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, o)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func policyVersion(t *testing.T, c client.Client) string {
	t.Helper()
	var s corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: IdentitySecret}, &s); err != nil {
		t.Fatal(err)
	}
	return s.Annotations[policyVersionAnnotation]
}

func TestSnapshotApplyAndPrune(t *testing.T) {
	c := cluster(t, wafv1alpha1.ModeManaged, "")
	withIdentity(t, c)
	ctx := context.Background()
	// The cluster's own policy: never touched.
	mine := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: app, Name: "mine"},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "mine"}}},
	}
	if err := c.Create(ctx, mine); err != nil {
		t.Fatal(err)
	}
	a := newApplier(c)

	checkout := policyObj("checkout", "Block")
	// The snapshot can't choose the source label.
	checkout.Labels = map[string]string{"team": "payments", wafv1alpha1.SourceLabel: "gitops"}
	wantAck(t, a, snapshot(1,
		checkout,
		obj("WAFRuleSet", app, "custom", `{"source":{"seclang":"SecRule ARGS \"@contains evil\" \"id:100001,phase:2,deny\""}}`, nil),
		obj("ClusterWAFRuleSet", "", "crs", `{"source":{"builtin":"crs-v4"}}`, nil),
	))
	var p wafv1alpha1.WAFPolicy
	if !exists(t, c, &p, app, "checkout") {
		t.Fatal("the policy wasn't written")
	}
	if p.Labels[wafv1alpha1.SourceLabel] != wafv1alpha1.SourceSaaS || p.Labels["team"] != "payments" || p.Spec.Mode != wafv1alpha1.PolicyBlock {
		t.Errorf("policy %v %+v", p.Labels, p.Spec)
	}
	if !exists(t, c, &wafv1alpha1.WAFRuleSet{}, app, "custom") || !exists(t, c, &wafv1alpha1.ClusterWAFRuleSet{}, "", "crs") {
		t.Error("the rule sets weren't written")
	}
	if v := policyVersion(t, c); v != "1" || a.applied != 1 {
		t.Errorf("policy version %q, applied %d", v, a.applied)
	}

	// The next snapshot changes the policy and drops the rule sets.
	wantAck(t, a, snapshot(2, policyObj("checkout", "Detect")))
	if exists(t, c, &p, app, "checkout"); p.Spec.Mode != wafv1alpha1.PolicyDetect || p.Generation != 2 {
		t.Errorf("policy not updated: generation %d, %+v", p.Generation, p.Spec)
	}
	if exists(t, c, &wafv1alpha1.WAFRuleSet{}, app, "custom") || exists(t, c, &wafv1alpha1.ClusterWAFRuleSet{}, "", "crs") {
		t.Error("the rule sets weren't deleted")
	}

	// An empty snapshot deletes everything of the control plane's.
	wantAck(t, a, snapshot(3))
	if exists(t, c, &p, app, "checkout") {
		t.Error("the policy wasn't deleted")
	}
	if !exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "mine") {
		t.Error("the cluster's own policy was deleted")
	}
	if v := policyVersion(t, c); v != "3" {
		t.Errorf("policy version %q", v)
	}
}

// One bad object refuses the whole snapshot: nothing is written or
// deleted.
func TestSnapshotAllOrNothing(t *testing.T) {
	c := cluster(t, wafv1alpha1.ModeManaged, "")
	withIdentity(t, c)
	ctx := context.Background()
	mine := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: app, Name: "mine"},
		Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "mine"}}},
	}
	if err := c.Create(ctx, mine); err != nil {
		t.Fatal(err)
	}
	a := newApplier(c)
	wantAck(t, a, snapshot(1, policyObj("kept", "Block")))

	good := policyObj("new", "Block")
	for i, tc := range []struct {
		name string
		bad  *controlplanev1.Object
		want string
	}{
		{"an unknown field", obj("WAFPolicy", app, "bad", `{"targetRefs":[{"kind":"Ingress","name":"x"}],"rateLimits":[{}]}`, nil), `unknown field "spec.rateLimits"`},
		{"refused by the schema", obj("WAFPolicy", app, "bad", `{"mode":"Block"}`, nil), "targetRefs"},
		{"another kind", obj("InkwallConfig", "", "default", `{"mode":"Standalone"}`, nil), `kind "InkwallConfig"`},
		{"another API version", &controlplanev1.Object{ApiVersion: "waf.inkwall.dev/v2", Kind: "WAFPolicy", Namespace: app, Name: "bad", Spec: []byte(`{}`)}, "apiVersion"},
		{"rules from a ConfigMap", obj("WAFRuleSet", app, "bad", `{"source":{"configMapRef":{"name":"r","key":"k"}}}`, nil), "configMapRef"},
		{"no namespace", obj("WAFPolicy", "", "bad", `{}`, nil), "no namespace"},
		{"a namespace that doesn't exist", obj("WAFPolicy", "nowhere", "bad", `{"targetRefs":[{"kind":"Ingress","name":"x"}]}`, nil), "not found"},
		{"a spec that isn't an object", obj("WAFPolicy", app, "bad", `[]`, nil), "not a JSON object"},
		{"twice", policyObj("new", "Detect"), "twice"},
		{"the cluster's own object", policyObj("mine", "Block"), "isn't the control plane's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := wantNack(t, a, snapshot(uint64(2+i), good, tc.bad), tc.want)
			if len(n.GetObjects()) != 1 || n.GetObjects()[0].GetName() != tc.bad.GetName() {
				t.Errorf("refused objects %v, want only %s", n.GetObjects(), tc.bad.GetName())
			}
			if exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "new") {
				t.Fatal("the good object was written")
			}
			if !exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "kept") {
				t.Fatal("the applied snapshot's object was deleted")
			}
		})
	}
	var p wafv1alpha1.WAFPolicy
	if exists(t, c, &p, app, "mine"); p.Labels[wafv1alpha1.SourceLabel] != "" || p.Generation != 1 {
		t.Errorf("the cluster's own policy changed: %v %+v", p.Labels, p.Spec)
	}
	if v := policyVersion(t, c); v != "1" {
		t.Errorf("policy version %q after refusals", v)
	}
}

func TestSnapshotVersions(t *testing.T) {
	c := cluster(t, wafv1alpha1.ModeManaged, "")
	withIdentity(t, c)
	a := newApplier(c)
	wantAck(t, a, snapshot(5, policyObj("checkout", "Block")))

	wantNack(t, a, snapshot(3), "older than the applied snapshot 5")
	if !exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "checkout") {
		t.Fatal("an older snapshot deleted the policy")
	}
	wantNack(t, a, snapshot(0), "version 0")
	// The same version again, after a reconnect say: applied again, which
	// changes nothing.
	wantAck(t, a, snapshot(5, policyObj("checkout", "Block")))
	if a.applied != 5 {
		t.Errorf("applied %d", a.applied)
	}
}

// A cluster in GitOps mode refuses snapshots and writes nothing.
func TestSnapshotNotManaged(t *testing.T) {
	c := cluster(t, wafv1alpha1.ModeGitOps, "")
	a := newApplier(c)
	wantNack(t, a, snapshot(1, policyObj("checkout", "Block")), "not in Managed mode")
	if exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "checkout") {
		t.Error("written in GitOps mode")
	}
}

// The round trip over the stream: a snapshot from the control plane is
// written and acknowledged, the next Hello carries its version, and the
// next snapshot prunes.
func TestManagedRoundTrip(t *testing.T) {
	testenv.Skip(t, apiServer)
	cp, err := fakecontrolplane.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cp.Stop)
	cp.HeartbeatInterval = 50 * time.Millisecond
	cp.AddToken("tok-1")
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, cp.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cluster(t, wafv1alpha1.ModeManaged, cp.Endpoint())
	ctx := context.Background()
	if err := c.Create(ctx, tokenSecret("tok-1")); err != nil {
		t.Fatal(err)
	}
	e := &env{cp: cp, client: c, conn: &Connector{
		Client: c, APIReader: c, Namespace: ns, Replica: "op-0", OperatorVersion: "0.2.0-test",
		CAFile: ca, Poll: 50 * time.Millisecond, MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
	}}
	e.run(t)
	e.waitReason(t, ReasonConnected)

	acked := func(v uint64) func() bool {
		return func() bool { return slices.Contains(cp.Stats().Acks, v) }
	}
	if sent, err := cp.SendSnapshot(snapshot(1, policyObj("checkout", "Block"))); !sent || err != nil {
		t.Fatalf("send: %v %v", sent, err)
	}
	waitFor(t, "PolicyAck 1", acked(1))
	if !exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "checkout") {
		t.Fatal("the policy wasn't written")
	}

	// A new stream says which snapshot the cluster has: the control plane
	// doesn't send it again.
	hellos := len(cp.Stats().Hellos)
	var cfg wafv1alpha1.InkwallConfig
	if err := c.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Spec.Suspend = true
	if err := c.Update(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a new Hello", func() bool { return len(cp.Stats().Hellos) > hellos })
	if h := cp.Stats().Hellos[len(cp.Stats().Hellos)-1]; h.GetPolicyVersion() != 1 || h.GetMode() != controlplanev1.ClusterMode_CLUSTER_MODE_MANAGED {
		t.Errorf("hello %v", h)
	}

	if sent, err := cp.SendSnapshot(snapshot(2)); !sent || err != nil {
		t.Fatalf("send: %v %v", sent, err)
	}
	waitFor(t, "PolicyAck 2", acked(2))
	if exists(t, c, &wafv1alpha1.WAFPolicy{}, app, "checkout") {
		t.Error("the policy wasn't deleted")
	}
	if st := cp.Stats(); len(st.Acks) != 2 || len(st.Nacks) != 0 {
		t.Errorf("acks %v, nacks %v", st.Acks, st.Nacks)
	}
}

// Over the stream too: a GitOps cluster answers a snapshot with PolicyNack.
func TestGitOpsRefusesSnapshots(t *testing.T) {
	e := newEnv(t, wafv1alpha1.ModeGitOps, "tok-1")
	e.cp.AddToken("tok-1")
	e.run(t)
	e.waitReason(t, ReasonConnected)
	if sent, err := e.cp.SendSnapshot(snapshot(1, policyObj("checkout", "Block"))); !sent || err != nil {
		t.Fatalf("send: %v %v", sent, err)
	}
	waitFor(t, "PolicyNack", func() bool { return len(e.cp.Stats().Nacks) == 1 })
	if n := e.cp.Stats().Nacks[0]; n.GetVersion() != 1 || !strings.Contains(n.GetError(), "not in Managed mode") {
		t.Errorf("nack %v", n)
	}
	var list wafv1alpha1.WAFPolicyList
	if err := e.client.List(context.Background(), &list); err != nil || len(list.Items) != 0 {
		t.Errorf("policies %v, %v", list.Items, err)
	}
}

// A dry run that can't be done (the API server or the webhook unreachable)
// isn't a refusal: no PolicyNack, an error, and the stream reconnects.
func TestSnapshotDryRunUnavailable(t *testing.T) {
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wafv1alpha1.InkwallConfigSpec{Mode: wafv1alpha1.ModeManaged}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cfg).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return apierrors.NewInternalError(errors.New(`failed calling webhook "wafpolicies.waf.inkwall.dev": connection refused`))
		},
	}).Build()
	msg, err := newApplier(c).apply(context.Background(), snapshot(1, policyObj("checkout", "Block")))
	if err == nil || msg != nil {
		t.Fatalf("got %v, %v: want an error", msg, err)
	}
}
