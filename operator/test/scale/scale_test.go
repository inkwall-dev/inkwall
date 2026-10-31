// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package scale checks the operator's scale targets (0004 §8) against a
// local API server (envtest) and fake engines: it creates policies and the
// routes they target (Ingresses and Traefik IngressRoutes, 10 routes per
// policy), connects fake engines that speak the bundle protocol, and
// measures the operator's memory, the bundle's size and the time from a
// change to every engine having the bundle with it.
//
// It runs only with INKWALL_SCALE set to "<policies>x<engines>", e.g.
// 100x50 (`make scale-test`). The operator runs in this process, with its
// production defaults, so the memory measured is the operator's (and this
// test's, which is small); the API server and etcd are separate processes,
// and so are the fake engines (a child process, this test binary again),
// so neither is counted.
package scale

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/protobuf/proto"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/manager"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/operator/test/fakeengine"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const (
	// scaleEnv selects the size: "<policies>x<engines>".
	scaleEnv = "INKWALL_SCALE"
	// changesEnv is the number of single-policy edits timed (default 10).
	changesEnv = "INKWALL_SCALE_CHANGES"
	// outEnv, if set, is a file each run appends its results to, as JSON.
	outEnv = "INKWALL_SCALE_OUT"
	// logEnv, if set, is a file for the operator's logs (warnings and
	// errors); else they are discarded: at scale, conflicts retried are
	// many.
	logEnv = "INKWALL_SCALE_LOG"
	// engineHostEnv makes the test binary the fake engines' process.
	engineHostEnv = "INKWALL_SCALE_ENGINE_HOST"

	// routesPerPolicy: 0004 §8 has 50,000 routes for 5,000 policies.
	routesPerPolicy = 10
	// operatorNamespace is the operator's, as the Helm chart installs it.
	operatorNamespace = "inkwall-system"
	// engineNamespace and engineSA are the fake engines' ServiceAccount.
	engineNamespace, engineSA = "edge", "traefik"
	certSecret                = "inkwall-operator-webhook-tls"

	// The scale targets (0004 §8).
	targetMemory  = 512 << 20
	targetLatency = 10 * time.Second
)

var env *testenv.Env

func TestMain(m *testing.M) {
	if os.Getenv(engineHostEnv) != "" {
		os.Exit(hostEngines())
	}
	if os.Getenv(scaleEnv) == "" {
		os.Exit(m.Run()) // TestScale skips.
	}
	os.Exit(run(m))
}

// run starts the API server and runs the tests.
func run(m *testing.M) int {
	logs := io.Discard
	if path := os.Getenv(logEnv); path != "" {
		f, err := os.Create(path) // #nosec G304 -- the caller's file
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = f.Close() }()
		logs = f
	}
	ctrl.SetLogger(logr.FromSlogHandler(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	// The webhook server's TLS handshake errors (API server connections
	// closed early) go to the standard logger.
	log.SetOutput(logs)
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{Webhooks: true})
	defer stop()
	if err == nil && env != nil {
		// Traefik's IngressRoute CRD, installed before the operator starts.
		err = testenv.InstallLater(env)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		return 1
	}
	return m.Run()
}

// Result is one run's measurements, appended to INKWALL_SCALE_OUT.
type Result struct {
	Policies int `json:"policies"`
	Routes   int `json:"routes"`
	Engines  int `json:"engines"`
	Changes  int `json:"changes"`
	// MemoryLimitBytes is the Go runtime's soft memory limit.
	MemoryLimitBytes int64 `json:"memoryLimitBytes"`

	// CreateSeconds: creating every policy and route.
	CreateSeconds float64 `json:"createSeconds"`
	// SyncSeconds: from the last object created to every engine having
	// the bundle with all policies; 0 if they never did.
	SyncSeconds float64 `json:"syncSeconds"`
	// ConnectSeconds: until every engine has its first bundle (empty).
	ConnectSeconds float64 `json:"connectSeconds"`

	// Change → every engine has the bundle with it, over Changes edits.
	AllEnginesP50 float64 `json:"allEnginesP50Seconds"`
	AllEnginesP95 float64 `json:"allEnginesP95Seconds"`
	AllEnginesMax float64 `json:"allEnginesMaxSeconds"`
	// Change → one engine has it, over every engine and edit.
	PerEngineP95 float64 `json:"perEngineP95Seconds"`

	// ReconcileSeconds: the bundle reconciler's mean duration during the
	// edits (resolve, build, sign, store, status of every policy).
	ReconcileSeconds float64 `json:"reconcileSeconds"`
	// ResolveSeconds: resolver.Resolve alone, on the same objects.
	ResolveSeconds float64 `json:"resolveSeconds"`
	// Bundle sizes in bytes: serialized, and gzipped as in the Secret.
	BundleBytes           int `json:"bundleBytes"`
	BundleCompressedBytes int `json:"bundleCompressedBytes"`

	// Memory of this process: the Go heap in use after a GC at the end
	// (live), the largest heap sampled every 250ms (peak, garbage
	// included), and the resident set (peak and at the end).
	HeapLiveBytes uint64 `json:"heapLiveBytes"`
	HeapPeakBytes uint64 `json:"heapPeakBytes"`
	RSSBytes      uint64 `json:"rssBytes"`
	RSSPeakBytes  uint64 `json:"rssPeakBytes"`
	// The peaks during the initial sync, and during the edits only (the
	// kernel's peak RSS is reset in between).
	HeapPeakSyncBytes    uint64 `json:"heapPeakSyncBytes"`
	RSSPeakSyncBytes     uint64 `json:"rssPeakSyncBytes"`
	HeapPeakChangesBytes uint64 `json:"heapPeakChangesBytes"`
	RSSPeakChangesBytes  uint64 `json:"rssPeakChangesBytes"`
}

func parseScale(s string) (policies, engines int, err error) {
	p, e, ok := strings.Cut(s, "x")
	if !ok {
		return 0, 0, fmt.Errorf("%s=%q: want <policies>x<engines>", scaleEnv, s)
	}
	if policies, err = strconv.Atoi(p); err != nil || policies < 1 {
		return 0, 0, fmt.Errorf("%s=%q: bad policy count", scaleEnv, s)
	}
	if engines, err = strconv.Atoi(e); err != nil || engines < 1 {
		return 0, 0, fmt.Errorf("%s=%q: bad engine count", scaleEnv, s)
	}
	return policies, engines, nil
}

// TestScale is the scale test; one size per process, as controller-runtime
// allows one manager per process.
func TestScale(t *testing.T) {
	spec := os.Getenv(scaleEnv)
	if spec == "" {
		t.Skip(scaleEnv + " is not set (make scale-test sets it)")
	}
	testenv.Skip(t, env)
	nPolicies, nEngines, err := parseScale(spec)
	if err != nil {
		t.Fatal(err)
	}
	nChanges := 10
	if s := os.Getenv(changesEnv); s != "" {
		if nChanges, err = strconv.Atoi(s); err != nil || nChanges < 1 {
			t.Fatalf("%s=%q: want a positive number", changesEnv, s)
		}
	}
	// The chart's 512 MiB limit: cmd/operator sets GOMEMLIMIT to 90% of
	// it. GOMEMLIMIT overrides it (off: no limit).
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(512 << 20 / 10 * 9)
	}
	res := Result{Policies: nPolicies, Engines: nEngines, Changes: nChanges, MemoryLimitBytes: debug.SetMemoryLimit(-1)}

	// The operator's client is not rate limited, as ctrl.GetConfig sets it
	// up in cmd/operator.
	cfg := rest.CopyConfig(env.Config)
	cfg.QPS = -1
	c, err := client.New(cfg, client.Options{Scheme: mustScheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupEngineAccess(ctx, t, c)

	distAddr := startOperator(ctx, t, cfg)
	engineCfg := engineConfig(ctx, t, c, distAddr, nEngines)

	sampler := startSampler()
	defer sampler.stop()

	engines := startEngines(t, engineCfg)
	defer engines.stop()
	start := time.Now()
	if !engines.wait(func(s engineState) bool { return s.version > 0 }, 2*time.Minute) {
		t.Fatalf("not every engine connected after 2m: %d/%d", engines.count(func(s engineState) bool { return s.version > 0 }), nEngines)
	}
	res.ConnectSeconds = time.Since(start).Seconds()
	t.Logf("%d engines connected in %.1fs", nEngines, res.ConnectSeconds)

	// A GitOps sync of every policy and route.
	start = time.Now()
	createObjects(ctx, t, c, nPolicies)
	created := time.Now()
	res.CreateSeconds = created.Sub(start).Seconds()
	t.Logf("%d policies and their routes created in %.1fs", nPolicies, res.CreateSeconds)
	full := func(s engineState) bool {
		return s.policies == nPolicies && s.routes == nPolicies*routesPerPolicy
	}
	synced := engines.wait(full, 10*time.Minute)
	if synced {
		res.SyncSeconds = time.Since(created).Seconds()
		t.Logf("every engine has the %d policies %.1fs later", nPolicies, res.SyncSeconds)
	} else {
		t.Errorf("not every engine has the bundle with every policy and route after 10m: %d/%d", engines.count(full), nEngines)
	}

	if synced {
		res.HeapPeakSyncBytes = sampler.reset()
		_, res.RSSPeakSyncBytes = rss()
		resetPeakRSS()
		measureChanges(ctx, t, c, engines, nPolicies, nChanges, &res)
		res.HeapPeakChangesBytes = sampler.reset()
		_, res.RSSPeakChangesBytes = rss()
	}

	// Memory first: what follows lists every object in this process.
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.HeapLiveBytes = ms.HeapAlloc
	res.HeapPeakBytes = max(sampler.stop(), res.HeapPeakSyncBytes, res.HeapPeakChangesBytes)
	res.RSSBytes, res.RSSPeakBytes = rss()
	res.RSSPeakBytes = max(res.RSSPeakBytes, res.RSSPeakSyncBytes, res.RSSPeakChangesBytes)

	measureBundle(ctx, t, c, &res)
	report(t, res)

	if !synced {
		return
	}
	if res.AllEnginesP95 >= targetLatency.Seconds() {
		t.Errorf("change → every engine p95 %.1fs, target < %s", res.AllEnginesP95, targetLatency)
	}
	if res.RSSPeakBytes >= targetMemory {
		t.Errorf("operator peak RSS %s, target < %s", mib(res.RSSPeakBytes), mib(targetMemory))
	}
	if res.Routes != nPolicies*routesPerPolicy {
		t.Errorf("%d routes resolved, want %d", res.Routes, nPolicies*routesPerPolicy)
	}
}

// measureChanges edits one policy at a time, and times how long until
// every engine has a bundle with the edit, after the operator settled.
func measureChanges(ctx context.Context, t *testing.T, c client.Client, engines *engineHost, nPolicies, nChanges int, res *Result) {
	settle(t)
	before := reconcileStats(t)
	var all, each []time.Duration
	for k := range nChanges {
		i := k * nPolicies / nChanges
		pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace(i, nPolicies), Name: name(i)}}
		version := engines.maxVersion()
		changed := time.Now()
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
				return err
			}
			if pol.Spec.Mode == wafv1alpha1.PolicyBlock {
				pol.Spec.Mode = wafv1alpha1.PolicyDetect
			} else {
				pol.Spec.Mode = wafv1alpha1.PolicyBlock
			}
			return c.Update(ctx, pol)
		})
		if err != nil {
			t.Fatal(err)
		}
		newer := func(s engineState) bool { return s.version > version }
		if !engines.wait(newer, 2*time.Minute) {
			t.Fatalf("change %d: not every engine has a new bundle after 2m: %d/%d", k, engines.count(newer), len(engines.states))
		}
		var slowest time.Duration
		for _, at := range engines.reached(version) {
			d := at.Sub(changed)
			each = append(each, d)
			slowest = max(slowest, d)
		}
		all = append(all, slowest)
		t.Logf("change %d: every engine has it after %.1fs", k+1, slowest.Seconds())
		settle(t)
	}
	after := reconcileStats(t)
	if n := after.count - before.count; n > 0 {
		res.ReconcileSeconds = (after.sum - before.sum) / float64(n)
	}
	res.AllEnginesP50 = percentile(all, 0.50).Seconds()
	res.AllEnginesP95 = percentile(all, 0.95).Seconds()
	res.AllEnginesMax = slices.Max(all).Seconds()
	res.PerEngineP95 = percentile(each, 0.95).Seconds()
}

// percentile is the nearest-rank percentile.
func percentile(d []time.Duration, p float64) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	i := int(float64(len(s))*p+0.999999) - 1
	return s[max(0, min(i, len(s)-1))]
}

// measureBundle resolves the objects as the bundle reconciler does, timing
// it, and sizes the bundle.
func measureBundle(ctx context.Context, t *testing.T, c client.Client, res *Result) {
	in := resolver.Input{CheckRules: coraza.CheckUserRules}
	var (
		policies        wafv1alpha1.WAFPolicyList
		ingresses       networkingv1.IngressList
		ruleSets        wafv1alpha1.WAFRuleSetList
		clusterRuleSets wafv1alpha1.ClusterWAFRuleSetList
	)
	for _, l := range []client.ObjectList{&policies, &ingresses, &ruleSets, &clusterRuleSets} {
		if err := c.List(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	routes, _, err := wiring.IngressRoutes(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	in.Policies, in.Ingresses, in.IngressRoutes, in.RuleSets, in.ClusterRuleSets =
		policies.Items, ingresses.Items, routes, ruleSets.Items, clusterRuleSets.Items
	var (
		out   resolver.Result
		times []time.Duration
	)
	for range 3 {
		start := time.Now()
		out = resolver.Resolve(in)
		times = append(times, time.Since(start))
	}
	res.ResolveSeconds = percentile(times, 0.5).Seconds()
	for _, p := range out.Policies {
		res.Routes += len(p.GetRoutes())
	}

	signer, err := bundle.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := bundle.Next(nil, &bundlev1.Bundle{ClusterId: "scale", Policies: out.Policies, RuleSets: out.RuleSets}, 0, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	res.BundleBytes = len(signed.GetBundle())
	// As bundle.Encode stores it, without its size limit.
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var n countingWriter
	zw := gzip.NewWriter(&n)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	res.BundleCompressedBytes = int(n)
	if n > bundle.MaxCompressedBytes {
		t.Errorf("bundle %s compressed, over the %s a Secret takes (bundle.MaxCompressedBytes)", kib(int(n)), kib(bundle.MaxCompressedBytes))
	}
}

type countingWriter int

func (w *countingWriter) Write(p []byte) (int, error) {
	*w += countingWriter(len(p))
	return len(p), nil
}

func report(t *testing.T, r Result) {
	t.Logf("| Policies | Routes | Engines | Peak RSS | Peak heap | Live heap | Reconcile | Resolve | Bundle (gzip) | Initial sync | Change → all engines p50 / p95 / max | Change → one engine p95 |")
	t.Logf("| %d | %d | %d | %s | %s | %s | %.2f s | %.3f s | %s (%s raw) | %.1f s | %.1f / %.1f / %.1f s | %.1f s |",
		r.Policies, r.Routes, r.Engines, mib(r.RSSPeakBytes), mib(r.HeapPeakBytes), mib(r.HeapLiveBytes),
		r.ReconcileSeconds, r.ResolveSeconds, kib(r.BundleCompressedBytes), kib(r.BundleBytes), r.SyncSeconds,
		r.AllEnginesP50, r.AllEnginesP95, r.AllEnginesMax, r.PerEngineP95)
	t.Logf("peak RSS / heap: initial sync %s / %s, edits %s / %s; connect %.1f s, create %.1f s",
		mib(r.RSSPeakSyncBytes), mib(r.HeapPeakSyncBytes), mib(r.RSSPeakChangesBytes), mib(r.HeapPeakChangesBytes),
		r.ConnectSeconds, r.CreateSeconds)
	path := os.Getenv(outEnv)
	if path == "" {
		return
	}
	line, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

func mib(b uint64) string { return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20)) }
func kib(b int) string    { return fmt.Sprintf("%.0f KiB", float64(b)/(1<<10)) }

func mustScheme(t *testing.T) *k8sruntime.Scheme {
	t.Helper()
	s, err := manager.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setupEngineAccess creates the operator's namespace and the engines'
// ServiceAccount, with what injection grants it (0004 §4.3): reading the
// bundle Secret.
func setupEngineAccess(ctx context.Context, t *testing.T, c client.Client) {
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: engineNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: engineNamespace, Name: engineSA}},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: "inkwall-bundle-reader"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{bundle.BundleSecret}, Verbs: []string{"get"}}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: "inkwall-bundle-reader"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "inkwall-bundle-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: engineNamespace, Name: engineSA}},
		},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// startOperator runs the operator with its production defaults (debounce,
// report intervals), until the test ends, and returns its distribution
// server's address once it is ready and leads.
func startOperator(ctx context.Context, t *testing.T, cfg *rest.Config) string {
	t.Helper()
	probe, dist := freeAddr(t), freeAddr(t)
	_, port, _ := net.SplitHostPort(dist)
	distPort, _ := strconv.Atoi(port)
	mgr, err := manager.New(cfg, manager.Options{
		MetricsAddr:     "0",
		ProbeAddr:       probe,
		LeaderElect:     true,
		Namespace:       operatorNamespace,
		Webhooks:        true,
		WebhookPort:     env.WebhookPort,
		WebhookCertDir:  t.TempDir(),
		WebhookCerts:    manager.CertsRotate,
		WebhookSecret:   certSecret,
		WebhookDNSNames: []string{"localhost"},

		DistributionPort: distPort,
		Inject:           true,
		EngineImage:      "inkwall-engine:test",
		EnginePullPolicy: corev1.PullNever,
		Replica:          "operator-0",
	})
	if err != nil {
		t.Fatal(err)
	}
	mctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(mctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("manager stopped with %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("manager did not stop after 30s")
		}
	})

	deadline := time.Now().Add(time.Minute)
	for {
		resp, err := http.Get("http://" + probe + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("operator not ready after 1m (last error: %v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-mgr.Elected():
	case <-time.After(30 * time.Second):
		t.Fatal("operator not elected leader after 30s")
	}
	return "localhost:" + port
}

// enginesConfig is what the engines' process reads on stdin.
type enginesConfig struct {
	Addr      string        `json:"addr"`
	CA        []byte        `json:"ca"`
	PublicKey []byte        `json:"publicKey"`
	Tokens    []string      `json:"tokens"`
	Heartbeat time.Duration `json:"heartbeat"`
}

// engineConfig issues a token per engine, as each engine pod has its own,
// and reads the CA and the bundle signing key once the operator made them.
func engineConfig(ctx context.Context, t *testing.T, c client.Client, addr string, n int) enginesConfig {
	t.Helper()
	ec := enginesConfig{Addr: addr, Tokens: make([]string, n), Heartbeat: agent.DefaultHeartbeat}
	deadline := time.Now().Add(time.Minute)
	for {
		var certs, keys corev1.Secret
		errC := c.Get(ctx, types.NamespacedName{Namespace: operatorNamespace, Name: certSecret}, &certs)
		errK := c.Get(ctx, types.NamespacedName{Namespace: operatorNamespace, Name: bundle.SigningKeySecret}, &keys)
		if errC == nil && errK == nil && len(certs.Data["ca.crt"]) > 0 && len(keys.Data[bundle.PublicKeyKey]) > 0 {
			ec.CA, ec.PublicKey = certs.Data["ca.crt"], keys.Data[bundle.PublicKeyKey]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no CA or signing key after 1m: %v", errors.Join(errC, errK))
		}
		time.Sleep(100 * time.Millisecond)
	}
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	err = parallel(n, 16, func(i int) error {
		tr, err := cs.CoreV1().ServiceAccounts(engineNamespace).CreateToken(ctx, engineSA, &authnv1.TokenRequest{
			Spec: authnv1.TokenRequestSpec{Audiences: []string{distribution.Audience}, ExpirationSeconds: ptr.To(int64(3600))},
		}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		ec.Tokens[i] = tr.Status.Token
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ec
}

// The objects: policy i targets route object i (an Ingress for even i, an
// IngressRoute for odd i), in one of nPolicies/100 namespaces, with
// routesPerPolicy routes: two hosts × five path prefixes.
const (
	hostsPerRoute = 2
	pathsPerHost  = routesPerPolicy / hostsPerRoute
)

func name(i int) string { return fmt.Sprintf("app-%d", i) }

func namespace(i, n int) string { return fmt.Sprintf("team-%d", i%max(1, n/100)) }

func host(i, h int) string { return fmt.Sprintf("app-%d-%d.example.com", i, h) }

func routePath(p int) string { return fmt.Sprintf("/svc-%d", p) }

func routeObject(i, n int) (client.Object, wafv1alpha1.TargetRef) {
	ns := namespace(i, n)
	if i%2 == 0 {
		prefix := networkingv1.PathTypePrefix
		ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name(i)}}
		for h := range hostsPerRoute {
			rule := networkingv1.IngressRule{Host: host(i, h), IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{}}}
			for p := range pathsPerHost {
				rule.HTTP.Paths = append(rule.HTTP.Paths, networkingv1.HTTPIngressPath{Path: routePath(p), PathType: &prefix,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name(i), Port: networkingv1.ServiceBackendPort{Number: 80}}}})
			}
			ing.Spec.Rules = append(ing.Spec.Rules, rule)
		}
		return ing, wafv1alpha1.TargetRef{Kind: "Ingress", Name: name(i)}
	}
	var routes []any
	for h := range hostsPerRoute {
		for p := range pathsPerHost {
			routes = append(routes, map[string]any{
				"kind": "Rule", "match": fmt.Sprintf("Host(`%s`) && PathPrefix(`%s`)", host(i, h), routePath(p)),
				"services": []any{map[string]any{"name": name(i), "port": int64(80)}},
			})
		}
	}
	ir := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"entryPoints": []any{"web"}, "routes": routes}}}
	ir.SetGroupVersionKind(integrations.TraefikIngressRouteGVK)
	ir.SetNamespace(ns)
	ir.SetName(name(i))
	return ir, wafv1alpha1.TargetRef{Group: "traefik.io", Kind: "IngressRoute", Name: name(i)}
}

// createObjects creates the namespaces, then each route and its policy,
// concurrently, as a GitOps tool applying a large change would.
func createObjects(ctx context.Context, t *testing.T, c client.Client, n int) {
	t.Helper()
	for i := range max(1, n/100) {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace(i, n)}}); err != nil {
			t.Fatal(err)
		}
	}
	err := parallel(n, 32, func(i int) error {
		route, target := routeObject(i, n)
		if err := c.Create(ctx, route); err != nil {
			return fmt.Errorf("create route %d: %w", i, err)
		}
		pol := &wafv1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: route.GetNamespace(), Name: name(i)},
			Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{target}},
		}
		if err := c.Create(ctx, pol); err != nil {
			return fmt.Errorf("create policy %d: %w", i, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// parallel calls f(0) … f(n-1), at most limit at a time, and returns the
// first error; after one, the calls not started are skipped.
func parallel(n, limit int, f func(int) error) error {
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		first  error
		tokens = make(chan struct{}, limit)
	)
	for i := range n {
		mu.Lock()
		failed := first != nil
		mu.Unlock()
		if failed {
			break
		}
		tokens <- struct{}{}
		wg.Go(func() {
			defer func() { <-tokens }()
			if err := f(i); err != nil {
				mu.Lock()
				first = cmp.Or(first, err)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return first
}

// reconcileTotals are the bundle reconciler's metrics (controller-runtime's).
type reconcileTotals struct {
	count       uint64
	sum         float64
	total       float64
	active      float64
	queueLength float64
}

func reconcileStats(t *testing.T) reconcileTotals {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var r reconcileTotals
	for _, f := range families {
		for _, m := range f.GetMetric() {
			is := func(label, value string) bool {
				for _, l := range m.GetLabel() {
					if l.GetName() == label && l.GetValue() == value {
						return true
					}
				}
				return false
			}
			switch {
			case f.GetName() == "controller_runtime_reconcile_time_seconds" && is("controller", "bundle"):
				r.count, r.sum = m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
			case f.GetName() == "controller_runtime_reconcile_total" && is("controller", "bundle"):
				r.total += m.GetCounter().GetValue()
			case f.GetName() == "controller_runtime_active_workers" && is("controller", "bundle"):
				r.active = m.GetGauge().GetValue()
			case f.GetName() == "workqueue_depth" && is("name", "bundle"):
				r.queueLength = m.GetGauge().GetValue()
			}
		}
	}
	return r
}

// settle waits until the bundle reconciler is idle: nothing running or
// queued, and no reconcile for twice the debounce (a change is queued after
// the debounce).
func settle(t *testing.T) {
	t.Helper()
	const quiet = 1500 * time.Millisecond
	deadline := time.Now().Add(5 * time.Minute)
	last, since := reconcileStats(t), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		s := reconcileStats(t)
		if s.total != last.total || s.active > 0 || s.queueLength > 0 {
			last, since = s, time.Now()
			continue
		}
		if time.Since(since) >= quiet {
			return
		}
	}
	t.Fatal("the bundle reconciler did not settle in 5m")
}

// sampler records the largest heap in use.
type sampler struct {
	peak atomic.Uint64
	done chan struct{}
	once sync.Once
}

func startSampler() *sampler {
	s := &sampler{done: make(chan struct{})}
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > s.peak.Load() {
				s.peak.Store(ms.HeapAlloc)
			}
			select {
			case <-t.C:
			case <-s.done:
				return
			}
		}
	}()
	return s
}

// reset returns the peak so far, and starts over.
func (s *sampler) reset() uint64 { return s.peak.Swap(0) }

// resetPeakRSS resets the kernel's peak RSS of this process (VmHWM).
func resetPeakRSS() { _ = os.WriteFile("/proc/self/clear_refs", []byte("5"), 0) }

func (s *sampler) stop() uint64 {
	s.once.Do(func() { close(s.done) })
	return s.peak.Load()
}

// rss returns this process's resident set size and its peak (Linux).
func rss() (current, peak uint64) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "VmRSS":
			current = kb << 10
		case "VmHWM":
			peak = kb << 10
		}
	}
	return current, peak
}

// engineState is what an engine last applied.
type engineState struct {
	version  uint64
	policies int
	routes   int
}

// engineHost is the fake engines' process, and when each reached each
// bundle version.
type engineHost struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser

	mu      sync.Mutex
	changed *sync.Cond
	states  []engineState
	// applied[i] lists engine i's versions and when they arrived.
	applied [][]versionAt
	exited  error
	done    chan struct{}
}

type versionAt struct {
	version uint64
	at      time.Time
}

// startEngines starts the fake engines in a child process: this test
// binary, which reads the configuration on stdin and prints a line per
// bundle applied, "applied <engine> <version> <policies> <routes>".
func startEngines(t *testing.T, ec enginesConfig) *engineHost {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- this test binary
	cmd.Env = append(os.Environ(), engineHostEnv+"=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &engineHost{cmd: cmd, stdin: stdin, states: make([]engineState, len(ec.Tokens)), applied: make([][]versionAt, len(ec.Tokens)), done: make(chan struct{})}
	h.changed = sync.NewCond(&h.mu)
	go func() {
		defer close(h.done)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			at := time.Now()
			var (
				i    int
				s    engineState
				verb string
			)
			if _, err := fmt.Sscanf(sc.Text(), "%s %d %d %d %d", &verb, &i, &s.version, &s.policies, &s.routes); err != nil || verb != "applied" || i < 0 || i >= len(h.states) {
				continue
			}
			h.mu.Lock()
			h.states[i] = s
			h.applied[i] = append(h.applied[i], versionAt{s.version, at})
			h.changed.Broadcast()
			h.mu.Unlock()
		}
		err := cmd.Wait()
		h.mu.Lock()
		h.exited = errors.Join(errors.New("the engines' process exited"), err)
		h.changed.Broadcast()
		h.mu.Unlock()
	}()
	if err := json.NewEncoder(stdin).Encode(ec); err != nil {
		t.Fatal(err)
	}
	return h
}

// stop ends the engines' process: it exits when its stdin closes.
func (h *engineHost) stop() {
	_ = h.stdin.Close()
	select {
	case <-h.done:
	case <-time.After(30 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
}

func (h *engineHost) count(ok func(engineState) bool) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.states {
		if ok(s) {
			n++
		}
	}
	return n
}

// wait waits until every engine's state is ok; false after timeout or if
// the engines' process exited.
func (h *engineHost) wait(ok func(engineState) bool, timeout time.Duration) bool {
	timer := time.AfterFunc(timeout, func() {
		h.mu.Lock()
		h.changed.Broadcast()
		h.mu.Unlock()
	})
	defer timer.Stop()
	deadline := time.Now().Add(timeout)
	h.mu.Lock()
	defer h.mu.Unlock()
	for {
		if !slices.ContainsFunc(h.states, func(s engineState) bool { return !ok(s) }) {
			return true
		}
		if h.exited != nil || !time.Now().Before(deadline) {
			return false
		}
		h.changed.Wait()
	}
}

func (h *engineHost) maxVersion() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var v uint64
	for _, s := range h.states {
		v = max(v, s.version)
	}
	return v
}

// reached returns when each engine first applied a version after v.
func (h *engineHost) reached(v uint64) []time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []time.Time
	for _, vs := range h.applied {
		for _, a := range vs {
			if a.version > v {
				out = append(out, a.at)
				break
			}
		}
	}
	return out
}

// hostEngines is the fake engines' process: it runs the engines stdin
// configures, reconnecting as engines do, until stdin closes.
func hostEngines() int {
	in := bufio.NewReader(os.Stdin)
	var ec enginesConfig
	if err := json.NewDecoder(in).Decode(&ec); err != nil {
		fmt.Fprintln(os.Stderr, "engines: read the configuration:", err)
		return 1
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ec.CA) {
		fmt.Fprintln(os.Stderr, "engines: no CA")
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	var (
		outMu sync.Mutex
		out   = bufio.NewWriter(os.Stdout)
		wg    sync.WaitGroup
	)
	for i, token := range ec.Tokens {
		e := &fakeengine.Engine{
			ID:              fmt.Sprintf("fake-%d", i),
			Addr:            ec.Addr,
			TLS:             &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			Token:           token,
			PublicKeys:      []ed25519.PublicKey{ec.PublicKey},
			Heartbeat:       ec.Heartbeat,
			KeepVersionOnly: true,
			OnApply: func(b *bundlev1.Bundle) {
				routes := 0
				for _, p := range b.GetPolicies() {
					routes += len(p.GetRoutes())
				}
				outMu.Lock()
				defer outMu.Unlock()
				_, _ = fmt.Fprintf(out, "applied %d %d %d %d\n", i, b.GetVersion(), len(b.GetPolicies()), routes)
				_ = out.Flush()
			},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if err := e.Run(ctx); err != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "engines: %s: %v\n", e.ID, err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
		}()
	}
	_, _ = io.Copy(io.Discard, in)
	cancel()
	wg.Wait()
	return 0
}
