// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var env *testenv.Env

// distAddr is the operator's distribution server in the test.
var distAddr string

func TestMain(m *testing.M) {
	// Operator logs go to stderr, shown for failing tests with -v.
	ctrl.SetLogger(logr.FromSlogHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{Webhooks: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
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

// warnings records the warnings the API server returns.
type warnings struct {
	mu   sync.Mutex
	list []string
}

func (w *warnings) HandleWarningHeader(_ int, _, text string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.list = append(w.list, text)
}

func (w *warnings) take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	l := w.list
	w.list = nil
	return l
}

// startOperator runs the manager the way it runs in a cluster, in
// namespace default, until the test ends or stop is called. It waits until
// the replica is ready and leads, and returns a client that records API
// warnings.
func startOperator(t *testing.T) (_ context.Context, _ client.Client, _ *warnings, stop func()) {
	t.Helper()
	testenv.Skip(t, env)
	probe := freeAddr(t)
	distAddr = freeAddr(t)
	_, port, _ := net.SplitHostPort(distAddr)
	distPort, _ := strconv.Atoi(port)
	mgr, err := New(env.Config, Options{
		MetricsAddr:     "0",
		ProbeAddr:       probe,
		LeaderElect:     true,
		Namespace:       "default",
		Debounce:        50 * time.Millisecond,
		Webhooks:        true,
		WebhookPort:     env.WebhookPort,
		WebhookCertDir:  t.TempDir(),
		WebhookCerts:    CertsRotate,
		WebhookSecret:   "inkwall-operator-webhook-tls",
		WebhookDNSNames: []string{"localhost"},

		DistributionPort:     distPort,
		Inject:               true,
		EngineImage:          "inkwall-engine:test",
		EnginePullPolicy:     corev1.PullNever,
		Replica:              "operator-0",
		EngineReportInterval: 200 * time.Millisecond,
		CRDInterval:          200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
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
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(30 * time.Second)
	for {
		var last string
		resp, err := http.Get("http://" + probe + "/readyz?verbose")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			last = string(body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ready after 30s (last error: %v)\n%s", err, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-mgr.Elected():
	case <-time.After(20 * time.Second):
		t.Fatal("not elected leader after 20s")
	}

	cfg := rest.CopyConfig(env.Config)
	warn := &warnings{}
	cfg.WarningHandler = warn
	c, err := client.New(cfg, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, c, warn, stop
}

// TestOperator runs one operator for all the checks: controller-runtime
// allows one manager per process.
func TestOperator(t *testing.T) {
	ctx, c, warn, stop := startOperator(t)
	t.Run("webhook", func(t *testing.T) { testWebhook(ctx, t, c, warn) })
	t.Run("bundles", func(t *testing.T) { testBundles(ctx, t, c) })
	t.Run("distribution", func(t *testing.T) { testDistribution(ctx, t, c) })
	t.Run("engine", func(t *testing.T) { testEngine(ctx, t, c) })
	t.Run("injection", func(t *testing.T) { testInjection(ctx, t, c) })
	t.Run("wiring", func(t *testing.T) { testWiring(ctx, t, c) })
	t.Run("ingressroutes", func(t *testing.T) { testIngressRoutes(ctx, t, c) })
	t.Run("failure policy", func(t *testing.T) { testFailurePolicy(ctx, t, c) })
	t.Run("source guard", func(t *testing.T) { testSourceGuard(ctx, t, c) })
	// Last: it stops the operator.
	t.Run("uninstall", func(t *testing.T) { testUninstall(ctx, t, c, stop) })
}

// testWebhook checks the webhook as deployed: the operator creates the
// webhook certificate, injects its CA into the webhook configuration and
// serves the webhook, which the API server calls for every WAF object.
func testWebhook(ctx context.Context, t *testing.T, c client.Client, warn *warnings) {
	var secret corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "inkwall-operator-webhook-tls"}, &secret); err != nil {
		t.Fatalf("certificate Secret: %v", err)
	}

	ruleSet := func(name string, src wafv1alpha1.RuleSetSource) *wafv1alpha1.WAFRuleSet {
		return &wafv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: src},
		}
	}
	// The webhook is reached, over TLS with the injected CA, and rejects
	// rules that don't compile, naming the line.
	bad := ruleSet("bad", wafv1alpha1.RuleSetSource{SecLang: "SecRule ARGS \"@rx a\" \"id:100001,phase:1,deny\"\nSecRule ARGS \"@nosuchop a\" \"id:100002,phase:1,deny\""})
	err := c.Create(ctx, bad)
	if err == nil || !strings.Contains(err.Error(), "spec.source.seclang") || !strings.Contains(err.Error(), "line 2: ") {
		t.Fatalf("bad rules: got %v, want a spec.source.seclang error at line 2", err)
	}
	good := ruleSet("good", wafv1alpha1.RuleSetSource{SecLang: `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100003,phase:1,deny,status:403"`})
	if err := c.Create(ctx, good); err != nil {
		t.Fatalf("good rules: %v", err)
	}
	// Labels can change without the rules being compiled again.
	update(ctx, t, c, good, func(rs *wafv1alpha1.WAFRuleSet) { rs.Labels = map[string]string{"team": "shop"} })

	fromConfigMap := ruleSet("from-configmap", wafv1alpha1.RuleSetSource{ConfigMapRef: &wafv1alpha1.ConfigMapKeyRef{Name: "rules", Key: "rules.conf"}})
	warn.take()
	if err := c.Create(ctx, fromConfigMap); err != nil {
		t.Fatalf("ConfigMap rules: %v", err)
	}
	if w := warn.take(); len(w) != 1 || !strings.Contains(w[0], "ConfigMap") {
		t.Errorf("ConfigMap rules: warnings %q, want one about the ConfigMap", w)
	}

	cluster := &wafv1alpha1.ClusterWAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "engine-off"},
		Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{SecLang: "SecRuleEngine Off"}},
	}
	if err := c.Create(ctx, cluster); err == nil || !strings.Contains(err.Error(), `directive "secruleengine" is not allowed`) {
		t.Fatalf("SecRuleEngine in a ClusterWAFRuleSet: got %v", err)
	}

	policy := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "shop"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "shop"}},
			Skip:       &wafv1alpha1.SkipSpec{Paths: []wafv1alpha1.PathPattern{"/healthz", "/static/../admin/*"}},
		},
	}
	if err := c.Create(ctx, policy); err == nil || !strings.Contains(err.Error(), "spec.skip.paths[1]") || !strings.Contains(err.Error(), "not clean") {
		t.Fatalf("unclean skip path: got %v", err)
	}
	policy.Spec.Skip.Paths[1] = "/static/*"
	if err := c.Create(ctx, policy); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
}

// update reads obj, changes it with mutate and saves it, again on a
// conflict: the operator writes the status, a new resourceVersion, at any
// time.
func update[T client.Object](ctx context.Context, t *testing.T, c client.Client, obj T, mutate func(T)) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		mutate(obj)
		return c.Update(ctx, obj)
	})
	if err != nil {
		t.Fatalf("update %s: %v", client.ObjectKeyFromObject(obj), err)
	}
}
