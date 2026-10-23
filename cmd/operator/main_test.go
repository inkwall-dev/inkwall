// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var env *testenv.Env

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

func TestFlags(t *testing.T) {
	var stderr strings.Builder
	if code := run([]string{"--help"}, &stderr); code != 0 {
		t.Errorf("--help: exit %d", code)
	}
	if !strings.Contains(stderr.String(), "-webhook-certs") {
		t.Errorf("--help does not list the flags:\n%s", stderr.String())
	}
	for _, args := range [][]string{{"--no-such-flag"}, {"extra"}, {"--webhook-certs", "cert-manager"}} {
		if code := run(args, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	t.Setenv("POD_NAMESPACE", "security")
	if o, err := parseFlags(nil, io.Discard); err != nil || o.namespace != "security" {
		t.Errorf("namespace from POD_NAMESPACE: got %q, %v", o.namespace, err)
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

// TestOperator runs the manager the way it runs in a cluster: it creates
// the webhook certificate, injects its CA into the webhook configuration,
// serves the webhook, reports ready and wins the leader election. The API
// server then calls the webhook for every WAF object.
func TestOperator(t *testing.T) {
	testenv.Skip(t, env)
	probe := freeAddr(t)
	mgr, err := newManager(env.Config, options{
		metricsAddr:     "0",
		probeAddr:       probe,
		leaderElect:     true,
		namespace:       "default",
		webhooks:        true,
		webhookPort:     env.WebhookPort,
		webhookCertDir:  t.TempDir(),
		webhookCerts:    certsRotate,
		webhookSecret:   "inkwall-operator-webhook-tls",
		webhookDNSNames: []string{"localhost"},
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
	err = c.Create(ctx, bad)
	if err == nil || !strings.Contains(err.Error(), "spec.source.seclang") || !strings.Contains(err.Error(), "line 2: ") {
		t.Fatalf("bad rules: got %v, want a spec.source.seclang error at line 2", err)
	}
	good := ruleSet("good", wafv1alpha1.RuleSetSource{SecLang: `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100003,phase:1,deny,status:403"`})
	if err := c.Create(ctx, good); err != nil {
		t.Fatalf("good rules: %v", err)
	}
	// Labels can change without the rules being compiled again.
	good.Labels = map[string]string{"team": "shop"}
	if err := c.Update(ctx, good); err != nil {
		t.Fatalf("label update: %v", err)
	}

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
