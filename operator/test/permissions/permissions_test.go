// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package permissions runs the operator with the RBAC the chart grants
// (operator/config/rbac), less one integration's ClusterRole: it starts,
// the other integrations wire their routes, and the policies on routes of
// the disabled one say why they aren't wired (0004 §7). Its own process:
// controller-runtime allows one manager per process.
package permissions

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/config/rbac"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/access"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/manager"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// namespace is the operator's: role.yaml's Role is in it.
const namespace = "inkwall-system"

var env *testenv.Env

func TestMain(m *testing.M) {
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

// grant binds user to role.yaml's roles, but the ClusterRoles of the
// integrations left out.
func grant(ctx context.Context, t *testing.T, c client.Client, user string, leftOut ...string) {
	t.Helper()
	subjects := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: user}}
	for _, doc := range strings.Split(string(rbac.Roles), "\n---\n") {
		var role rbacv1.Role // a ClusterRole has the same fields
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatal(err)
		}
		skip := false
		for _, name := range leftOut {
			skip = skip || role.Name == access.RolePrefix+name
		}
		if skip {
			continue
		}
		name := user + "-" + role.Name
		ref := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: meta.Kind, Name: name}
		var objs []client.Object
		switch meta.Kind {
		case "ClusterRole":
			objs = []client.Object{
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: role.Rules},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, RoleRef: ref, Subjects: subjects},
			}
		case "Role":
			objs = []client.Object{
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: role.Namespace, Name: name}, Rules: role.Rules},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: role.Namespace, Name: name}, RoleRef: ref, Subjects: subjects},
			}
		default:
			continue
		}
		for _, o := range objs {
			if err := c.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
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

// eventually retries cond until it returns "" or a minute passes.
func eventually(t *testing.T, what string, cond func() string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		msg := cond()
		if msg == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s", what, msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Every integration has a ClusterRole of its own, with every rule its
// wiring's markers declare: each kubebuilder:rbac marker in
// operator/internal/wiring, but the wiring controller's own, names its
// integration's role.
func TestRoles(t *testing.T) {
	roles, err := access.Roles()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range integrations.All {
		if len(roles[in.Name]) == 0 {
			t.Errorf("no ClusterRole %s%s in role.yaml: give the %s wiring's kubebuilder:rbac markers roleName=%[1]s%[2]s", access.RolePrefix, in.Name, in.Name)
		}
	}
	if len(roles) != len(integrations.All) {
		t.Errorf("roles for %d integrations, want %d", len(roles), len(integrations.All))
	}

	_, file, _, _ := runtime.Caller(0)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "internal", "wiring", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("wiring sources: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "controller.go" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			marker, ok := strings.CutPrefix(line, "// +kubebuilder:rbac:")
			if !ok {
				continue
			}
			args := map[string][]string{}
			for _, kv := range strings.Split(marker, ",") {
				k, v, _ := strings.Cut(kv, "=")
				args[k] = strings.Split(strings.Trim(v, `"`), ";")
			}
			name, ok := strings.CutPrefix(strings.Join(args["roleName"], ""), access.RolePrefix)
			if !ok || roles[name] == nil {
				t.Errorf("%s: %s: no roleName of an integration's ClusterRole", filepath.Base(f), line)
				continue
			}
			for _, g := range args["groups"] {
				for _, r := range args["resources"] {
					for _, v := range args["verbs"] {
						if !grants(roles[name], g, r, v) {
							t.Errorf("%s: role %s doesn't grant %s %s.%s", filepath.Base(f), name, v, r, g)
						}
					}
				}
			}
		}
	}
}

// grants reports whether rules allow verb on group's resource.
func grants(rules []rbacv1.PolicyRule, group, resource, verb string) bool {
	for _, r := range rules {
		if slices.Contains(r.APIGroups, group) && slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) {
			return true
		}
	}
	return false
}

// The operator runs without Envoy Gateway's ClusterRole, with Envoy
// Gateway's CRDs installed: Traefik's Ingresses are wired, a policy on an
// HTTPRoute of Envoy Gateway is IntegrationDisabled, and discovery says
// Envoy Gateway is Unsupported, and why.
func TestWithoutEnvoyGateway(t *testing.T) {
	testenv.Skip(t, env)
	ctx := context.Background()
	s, err := manager.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(env.Config, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	for _, install := range []func(*testenv.Env) error{testenv.InstallGatewayAPI, testenv.InstallEnvoyGateway} {
		if err := install(env); err != nil {
			t.Fatal(err)
		}
	}
	for _, ns := range []string{namespace, "proxy", "shop", "edge"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			t.Fatal(err)
		}
	}
	const user = "inkwall-operator"
	grant(ctx, t, c, user, integrations.EnvoyGateway.Name)
	cfg, err := env.User(user)
	if err != nil {
		t.Fatal(err)
	}
	ucfg := rest.CopyConfig(cfg)
	ucfg.QPS = -1 // as the operator checks
	uc, err := client.New(ucfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	denied, err := access.Denied(ctx, uc)
	t.Logf("permissions checked in %v", time.Since(start))
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 1 || !strings.Contains(denied[integrations.EnvoyGateway.Name], "create backends.gateway.envoyproxy.io") {
		t.Fatalf("denied %v, want envoy-gateway's", denied)
	}

	// The operator, as that user.
	probe, dist := freeAddr(t), freeAddr(t)
	_, port, _ := net.SplitHostPort(dist)
	distPort, _ := strconv.Atoi(port)
	mgr, err := manager.New(cfg, manager.Options{
		MetricsAddr: "0", ProbeAddr: probe, Namespace: namespace, Debounce: 50 * time.Millisecond,
		Webhooks: true, WebhookPort: env.WebhookPort, WebhookCertDir: t.TempDir(), WebhookCerts: manager.CertsRotate,
		WebhookSecret: "inkwall-operator-webhook-tls", WebhookDNSNames: []string{"localhost"},
		DistributionPort: distPort, Inject: true, EngineImage: "inkwall-engine:test", EnginePullPolicy: corev1.PullNever,
		Replica: "operator-0", CRDInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	mctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(mctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager stopped with %v", err)
		}
	})
	eventually(t, "ready", func() string {
		resp, err := http.Get("http://" + probe + "/readyz?verbose")
		if err != nil {
			return err.Error()
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return string(body)
		}
		return ""
	})

	// Traefik: an Ingress, a pod, a policy.
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "eg"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(integrations.EnvoyGateway.GatewayController)}}
	listeners := []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80}}
	for _, o := range []client.Object{
		&wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "traefik"}, Spec: networkingv1.IngressClassSpec{Controller: integrations.Traefik.Controller}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("traefik"),
			DefaultBackend:   &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}},
		}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "traefik", Labels: map[string]string{"app.kubernetes.io/name": "traefik"}},
			Spec:       corev1.PodSpec{ServiceAccountName: "traefik", Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3.7.13"}}},
		},
		&wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
		}},
		// Envoy Gateway: a Gateway of its class, a route, a policy.
		gatewayClass,
		&gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "eg"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg", Listeners: listeners}},
		&gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app"}, Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "eg", Namespace: ptr.To(gatewayv1.Namespace("edge"))}}},
		}},
		&wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app"}, Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app"}},
		}},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	programmed := func(name string, st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var p wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, types.NamespacedName{Namespace: "shop", Name: name}, &p); err != nil {
				return err.Error()
			}
			cnd := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionProgrammed)
			if cnd == nil {
				return "no Programmed"
			}
			if cnd.Status != st || cnd.Reason != reason || !strings.Contains(cnd.Message, msg) {
				return string(cnd.Status) + " " + cnd.Reason + ": " + cnd.Message
			}
			return ""
		}
	}
	eventually(t, "the Traefik Ingress is wired", programmed("web", metav1.ConditionTrue, wiring.ReasonProgrammed, "1 Ingress(es) wired to the engine in Traefik"))
	eventually(t, "the Envoy Gateway route isn't", programmed("app", metav1.ConditionFalse, wiring.ReasonIntegrationDisabled,
		"the envoy-gateway integration is disabled: the operator may not"))
	eventually(t, "discovery", func() string {
		var ic wafv1alpha1.InkwallConfig
		if err := c.Get(ctx, types.NamespacedName{Name: "default"}, &ic); err != nil {
			return err.Error()
		}
		for _, p := range ic.Status.Proxies {
			if p.Integration == integrations.EnvoyGateway.Name {
				if p.Support != wafv1alpha1.SupportUnsupported || !strings.Contains(p.Message, "integration is disabled") {
					return fmt.Sprintf("%+v", p)
				}
				return ""
			}
		}
		return fmt.Sprintf("no envoy-gateway proxy: %+v", ic.Status.Proxies)
	})
}
