// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package scale

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// The wiring scale test (#373, SCALE=wiring): policies on Istio
// VirtualServices served by the ingress gateway pods of one Istio Gateway,
// wired by the operator's wiring controller. It measures the API calls a
// wiring reconcile makes, the policies' status writes through a rollout of
// gateway pods, the reconcile's duration and the operator's memory.
const (
	// wiringDefault is the number of policies of SCALE=wiring: as many
	// VirtualServices as one gateway namespace's EnvoyFilter holds under
	// etcd's 1.5 MiB limit (about 1,200; #424). 5,000 once that is fixed.
	wiringDefault = 1000
	// wiringPods are the ingress gateway pods; rolloutPods the pods of the
	// rollout, created and deleted one at a time.
	wiringPods, rolloutPods = 3, 5
	// The budgets: uncached pod lists per wiring reconcile (one per Gateway
	// selector), and status writes per policy through the rollout
	// (Programmed and Ready, each down and back up).
	budgetPodLists      = 1.0
	budgetRolloutWrites = 4.0
	gatewayNamespace    = "istio-ingress"
)

// WiringResult is one SCALE=wiring run's measurements, appended to
// INKWALL_SCALE_OUT.
type WiringResult struct {
	Policies int `json:"policies"`
	Pods     int `json:"pods"`
	// WiredSeconds: from the last object created to every policy
	// Programmed.
	WiredSeconds float64 `json:"wiredSeconds"`
	// Per wiring reconcile, over a few reconciles once wired: its mean
	// duration, the API requests it makes, and the uncached pod lists
	// among them.
	ReconcileSeconds     float64 `json:"reconcileSeconds"`
	RequestsPerReconcile float64 `json:"requestsPerReconcile"`
	PodListsPerReconcile float64 `json:"podListsPerReconcile"`
	// RolloutWritesPerPolicy: the policies' status writes while
	// rolloutPods pods without the engine come and go, one at a time,
	// divided by the policies.
	RolloutPods            int     `json:"rolloutPods"`
	RolloutWritesPerPolicy float64 `json:"rolloutWritesPerPolicy"`
	RSSPeakBytes           uint64  `json:"rssPeakBytes"`
	HeapPeakBytes          uint64  `json:"heapPeakBytes"`
}

// parseWiring reads "wiring" or "wiring:<policies>"; ok is false for
// another scale.
func parseWiring(s string) (policies int, ok bool, err error) {
	rest, found := strings.CutPrefix(s, "wiring")
	if !found {
		return 0, false, nil
	}
	if rest == "" {
		return wiringDefault, true, nil
	}
	n, err := strconv.Atoi(strings.TrimPrefix(rest, ":"))
	if !strings.HasPrefix(rest, ":") || err != nil || n < 1 {
		return 0, true, fmt.Errorf("%s=%q: want wiring or wiring:<policies>", scaleEnv, s)
	}
	return n, true, nil
}

// requestCounter counts the operator's API requests.
type requestCounter struct {
	mu sync.Mutex
	// by "METHOD kind": kind is "podlist" (a pod LIST, which the cache
	// only makes when it starts and a watch breaks), "status" (a
	// WAFPolicy status write) or "other".
	counts map[string]int
	rt     http.RoundTripper
}

func (c *requestCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	kind := "other"
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/pods") && r.URL.Query().Get("watch") == "":
		kind = "podlist"
	case (r.Method == http.MethodPut || r.Method == http.MethodPatch) && strings.Contains(p, "/wafpolicies/") && strings.HasSuffix(p, "/status"):
		kind = "status"
	}
	c.mu.Lock()
	c.counts[kind]++
	c.mu.Unlock()
	return c.rt.RoundTrip(r)
}

func (c *requestCounter) take() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.counts
	c.counts = map[string]int{}
	return out
}

func TestScaleWiring(t *testing.T) {
	n, ok, err := parseWiring(os.Getenv(scaleEnv))
	if !ok {
		t.Skip(scaleEnv + " is not wiring[:<policies>] (make scale-test SCALE=wiring)")
	}
	if err != nil {
		t.Fatal(err)
	}
	testenv.Skip(t, env)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(512 << 20 / 10 * 9)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := rest.CopyConfig(env.Config)
	cfg.QPS = -1
	c, err := client.New(cfg, client.Options{Scheme: mustScheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := testenv.InstallIstio(env); err != nil {
		t.Fatal(err)
	}
	setupEngineAccess(ctx, t, c)
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gatewayNamespace}}); err != nil {
		t.Fatal(err)
	}

	counter := &requestCounter{counts: map[string]int{}}
	opCfg := rest.CopyConfig(cfg)
	opCfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { counter.rt = rt; return counter })
	startOperator(ctx, t, opCfg)
	sampler := startSampler()
	defer sampler.stop()
	res := WiringResult{Policies: n, Pods: wiringPods, RolloutPods: rolloutPods}

	// The Gateway and its pods, which the Pod webhook injects.
	gw := istioObject(t, "Gateway", gatewayNamespace, "edge", map[string]any{
		"selector": map[string]any{"istio": "ingressgateway"},
		"servers":  []any{map[string]any{"port": map[string]any{"number": int64(80), "name": "http", "protocol": "HTTP"}, "hosts": []any{"*"}}},
	})
	if err := c.Create(ctx, gw); err != nil {
		t.Fatal(err)
	}
	for i := range wiringPods {
		pod := gatewayPod(fmt.Sprintf("istio-ingressgateway-6b7c-%d", i), "6b7c", false)
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil || !injection.HasEngine(pod) {
			t.Fatalf("gateway pod %s not injected: %v", pod.Name, err)
		}
	}

	// A policy per VirtualService.
	for i := range max(1, n/100) {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace(i, n)}}); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	err = parallel(n, 32, func(i int) error {
		ns := namespace(i, n)
		vs := istioObject(t, "VirtualService", ns, name(i), map[string]any{
			"hosts":    []any{host(i, 0)},
			"gateways": []any{gatewayNamespace + "/edge"},
			"http":     []any{map[string]any{"name": fmt.Sprintf("r-%d", i), "route": []any{map[string]any{"destination": map[string]any{"host": "web"}}}}},
		})
		if err := c.Create(ctx, vs); err != nil {
			return err
		}
		return c.Create(ctx, &wafv1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name(i)},
			Spec:       wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Group: "networking.istio.io", Kind: "VirtualService", Name: name(i)}}},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	t.Logf("%d policies and VirtualServices created in %.1fs", n, created.Sub(start).Seconds())
	programmed := func(want metav1.ConditionStatus) func() (int, error) {
		return func() (int, error) {
			var list wafv1alpha1.WAFPolicyList
			if err := c.List(ctx, &list); err != nil {
				return 0, err
			}
			got := 0
			// Why the others aren't, for the failure: a count and a
			// message per reason.
			why := map[string]string{}
			counts := map[string]int{}
			for _, p := range list.Items {
				cnd := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionProgrammed)
				switch {
				case cnd != nil && cnd.Status == want:
					got++
				case cnd == nil:
					counts["(none)"]++
				default:
					counts[cnd.Reason]++
					why[cnd.Reason] = cnd.Message
				}
			}
			if got != len(list.Items) && len(counts) > 0 {
				var parts []string
				for r, k := range counts {
					parts = append(parts, fmt.Sprintf("%d %s (%.300s)", k, r, why[r]))
				}
				return got, fmt.Errorf("the others: %s", strings.Join(parts, "; "))
			}
			return got, nil
		}
	}
	waitCount(t, "every policy Programmed", programmed(metav1.ConditionTrue), n, 10*time.Minute)
	res.WiredSeconds = time.Since(created).Seconds()
	settleController(t, "wiring")

	// A few reconciles, once wired: a policy edited each time.
	const edits = 5
	before := reconcileStatsOf(t, "wiring")
	counter.take()
	for i := range edits {
		var p wafv1alpha1.WAFPolicy
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace(i, n), Name: name(i)}, &p); err != nil {
			t.Fatal(err)
		}
		p.Spec.Mode = map[bool]wafv1alpha1.PolicyMode{true: wafv1alpha1.PolicyBlock, false: wafv1alpha1.PolicyDetect}[p.Spec.Mode != wafv1alpha1.PolicyBlock]
		if err := c.Update(ctx, &p); err != nil {
			t.Fatal(err)
		}
		settleController(t, "wiring")
	}
	after := reconcileStatsOf(t, "wiring")
	calls := counter.take()
	reconciles := float64(after.count - before.count)
	if reconciles == 0 {
		t.Fatal("no wiring reconcile during the edits")
	}
	res.ReconcileSeconds = (after.sum - before.sum) / reconciles
	total := 0
	for _, v := range calls {
		total += v
	}
	res.RequestsPerReconcile = float64(total) / reconciles
	res.PodListsPerReconcile = float64(calls["podlist"]) / reconciles

	// A rollout: pods without the engine (opted out) of a new ReplicaSet
	// start one at a time, then go one at a time.
	counter.take()
	var rollout []*corev1.Pod
	for i := range rolloutPods {
		pod := gatewayPod(fmt.Sprintf("istio-ingressgateway-9f8e-%d", i), "9f8e", true)
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		rollout = append(rollout, pod)
		if i == 0 {
			waitCount(t, "every policy not Programmed with a pod without the engine", programmed(metav1.ConditionFalse), n, 5*time.Minute)
		}
		settleController(t, "wiring")
	}
	for _, pod := range rollout {
		if err := c.Delete(ctx, pod); err != nil {
			t.Fatal(err)
		}
		settleController(t, "wiring")
	}
	waitCount(t, "every policy Programmed again", programmed(metav1.ConditionTrue), n, 5*time.Minute)
	// The status aggregator follows Ready within its interval.
	time.Sleep(3 * time.Second)
	res.RolloutWritesPerPolicy = float64(counter.take()["status"]) / float64(n)

	runtime.GC()
	res.HeapPeakBytes = sampler.stop()
	_, res.RSSPeakBytes = rss()
	t.Logf("| Policies | Wired after | Reconcile | API requests / reconcile | Pod lists / reconcile | Status writes / policy, rollout of %d pods | Peak RSS | Peak heap |", rolloutPods)
	t.Logf("| %d | %.1f s | %.2f s | %.1f | %.1f | %.1f | %s | %s |", n, res.WiredSeconds, res.ReconcileSeconds,
		res.RequestsPerReconcile, res.PodListsPerReconcile, res.RolloutWritesPerPolicy, mib(res.RSSPeakBytes), mib(res.HeapPeakBytes))
	appendResult(t, res)

	if res.PodListsPerReconcile > budgetPodLists {
		t.Errorf("%.1f uncached pod lists per wiring reconcile, budget %.0f (one per Gateway selector)", res.PodListsPerReconcile, budgetPodLists)
	}
	if res.RolloutWritesPerPolicy > budgetRolloutWrites {
		t.Errorf("%.1f status writes per policy through a rollout of %d pods, budget %.0f", res.RolloutWritesPerPolicy, rolloutPods, budgetRolloutWrites)
	}
	if res.RSSPeakBytes >= targetMemory {
		t.Errorf("operator peak RSS %s, target < %s", mib(res.RSSPeakBytes), mib(targetMemory))
	}
}

func istioObject(t *testing.T, kind, ns, name string, spec map[string]any) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetAPIVersion("networking.istio.io/v1")
	u.SetKind(kind)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

// gatewayPod is an Istio ingress gateway pod of the Deployment
// istio-ingressgateway, through its ReplicaSet of the given hash; optedOut
// keeps the Pod webhook away.
func gatewayPod(name, hash string, optedOut bool) *corev1.Pod {
	l := map[string]string{"istio": "ingressgateway", "app": "istio-ingressgateway", "pod-template-hash": hash}
	if optedOut {
		l[injection.InjectLabel] = "false"
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayNamespace, Name: name, Labels: l,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "istio-ingressgateway-" + hash, UID: types.UID("rs-istio-ingressgateway-" + hash), Controller: ptr.To(true)}}},
		Spec: corev1.PodSpec{ServiceAccountName: "istio-ingressgateway", Containers: []corev1.Container{{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.31.3"}}},
	}
}

// waitCount waits until count returns want.
func waitCount(t *testing.T, what string, count func() (int, error), want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got, err := count()
		if err == nil && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d of %d after %s (%v)", what, got, want, timeout, err)
		}
		time.Sleep(time.Second)
	}
}

func appendResult(t *testing.T, r any) {
	t.Helper()
	path := os.Getenv(outEnv)
	if path == "" {
		return
	}
	line, err := jsonMarshal(r)
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
