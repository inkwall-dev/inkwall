// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package podcache

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

// Custom selectors sharing no label key with Envoy Gateway's: the cache
// holds the proxy pods, and no other pod.
func TestCache(t *testing.T) {
	testenv.Skip(t, env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := client.New(env.Config, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	selectors, _, err := integrations.FromConfig([]wafv1alpha1.IntegrationSpec{
		{Controller: integrations.Traefik.Name, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	envoy := map[string]string{"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway"}
	pod := func(name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: name, Labels: labels},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "c"}}},
		}
	}
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "proxy"}},
		pod("edge-1", map[string]string{"app": "edge"}),
		pod("envoy-1", envoy),
		// Both integrations' labels: listed once.
		pod("both-1", map[string]string{"app": "edge", "app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway"}),
		pod("shop-1", map[string]string{"app": "shop"}),
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "other"}},
	} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	pc, err := New(selectors.PodSelectors())(env.Config, cache.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	// The pods the informers report, as a controller's watch sees them.
	var mu sync.Mutex
	seen := map[string]int{}
	informer, err := pc.GetInformer(ctx, &corev1.Pod{})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{AddFunc: func(o any) {
		mu.Lock()
		defer mu.Unlock()
		seen[o.(*corev1.Pod).Name]++
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = pc.Start(ctx) }()
	if !pc.WaitForCacheSync(ctx) {
		t.Fatal("cache not synced")
	}
	select {
	case <-reg.HasSyncedChecker().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("handler not synced")
	}
	mu.Lock()
	if want := map[string]int{"edge-1": 1, "envoy-1": 1, "both-1": 2}; fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("informer added %v, want %v", seen, want)
	}
	mu.Unlock()

	names := func(opts ...client.ListOption) []string {
		t.Helper()
		var list corev1.PodList
		if err := pc.List(ctx, &list, opts...); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range list.Items {
			out = append(out, p.Name)
		}
		slices.Sort(out)
		return out
	}
	if got := names(); !slices.Equal(got, []string{"both-1", "edge-1", "envoy-1"}) {
		t.Errorf("pods cached %v", got)
	}
	if got := names(client.InNamespace("proxy"), client.MatchingLabels(envoy)); !slices.Equal(got, []string{"both-1", "envoy-1"}) {
		t.Errorf("Envoy Gateway's pods %v", got)
	}
	var p corev1.Pod
	if err := pc.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: "envoy-1"}, &p); err != nil {
		t.Errorf("get a proxy pod: %v", err)
	}
	if err := pc.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: "shop-1"}, &p); !apierrors.IsNotFound(err) {
		t.Errorf("get another pod: %v, want not found", err)
	}
	// Other kinds are cached as usual.
	var cm corev1.ConfigMap
	if err := pc.Get(ctx, types.NamespacedName{Namespace: "proxy", Name: "other"}, &cm); err != nil {
		t.Errorf("get a ConfigMap: %v", err)
	}
	if err := informer.RemoveEventHandler(reg); err != nil {
		t.Error(err)
	}
}
