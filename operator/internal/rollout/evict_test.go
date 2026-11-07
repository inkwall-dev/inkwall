// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package rollout

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// The Eviction API, as the API server answers it, evicts the pod. (envtest
// runs no disruption controller, so a budget's refusal is tested on kind:
// hack/kind/e2e.sh.)
func TestEvict(t *testing.T) {
	testenv.Skip(t, env)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c, err := client.New(env.Config, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	r := &Rollout{Client: c}
	pod := func(name string, labels map[string]string) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Labels: labels},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3"}}}}
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	free := pod("free", map[string]string{"app": "free"})
	if err := r.evict(ctx, free); err != nil {
		t.Fatalf("evict a pod without a budget: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(free), &corev1.Pod{}); err == nil {
		var got corev1.Pod
		_ = c.Get(ctx, client.ObjectKeyFromObject(free), &got)
		if got.DeletionTimestamp == nil {
			t.Error("the evicted pod is neither gone nor terminating")
		}
	}
}
