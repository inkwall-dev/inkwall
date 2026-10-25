// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

func TestSelectorWatch(t *testing.T) {
	selectorCheckInterval, selectorMaxDelay = 10*time.Millisecond, time.Millisecond
	t.Cleanup(func() { selectorCheckInterval, selectorMaxDelay = 10*time.Second, 30*time.Second })

	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cfg).Build()
	run := func() chan error {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		go func() {
			defer cancel()
			done <- (&selectorWatch{client: c, current: integrations.Defaults()}).Start(ctx)
		}()
		return done
	}

	// The same selectors (an InkwallConfig without integrations): it keeps
	// running.
	if err := <-run(); err != nil {
		t.Fatalf("unchanged selectors: %v", err)
	}

	// Another selector: the operator stops, to restart with it.
	cfg.Spec.Integrations = []wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}}}}
	if err := c.Update(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := <-run(); !errors.Is(err, errSelectorsChanged) {
		t.Fatalf("changed selectors: %v", err)
	}
}
