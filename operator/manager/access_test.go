// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/inkwall-dev/inkwall/operator/integrations"
)

func TestAccessWatch(t *testing.T) {
	accessCheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { accessCheckInterval = time.Minute })

	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	// The API server allows Envoy Gateway's resources once granted, and
	// Traefik's unless revoked, but for the next `denials` reviews of them.
	var granted, revoked atomic.Bool
	var denials atomic.Int32
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			review := obj.(*authorizationv1.SelfSubjectAccessReview)
			switch review.Spec.ResourceAttributes.Group {
			case "gateway.envoyproxy.io":
				review.Status.Allowed = granted.Load()
			case "traefik.io":
				review.Status.Allowed = !revoked.Load() && denials.Add(-1) < 0
			default:
				review.Status.Allowed = true
			}
			return nil
		},
	}).Build()
	run := func(denied map[string]string) chan error {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		go func() {
			defer cancel()
			done <- (&accessWatch{client: c, denied: denied, maxDelay: time.Millisecond}).Start(ctx)
		}()
		return done
	}
	egDenied := map[string]string{integrations.EnvoyGateway.Name: "denied"}

	if err := <-run(egDenied); err != nil {
		t.Fatalf("still denied: %v", err)
	}
	// Granted: the operator stops, to restart with it.
	granted.Store(true)
	if err := <-run(egDenied); !errors.Is(err, errAccessChanged) {
		t.Fatalf("granted: %v", err)
	}
	// Every integration enabled, and Traefik's role revoked: it stops too,
	// to restart with Traefik disabled.
	if err := <-run(nil); err != nil {
		t.Fatalf("all granted: %v", err)
	}
	revoked.Store(true)
	if err := <-run(nil); !errors.Is(err, errAccessChanged) {
		t.Fatalf("revoked: %v", err)
	}
	// Revoked for one check only (a binding replaced): it keeps running.
	revoked.Store(false)
	denials.Store(1)
	if err := <-run(nil); err != nil {
		t.Fatalf("revoked for a moment: %v", err)
	}
}
