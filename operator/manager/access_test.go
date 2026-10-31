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
	// The API server allows Envoy Gateway's resources once granted.
	var granted atomic.Bool
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			obj.(*authorizationv1.SelfSubjectAccessReview).Status.Allowed = granted.Load()
			return nil
		},
	}).Build()
	run := func() chan error {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		go func() {
			defer cancel()
			done <- (&accessWatch{client: c, denied: map[string]string{integrations.EnvoyGateway.Name: "denied"}, maxDelay: time.Millisecond}).Start(ctx)
		}()
		return done
	}

	if err := <-run(); err != nil {
		t.Fatalf("still denied: %v", err)
	}
	// Granted: the operator stops, to restart with it.
	granted.Store(true)
	if err := <-run(); !errors.Is(err, errAccessGranted) {
		t.Fatalf("granted: %v", err)
	}
}
