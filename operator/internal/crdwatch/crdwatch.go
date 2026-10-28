// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package crdwatch watches a kind whose CRD may be missing, such as
// Traefik's IngressRoute: a controller can't start with a watch on a kind
// the API server doesn't serve, so the watch is added once it does.
package crdwatch

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultInterval is how often a missing CRD is looked for.
const DefaultInterval = 30 * time.Second

// Installed reports whether the API server serves gvk. A missing kind is
// false with no error; an error means it couldn't be told.
func Installed(mapper meta.RESTMapper, gvk schema.GroupVersionKind) (bool, error) {
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	switch {
	case err == nil:
		return true, nil
	case meta.IsNoMatchError(err):
		return false, nil
	}
	return false, err
}

// Kind adds watches on GVK to controllers once its CRD is installed. It is
// a leader-only manager runnable, like the controllers; Add every watch
// before the manager starts.
type Kind struct {
	GVK    schema.GroupVersionKind
	Mapper meta.RESTMapper
	Cache  cache.Cache
	// Interval between looks for the CRD; 0: DefaultInterval.
	Interval time.Duration

	watches []watch
}

type watch struct {
	controller controller.Controller
	handler    handler.EventHandler
	predicates []predicate.Predicate
}

// Add watches GVK, as unstructured objects, for c once it is served.
func (k *Kind) Add(c controller.Controller, h handler.EventHandler, predicates ...predicate.Predicate) {
	k.watches = append(k.watches, watch{controller: c, handler: h, predicates: predicates})
}

// Start waits for the CRD, then starts the watches.
func (k *Kind) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithValues("kind", k.GVK.Kind)
	interval := k.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	for {
		ok, err := Installed(k.Mapper, k.GVK)
		if err != nil {
			logger.Error(err, "can't tell whether the CRD is installed")
		}
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
	for _, w := range k.watches {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(k.GVK)
		if err := w.controller.Watch(source.Kind[client.Object](k.Cache, obj, w.handler, w.predicates...)); err != nil {
			return err
		}
	}
	logger.Info("CRD installed, watching it")
	return nil
}

// NeedLeaderElection is true: the controllers it adds watches to run on the
// leader.
func (*Kind) NeedLeaderElection() bool { return true }
