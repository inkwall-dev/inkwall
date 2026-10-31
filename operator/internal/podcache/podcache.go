// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package podcache caches the proxy pods for the operator (0004 §4.3): one
// informer per integration's pod selector, read as one cache. A label
// selector can't express a union, so a single informer would watch every
// pod whenever the selectors share no label key.
package podcache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// New returns a cache constructor for the manager (ctrl.Options.NewCache).
// Its cache holds, of the pods, only those matching one of selectors, with
// an informer per distinct selector; other kinds are cached as the options
// say. Options.ByObject must not configure pods.
func New(selectors []labels.Selector) cache.NewCacheFunc {
	return func(cfg *rest.Config, o cache.Options) (cache.Cache, error) {
		if len(selectors) == 0 {
			return nil, errors.New("podcache: no pod selector")
		}
		others, err := cache.New(cfg, o)
		if err != nil {
			return nil, err
		}
		c := &podCache{Cache: others, scheme: o.Scheme}
		seen := map[string]bool{}
		for _, sel := range selectors {
			if seen[sel.String()] {
				continue
			}
			seen[sel.String()] = true
			po := o
			po.ByObject = map[client.Object]cache.ByObject{&corev1.Pod{}: {Label: sel}}
			pods, err := cache.New(cfg, po)
			if err != nil {
				return nil, fmt.Errorf("pods %s: %w", sel, err)
			}
			c.pods = append(c.pods, pods)
		}
		return c, nil
	}
}

// podCache sends pods to one cache per selector, everything else to the
// embedded cache.
type podCache struct {
	cache.Cache
	scheme *runtime.Scheme
	pods   []cache.Cache
}

var (
	podGVK     = corev1.SchemeGroupVersion.WithKind("Pod")
	podListGVK = corev1.SchemeGroupVersion.WithKind("PodList")
)

func (c *podCache) isPod(obj runtime.Object) bool {
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	return err == nil && (gvk == podGVK || gvk == podListGVK)
}

// Get returns the pod from the first cache that has it.
func (c *podCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if !c.isPod(obj) {
		return c.Cache.Get(ctx, key, obj, opts...)
	}
	var err error
	for _, p := range c.pods {
		if err = p.Get(ctx, key, obj, opts...); !apierrors.IsNotFound(err) {
			return err
		}
	}
	return err
}

// List lists the pods of every cache, once each: a pod may match several
// selectors.
func (c *podCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if !c.isPod(list) {
		return c.Cache.List(ctx, list, opts...)
	}
	if len(c.pods) == 1 {
		return c.pods[0].List(ctx, list, opts...)
	}
	var items []runtime.Object
	seen := map[types.NamespacedName]bool{}
	for _, p := range c.pods {
		part := list.DeepCopyObject().(client.ObjectList)
		if err := meta.SetList(part, nil); err != nil {
			return err
		}
		if err := p.List(ctx, part, opts...); err != nil {
			return err
		}
		err := meta.EachListItem(part, func(o runtime.Object) error {
			m, err := meta.Accessor(o)
			if err != nil {
				return err
			}
			key := types.NamespacedName{Namespace: m.GetNamespace(), Name: m.GetName()}
			if !seen[key] {
				seen[key] = true
				items = append(items, o)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return meta.SetList(list, items)
}

func (c *podCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	if !c.isPod(obj) {
		return c.Cache.GetInformer(ctx, obj, opts...)
	}
	return c.informers(func(p cache.Cache) (cache.Informer, error) { return p.GetInformer(ctx, obj, opts...) })
}

func (c *podCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption) (cache.Informer, error) {
	if gvk != podGVK {
		return c.Cache.GetInformerForKind(ctx, gvk, opts...)
	}
	return c.informers(func(p cache.Cache) (cache.Informer, error) { return p.GetInformerForKind(ctx, gvk, opts...) })
}

func (c *podCache) informers(get func(cache.Cache) (cache.Informer, error)) (cache.Informer, error) {
	u := make(union, 0, len(c.pods))
	for _, p := range c.pods {
		i, err := get(p)
		if err != nil {
			return nil, err
		}
		u = append(u, i)
	}
	return u, nil
}

func (c *podCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	if !c.isPod(obj) {
		return c.Cache.RemoveInformer(ctx, obj)
	}
	for _, p := range c.pods {
		if err := p.RemoveInformer(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

func (c *podCache) IndexField(ctx context.Context, obj client.Object, field string, extract client.IndexerFunc) error {
	if !c.isPod(obj) {
		return c.Cache.IndexField(ctx, obj, field, extract)
	}
	for _, p := range c.pods {
		if err := p.IndexField(ctx, obj, field, extract); err != nil {
			return err
		}
	}
	return nil
}

// Start runs every cache until ctx is done.
func (c *podCache) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, p := range append([]cache.Cache{c.Cache}, c.pods...) {
		g.Go(func() error { return p.Start(ctx) })
	}
	return g.Wait()
}

func (c *podCache) WaitForCacheSync(ctx context.Context) bool {
	for _, p := range append([]cache.Cache{c.Cache}, c.pods...) {
		if !p.WaitForCacheSync(ctx) {
			return false
		}
	}
	return true
}

// union is the pods' informers as one: a handler is added to each, and
// sees a pod matching several selectors once per informer.
type union []cache.Informer

func (u union) add(add func(cache.Informer) (toolscache.ResourceEventHandlerRegistration, error)) (toolscache.ResourceEventHandlerRegistration, error) {
	regs := make(registrations, 0, len(u))
	for _, i := range u {
		r, err := add(i)
		if err != nil {
			return nil, err
		}
		regs = append(regs, r)
	}
	return regs, nil
}

func (u union) AddEventHandler(h toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	return u.add(func(i cache.Informer) (toolscache.ResourceEventHandlerRegistration, error) {
		return i.AddEventHandler(h)
	})
}

func (u union) AddEventHandlerWithResyncPeriod(h toolscache.ResourceEventHandler, resync time.Duration) (toolscache.ResourceEventHandlerRegistration, error) {
	return u.add(func(i cache.Informer) (toolscache.ResourceEventHandlerRegistration, error) {
		return i.AddEventHandlerWithResyncPeriod(h, resync)
	})
}

func (u union) AddEventHandlerWithOptions(h toolscache.ResourceEventHandler, o toolscache.HandlerOptions) (toolscache.ResourceEventHandlerRegistration, error) {
	return u.add(func(i cache.Informer) (toolscache.ResourceEventHandlerRegistration, error) {
		return i.AddEventHandlerWithOptions(h, o)
	})
}

func (u union) RemoveEventHandler(h toolscache.ResourceEventHandlerRegistration) error {
	regs, ok := h.(registrations)
	if !ok || len(regs) != len(u) {
		return errors.New("podcache: not a registration of this informer")
	}
	for i, inf := range u {
		if err := inf.RemoveEventHandler(regs[i]); err != nil {
			return err
		}
	}
	return nil
}

func (u union) AddIndexers(indexers toolscache.Indexers) error {
	for _, i := range u {
		if err := i.AddIndexers(indexers); err != nil {
			return err
		}
	}
	return nil
}

func (u union) HasSynced() bool {
	for _, i := range u {
		if !i.HasSynced() {
			return false
		}
	}
	return true
}

func (u union) HasSyncedChecker() toolscache.DoneChecker {
	checkers := make([]toolscache.DoneChecker, len(u))
	for n, i := range u {
		checkers[n] = i.HasSyncedChecker()
	}
	return allDone(checkers)
}

func (u union) IsStopped() bool {
	for _, i := range u {
		if !i.IsStopped() {
			return false
		}
	}
	return true
}

// registrations are a handler's registrations, one per informer.
type registrations []toolscache.ResourceEventHandlerRegistration

func (r registrations) HasSynced() bool {
	for _, reg := range r {
		if !reg.HasSynced() {
			return false
		}
	}
	return true
}

func (r registrations) HasSyncedChecker() toolscache.DoneChecker {
	checkers := make([]toolscache.DoneChecker, len(r))
	for n, reg := range r {
		checkers[n] = reg.HasSyncedChecker()
	}
	return allDone(checkers)
}

// allDone is done once each checker is.
func allDone(checkers []toolscache.DoneChecker) toolscache.DoneChecker {
	d := done{checkers: checkers, ch: make(chan struct{})}
	go func() {
		for _, c := range checkers {
			<-c.Done()
		}
		close(d.ch)
	}()
	return d
}

type done struct {
	checkers []toolscache.DoneChecker
	ch       chan struct{}
}

func (d done) Name() string {
	names := make([]string, len(d.checkers))
	for i, c := range d.checkers {
		names[i] = c.Name()
	}
	return strings.Join(names, ", ")
}

func (d done) Done() <-chan struct{} { return d.ch }
