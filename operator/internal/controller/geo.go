// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/geo"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// The country database's refresh (design 0011 §3.2, §4.2).
const (
	// geoPoll is how often the source is polled: a file's size and
	// modification time, then its hash.
	geoPoll = time.Minute
	// geoRetry retries a transient failure: the API server's, a cancelled
	// context.
	geoRetry = 10 * time.Second
	// geoStaleAfter turns Loaded into Stale: databases change weekly, and
	// GeoLite2's terms ask for updates within 30 days.
	geoStaleAfter = 30 * 24 * time.Hour
)

// ReasonGeoStale is GeoDatabaseReady's reason for a table whose database is
// older than 30 days.
const ReasonGeoStale = "Stale"

// GeoReconciler compiles the InkwallConfig's country database into a
// country table, stores it in its Secrets, and reports GeoDatabaseReady
// and status.geo. It runs on the leader only. The bundle builder names the
// stored table in the bundle once a policy uses spec.geo and the
// InkwallConfig sets spec.geo: the table is always written before the
// bundle that names it.
type GeoReconciler struct {
	Client client.Client
	// APIReader reads uncached: the stored table, the published bundle and
	// the source Secret.
	APIReader client.Reader
	// Namespace is the operator's, where the geo Secrets are.
	Namespace string
	// Root is where database files are: spec.geo.database.file names a
	// path under geo.FileRoot, which is Root in the operator's pod (the
	// default) and a directory of their own in tests.
	Root string
	Now  func() time.Time

	// stored is the table in the Secrets, loaded once, then as stored.
	stored *geo.Table
	loaded bool
	// pending is a compiled table not stored yet: the published bundle
	// still names a table other than the stored one, whose slot it would
	// overwrite.
	pending *geo.Outcome
	// source is the state of the source last refreshed (a file's path,
	// size and time; a Secret's name, key and resourceVersion), and last
	// its outcome: an unchanged source isn't read again, a broken one
	// included.
	source string
	last   *geo.Outcome
	// dbSecret is the source Secret's name, for the watch's predicate.
	dbSecret atomic.Value
}

// SetupWithManager registers the reconciler with mgr.
func (r *GeoReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Root == "" {
		r.Root = geo.FileRoot
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	enqueue := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{clusterRequest}
	})
	// Only the database's Secret, once a reconcile has read its name; the
	// bundle Secret too, whose bundle naming no table lets the table's
	// Secrets go after spec.geo is removed.
	secrets := builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
		name, _ := r.dbSecret.Load().(string)
		return o.GetNamespace() == r.Namespace && (name != "" && o.GetName() == name || o.GetName() == bundle.BundleSecret)
	}))
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &corev1.Secret{}}
	return ctrl.NewControllerManagedBy(mgr).
		Named("geo").
		Watches(&wafv1alpha1.InkwallConfig{}, enqueue, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Secret{}, enqueue, secrets).
		WatchesRawSource(source.Channel(start, enqueue)).
		Complete(r)
}

// Reconcile refreshes the country table from the configured database.
func (r *GeoReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	var cfg wafv1alpha1.InkwallConfig
	err := r.Client.Get(ctx, client.ObjectKey{Name: "default"}, &cfg)
	if err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	if cfg.Spec.Geo == nil {
		r.dbSecret.Store("")
		r.pending, r.source, r.last = nil, "", nil
		if err == nil {
			if err := r.writeStatus(ctx, &cfg, nil); err != nil {
				return reconcile.Result{}, err
			}
		}
		return r.removeTable(ctx)
	}
	if !r.loaded {
		stored, err := geo.Load(ctx, r.APIReader, r.Namespace)
		if err != nil {
			// Unreadable: compiled again from the source, and replaced.
			logger.Error(err, "the stored country table can't be read; compiling the database again")
		}
		r.stored, r.loaded = stored, true
	}
	if r.pending != nil {
		return r.store(ctx, &cfg, r.pending)
	}
	db := cfg.Spec.Geo.Database
	var src *geo.Source
	var srcErr error
	var state string
	switch {
	case db.File != "":
		r.dbSecret.Store("")
		file := r.Root + strings.TrimPrefix(db.File, geo.FileRoot)
		if size, mtime, err := geo.StatFile(r.Root, file); err == nil {
			state = fmt.Sprintf("file %s %d %d", db.File, size, mtime.UnixNano())
		}
		if state != "" && state == r.source && r.last != nil {
			// Unchanged since read: neither hashed nor compiled again.
			return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, &cfg, r.last)
		}
		src, srcErr = geo.ReadFile(r.Root, file)
	case db.SecretRef != nil:
		r.dbSecret.Store(db.SecretRef.Name)
		var s corev1.Secret
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: db.SecretRef.Name}, &s); err == nil {
			state = fmt.Sprintf("secret %s %s %s", db.SecretRef.Name, db.SecretRef.Key, s.ResourceVersion)
		}
		if state != "" && state == r.source && r.last != nil {
			return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, &cfg, r.last)
		}
		src, srcErr = geo.ReadSecret(ctx, r.APIReader, r.Namespace, db.SecretRef.Name, db.SecretRef.Key)
	}
	o := geo.Refresh(ctx, src, srcErr, r.stored)
	_ = src.Close()
	if o.Transient() {
		logger.Info("country database not read; retrying", "error", o.Err.Error())
		return reconcile.Result{RequeueAfter: geoRetry}, nil
	}
	// Compiled or failed, the outcome stands until the source changes.
	r.source, r.last = state, &o
	if o.Err != nil {
		logger.Error(o.Err, "country database not compiled", "reason", o.Reason)
	}
	if o.New {
		return r.store(ctx, &cfg, &o)
	}
	return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, &cfg, &o)
}

// store writes a new table to its Secrets, unless the published bundle
// names another table than the stored one: the new table would go to that
// table's slot, which engines may still read. It is then kept, and stored
// once the bundle names the stored table (design 0011 §4.4).
func (r *GeoReconciler) store(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, o *geo.Outcome) (reconcile.Result, error) {
	published, err := r.publishedTable(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	if published != nil && (r.stored == nil || !bytes.Equal(published, r.stored.Hash[:])) {
		r.pending = o
		log.FromContext(ctx).Info("a new country table waits: the published bundle doesn't name the stored one yet")
		return reconcile.Result{RequeueAfter: geoRetry}, nil
	}
	if err := geo.Store(ctx, r.Client, r.APIReader, r.Namespace, o.Table); err != nil {
		return reconcile.Result{}, fmt.Errorf("store the country table: %w", err)
	}
	r.stored, r.pending = o.Table, nil
	log.FromContext(ctx).Info("country table published", "database", o.Table.DatabaseType, "built", o.Table.Built(), "ranges", o.Table.Ranges,
		"bytes", len(o.Table.Compressed), "hash", hex.EncodeToString(o.Table.Hash[:]))
	return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, cfg, o)
}

// removeTable deletes the table's Secrets once spec.geo is gone and the
// published bundle names no table: engines no longer need them.
func (r *GeoReconciler) removeTable(ctx context.Context) (reconcile.Result, error) {
	// Most clusters have none: checked in the cache, before the bundle is
	// read.
	var s corev1.Secret
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: bundlesecret.Geo.Name}, &s); apierrors.IsNotFound(err) {
		r.stored, r.loaded = nil, false
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}
	published, err := r.publishedTable(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	if published != nil {
		// The bundle builder publishes a bundle without it next.
		return reconcile.Result{RequeueAfter: geoRetry}, nil
	}
	if err := geo.Delete(ctx, r.Client, r.APIReader, r.Namespace); err != nil {
		return reconcile.Result{}, fmt.Errorf("delete the country table: %w", err)
	}
	r.stored, r.loaded = nil, false
	return reconcile.Result{}, nil
}

// publishedTable returns the table hash the published bundle names, nil
// if none (or no bundle).
func (r *GeoReconciler) publishedTable(ctx context.Context) ([]byte, error) {
	b, _, err := bundle.Load(ctx, r.APIReader, r.Namespace)
	if err != nil {
		return nil, fmt.Errorf("read the published bundle: %w", err)
	}
	return b.GetGeoTable().GetSha256(), nil
}

// writeStatus writes GeoDatabaseReady and status.geo; without spec.geo
// (o nil), it removes them.
func (r *GeoReconciler) writeStatus(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, o *geo.Outcome) error {
	var cond *metav1.Condition
	var st *wafv1alpha1.GeoStatus
	if o != nil {
		c := metav1.Condition{Type: wafv1alpha1.ConditionGeoDatabaseReady, Status: metav1.ConditionTrue,
			Reason: o.Reason, Message: o.Message, ObservedGeneration: cfg.Generation}
		if o.Reason != geo.ReasonLoaded {
			c.Status = metav1.ConditionFalse
		} else if age := r.Now().Sub(o.Table.Built()); age > geoStaleAfter {
			c.Reason = ReasonGeoStale
			c.Message = fmt.Sprintf("%s; built %d days ago: check the database's updater", o.Message, int(age.Hours()/24))
		}
		cond = &c
		if t := o.Table; t != nil {
			st = &wafv1alpha1.GeoStatus{
				SHA256: hex.EncodeToString(t.Hash[:]), DatabaseType: t.DatabaseType, Built: metav1.NewTime(t.Built()),
				Ranges: int64(t.Ranges), CompressedBytes: int64(min(len(t.Compressed), math.MaxInt32)),
			}
		}
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur wafv1alpha1.InkwallConfig
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(cfg), &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		changed := false
		if cond == nil {
			changed = meta.RemoveStatusCondition(&cur.Status.Conditions, wafv1alpha1.ConditionGeoDatabaseReady)
		} else {
			changed = meta.SetStatusCondition(&cur.Status.Conditions, *cond)
		}
		if !apiequality.Semantic.DeepEqual(cur.Status.Geo, st) {
			cur.Status.Geo, changed = st, true
		}
		if !changed {
			return nil
		}
		return r.Client.Status().Update(ctx, &cur)
	})
}
