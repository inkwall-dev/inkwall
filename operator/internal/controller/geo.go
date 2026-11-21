// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
// stored table in the bundle once a policy uses spec.geo: the table is
// always written before the bundle that names it.
type GeoReconciler struct {
	Client client.Client
	// APIReader reads uncached: the stored table and the source Secret.
	APIReader client.Reader
	// Namespace is the operator's, where the geo Secrets are.
	Namespace string
	// Root is where database files are (geo.FileRoot).
	Root string
	Now  func() time.Time

	// stored is the table in the Secrets, loaded once, then as stored.
	stored *geo.Table
	loaded bool
	// file is the source file's size and time when last compiled.
	fileSize int64
	fileTime time.Time
	filePath string
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
	// A Secret in the operator's namespace may be the source: not the
	// table's own.
	secrets := builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == r.Namespace && o.GetName() != bundlesecret.Geo.Name && !bundlesecret.Geo.IsChunk(o.GetName())
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
	if err := r.Client.Get(ctx, client.ObjectKey{Name: "default"}, &cfg); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if cfg.Spec.Geo == nil {
		return reconcile.Result{}, r.writeStatus(ctx, &cfg, nil)
	}
	if !r.loaded {
		stored, err := geo.Load(ctx, r.APIReader, r.Namespace)
		if err != nil {
			// Unreadable: compiled again from the source, and replaced.
			logger.Error(err, "the stored country table can't be read; compiling the database again")
		}
		r.stored, r.loaded = stored, true
	}
	db := cfg.Spec.Geo.Database
	var src *geo.Source
	var srcErr error
	switch {
	case db.File != "":
		size, mtime, err := geo.StatFile(r.Root, db.File)
		if err == nil && r.stored != nil && db.File == r.filePath && size == r.fileSize && mtime.Equal(r.fileTime) {
			// Unchanged since compiled: no need to hash it.
			return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, &cfg, &geo.Outcome{Table: r.stored, Reason: geo.ReasonLoaded, Message: describeTable(r.stored)})
		}
		src, srcErr = geo.ReadFile(r.Root, db.File)
	case db.SecretRef != nil:
		src, srcErr = geo.ReadSecret(ctx, r.APIReader, r.Namespace, db.SecretRef.Name, db.SecretRef.Key)
	}
	o := geo.Refresh(ctx, src, srcErr, r.stored)
	_ = src.Close()
	if o.Transient() {
		logger.Info("country database not read; retrying", "error", o.Err.Error())
		return reconcile.Result{RequeueAfter: geoRetry}, nil
	}
	if o.New {
		if err := geo.Store(ctx, r.Client, r.APIReader, r.Namespace, o.Table); err != nil {
			return reconcile.Result{}, fmt.Errorf("store the country table: %w", err)
		}
		r.stored = o.Table
		logger.Info("country table published", "database", o.Table.DatabaseType, "built", o.Table.Built(), "ranges", o.Table.Ranges,
			"bytes", len(o.Table.Compressed), "hash", hex.EncodeToString(o.Table.Hash[:]))
	}
	if src != nil && db.File != "" && o.Err == nil {
		r.filePath, r.fileSize, r.fileTime = db.File, src.Size, src.ModTime
	}
	if o.Err != nil {
		logger.Error(o.Err, "country database not compiled", "reason", o.Reason)
	}
	return reconcile.Result{RequeueAfter: geoPoll}, r.writeStatus(ctx, &cfg, &o)
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

func describeTable(t *geo.Table) string {
	return fmt.Sprintf("%s built %s, %d ranges, %d KiB compressed", t.DatabaseType, t.Built().Format(time.DateOnly), t.Ranges, (len(t.Compressed)+1023)>>10)
}
