// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/geo"
	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
)

const geoNS = "inkwall-system"

func geoDB(t *testing.T, epoch uint64, code string) []byte {
	t.Helper()
	db, err := mmdbtest.DB{BuildEpoch: epoch, Networks: []mmdbtest.Network{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Record: &mmdbtest.Record{Country: code}}}}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func geoClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&wafv1alpha1.InkwallConfig{}).Build()
}

func readyCondition(t *testing.T, c client.Client) (*metav1.Condition, *wafv1alpha1.GeoStatus) {
	t.Helper()
	var cfg wafv1alpha1.InkwallConfig
	if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, &cfg); err != nil {
		t.Fatal(err)
	}
	return meta.FindStatusCondition(cfg.Status.Conditions, wafv1alpha1.ConditionGeoDatabaseReady), cfg.Status.Geo
}

// TestGeoReconcilerSecret: a Secret source is compiled, stored before
// anything names it, and reported; a bad one keeps the stored table.
func TestGeoReconcilerSecret(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000+86400, 0)
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wafv1alpha1.InkwallConfigSpec{Geo: &wafv1alpha1.GeoConfig{Database: wafv1alpha1.GeoDatabase{SecretRef: &wafv1alpha1.SecretKeyReference{Name: "geo-db", Key: "db"}}}}}
	src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: geoNS, Name: "geo-db"}, Data: map[string][]byte{"db": geoDB(t, 1_700_000_000, "XA")}}
	c := geoClient(t, cfg, src)
	r := &GeoReconciler{Client: c, APIReader: c, Namespace: geoNS, Now: func() time.Time { return now }}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil || res.RequeueAfter != geoPoll {
		t.Fatalf("%v %+v", err, res)
	}
	cond, st := readyCondition(t, c)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != geo.ReasonLoaded || st == nil || st.Ranges == 0 {
		t.Fatalf("condition %+v, status %+v", cond, st)
	}
	stored, err := geo.Load(ctx, c, geoNS)
	if err != nil || stored == nil || hex.EncodeToString(stored.Hash[:]) != st.SHA256 {
		t.Fatalf("stored %v: %v", stored, err)
	}

	// An invalid source: the stored table stays, the condition says why.
	src.Data["db"] = []byte("not a database")
	if err := c.Update(ctx, src); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	cond, st = readyCondition(t, c)
	if cond.Status != metav1.ConditionFalse || cond.Reason != geo.ReasonInvalid || st == nil || st.SHA256 != hex.EncodeToString(stored.Hash[:]) {
		t.Errorf("invalid source: %+v, %+v", cond, st)
	}

	// Stale after 30 days.
	r.Now = func() time.Time { return now.Add(40 * 24 * time.Hour) }
	src.Data["db"] = geoDB(t, 1_700_000_000, "XA")
	_ = c.Update(ctx, src)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if cond, _ = readyCondition(t, c); cond.Reason != ReasonGeoStale || cond.Status != metav1.ConditionTrue {
		t.Errorf("stale: %+v", cond)
	}

	// spec.geo removed: the condition and status go.
	var cur wafv1alpha1.InkwallConfig
	_ = c.Get(ctx, client.ObjectKey{Name: "default"}, &cur)
	cur.Spec.Geo = nil
	_ = c.Update(ctx, &cur)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if cond, st = readyCondition(t, c); cond != nil || st != nil {
		t.Errorf("without spec.geo: %+v, %+v", cond, st)
	}
}

// TestGeoReconcilerFile: a file is compiled once, then only stat'ed while
// it doesn't change; a missing one keeps the stored table as Loaded.
func TestGeoReconcilerFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "country.mmdb")
	// The InkwallConfig names it as in the operator's pod.
	specPath := geo.FileRoot + "/country.mmdb"
	if err := os.WriteFile(path, geoDB(t, 1_700_000_000, "XA"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wafv1alpha1.InkwallConfigSpec{Geo: &wafv1alpha1.GeoConfig{Database: wafv1alpha1.GeoDatabase{File: specPath}}}}
	c := geoClient(t, cfg)
	r := &GeoReconciler{Client: c, APIReader: c, Namespace: geoNS, Root: root, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if cond, _ := readyCondition(t, c); cond == nil || cond.Reason != geo.ReasonLoaded {
		t.Fatalf("%+v", cond)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if cond, st := readyCondition(t, c); cond.Reason != geo.ReasonLoaded || st == nil {
		t.Errorf("missing file with a stored table: %+v", cond)
	}
}

// TestBundleGeoTable: the bundle names the stored table only when a policy
// uses geo, and only once the table is stored.
func TestBundleGeoTable(t *testing.T) {
	ctx := context.Background()
	c := geoClient(t)
	r := &BundleReconciler{Client: c, APIReader: c, Namespace: geoNS}
	withGeo := []*bundlev1.Policy{{Id: "a/b"}, {Id: "c/d", Geo: &bundlev1.Geo{Deny: []string{"RU"}}}}
	if ref, err := r.geoTable(ctx, withGeo); err != nil || ref != nil {
		t.Fatalf("no table stored: %v %v", ref, err)
	}
	tb, err := geo.Compile(ctx, geoDB(t, 1, "XA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := geo.Store(ctx, c, c, geoNS, tb); err != nil {
		t.Fatal(err)
	}
	ref, err := r.geoTable(ctx, withGeo)
	if err != nil || ref == nil || !bytes.Equal(ref.GetSha256(), tb.Hash[:]) || ref.GetSize() != uint64(tb.Size) {
		t.Fatalf("stored table: %v %v", ref, err)
	}
	if ref, _ := r.geoTable(ctx, withGeo[:1]); ref != nil {
		t.Error("named a table without a geo policy")
	}
}
