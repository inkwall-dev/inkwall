// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/geo"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// publish stores a signed bundle naming table hash (none if nil).
func publish(t *testing.T, c client.Client, version uint64, hash []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := &bundlev1.Bundle{Version: version}
	if hash != nil {
		b.GeoTable = &bundlev1.GeoTableRef{Sha256: hash, Size: 1}
	}
	signed, err := bundle.NewSigner(priv).Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Store(context.Background(), c, c, geoNS, b, signed, pub); err != nil {
		t.Fatal(err)
	}
}

func manifestHash(t *testing.T, c client.Client) []byte {
	t.Helper()
	var s corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: geoNS, Name: bundlesecret.GeoSecret}, &s); err != nil {
		return nil
	}
	m, err := bundlesecret.Geo.ParseManifest(s.Data[bundlesecret.ManifestKey])
	if err != nil {
		t.Fatal(err)
	}
	return m.SHA256Bytes()
}

func secretConfig(name string) *wafv1alpha1.InkwallConfig {
	return &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wafv1alpha1.InkwallConfigSpec{Geo: &wafv1alpha1.GeoConfig{Database: wafv1alpha1.GeoDatabase{SecretRef: &wafv1alpha1.SecretKeyReference{Name: name, Key: "db"}}}}}
}

// TestGeoOff: without spec.geo the bundle names no table, and the table's
// Secrets go once the published bundle names none.
func TestGeoOff(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: geoNS, Name: "geo-db"}, Data: map[string][]byte{"db": geoDB(t, 1_700_000_000, "XA")}}
	c := geoClient(t, secretConfig("geo-db"), src)
	r := &GeoReconciler{Client: c, APIReader: c, Namespace: geoNS, Now: time.Now}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	table := manifestHash(t, c)
	if table == nil {
		t.Fatal("no table stored")
	}
	b := &BundleReconciler{Client: c, APIReader: c, Namespace: geoNS}
	policies := []*bundlev1.Policy{{Id: "a/b", Geo: &bundlev1.Geo{Deny: []string{"RU"}}}}
	if ref, _ := b.geoTable(ctx, nil, policies); ref != nil {
		t.Error("a bundle names a table without an InkwallConfig")
	}
	if ref, _ := b.geoTable(ctx, &wafv1alpha1.InkwallConfig{}, policies); ref != nil {
		t.Error("a bundle names a table without spec.geo")
	}

	// spec.geo removed while the published bundle still names the table:
	// the Secrets stay, until a bundle names none.
	publish(t, c, 1, table)
	var cfg wafv1alpha1.InkwallConfig
	_ = c.Get(ctx, client.ObjectKey{Name: "default"}, &cfg)
	cfg.Spec.Geo = nil
	if err := c.Update(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil || res.RequeueAfter == 0 || manifestHash(t, c) == nil {
		t.Fatalf("with the table still named: %v %+v, stored %x", err, res, manifestHash(t, c))
	}
	publish(t, c, 2, nil)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if manifestHash(t, c) != nil {
		t.Error("the table's manifest outlived geo")
	}
	var chunks corev1.SecretList
	_ = c.List(ctx, &chunks, client.MatchingLabels{bundle.ChunkLabel: bundlesecret.GeoSecret})
	if len(chunks.Items) != 0 {
		t.Errorf("%d chunks outlived geo", len(chunks.Items))
	}
}

// TestGeoStoreWaits: a new table isn't written while the published bundle
// names another table than the stored one: it would overwrite that table's
// slot. It is stored once the bundle names the stored table.
func TestGeoStoreWaits(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: geoNS, Name: "geo-db"}, Data: map[string][]byte{"db": geoDB(t, 1_700_000_000, "XA")}}
	c := geoClient(t, secretConfig("geo-db"), src)
	r := &GeoReconciler{Client: c, APIReader: c, Namespace: geoNS, Now: time.Now}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	a := manifestHash(t, c)
	// The bundle still names an earlier table, in the other slot.
	publish(t, c, 1, []byte("an earlier table's hash, 32 byte"))
	src.Data["db"] = geoDB(t, 1_700_000_100, "XB")
	if err := c.Update(ctx, src); err != nil {
		t.Fatal(err)
	}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil || res.RequeueAfter != geoRetry || string(manifestHash(t, c)) != string(a) {
		t.Fatalf("a new table overwrote while the bundle names another: %v %+v", err, res)
	}
	publish(t, c, 2, a)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if string(manifestHash(t, c)) == string(a) {
		t.Error("the waiting table isn't stored once the bundle names the stored one")
	}
}

func TestPrunesGeo(t *testing.T) {
	cur := &bundlev1.GeoTableRef{Sha256: []byte("c")}
	for _, tc := range []struct {
		name      string
		published *bundlev1.Bundle
		current   *bundlev1.GeoTableRef
		want      bool
	}{
		{"no bundle", nil, cur, true},
		{"a bundle without a table", &bundlev1.Bundle{}, cur, true},
		{"the current table", &bundlev1.Bundle{GeoTable: &bundlev1.GeoTableRef{Sha256: []byte("c")}}, cur, true},
		{"the previous table", &bundlev1.Bundle{GeoTable: &bundlev1.GeoTableRef{Sha256: []byte("p")}}, cur, false},
		{"a table, none current", &bundlev1.Bundle{GeoTable: &bundlev1.GeoTableRef{Sha256: []byte("p")}}, nil, false},
	} {
		if got := prunesGeo(tc.published, tc.current); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// TestGeoBrokenFileNotReread: a broken file isn't read again while its
// size and time stay: a 256 MiB file isn't hashed every minute.
func TestGeoBrokenFileNotReread(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "country.mmdb")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wafv1alpha1.InkwallConfigSpec{Geo: &wafv1alpha1.GeoConfig{Database: wafv1alpha1.GeoDatabase{File: geo.FileRoot + "/country.mmdb"}}}}
	c := geoClient(t, cfg)
	r := &GeoReconciler{Client: c, APIReader: c, Namespace: geoNS, Root: root, Now: time.Now}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	cond, _ := readyCondition(t, c)
	first := cond.Message
	// Unreadable now, with the same size and time: a read would say so.
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if cond, _ = readyCondition(t, c); cond.Reason != geo.ReasonInvalid || cond.Message != first || strings.Contains(cond.Message, "permission") {
		t.Errorf("read again: %s %q", cond.Reason, cond.Message)
	}
}
