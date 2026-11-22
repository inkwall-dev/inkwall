// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	geov1 "github.com/inkwall-dev/inkwall/api/geo/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	"github.com/inkwall-dev/inkwall/pkg/geo"
)

// geoCluster is a cluster whose bundle names a country table mapping
// 198.51.100.0/24 to XA; named=false: a bundle that names none.
func geoCluster(t *testing.T, named bool) client.Client {
	t.Helper()
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(statusScheme()).Build()
	start := binary.BigEndian.Uint32(netip.MustParseAddr("198.51.100.0").AsSlice())
	gz, size, err := geo.Encode(&geov1.CountryTable{
		V4Starts: []uint32{0, start, start + 256}, V4Codes: []byte("\x00\x00XA\x00\x00"),
		V6Starts: make([]byte, 16), V6Codes: []byte{0, 0}, DatabaseType: "Test-Country", DatabaseBuildEpoch: 1_700_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, chunks, err := bundlesecret.Geo.Split("a", gz)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := m.Marshal()
	objs := []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: bundlesecret.GeoSecret}, Data: map[string][]byte{bundlesecret.ManifestKey: manifest}}}
	for i, ch := range chunks {
		objs = append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: m.Chunks[i]}, Data: map[string][]byte{bundlesecret.ChunkKey: ch}})
	}
	for _, o := range objs {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	b := &bundlev1.Bundle{Version: 4}
	if named {
		h := geo.Hash(gz)
		b.GeoTable = &bundlev1.GeoTableRef{Sha256: h[:], Size: uint64(size)}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := bundle.NewSigner(priv).Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Store(ctx, c, c, "inkwall-system", b, signed, pub); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGeoLookup(t *testing.T) {
	defer func(f func(string, string) (client.Reader, error)) { newStatusClient = f }(newStatusClient)
	c := geoCluster(t, true)
	newStatusClient = func(string, string) (client.Reader, error) { return c, nil }
	code, out, errOut := runCLI(t, "geo", "lookup", "198.51.100.7", "203.0.113.1", "10.0.0.1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"# Test-Country built 2023-11-14", "198.51.100.7\tXA\tcountry", "203.0.113.1\t-\tunknown", "10.0.0.1\t-\tprivate"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "geo", "lookup", "-o", "json", "198.51.100.7")
	var got []GeoLookup
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got) != 1 || got[0].Country != "XA" {
		t.Errorf("json: %d %s", code, out)
	}
	if code, _, _ := runCLI(t, "geo", "lookup", "not-an-ip"); code != 2 {
		t.Errorf("a bad address: exit %d", code)
	}
	if code, _, _ := runCLI(t, "geo"); code != 2 {
		t.Errorf("no subcommand: exit %d", code)
	}
	unnamed := geoCluster(t, false)
	newStatusClient = func(string, string) (client.Reader, error) { return unnamed, nil }
	if code, _, errOut := runCLI(t, "geo", "lookup", "198.51.100.7"); code != 2 || !strings.Contains(errOut, "names no country table") {
		t.Errorf("no table named: exit %d, %s", code, errOut)
	}
}
