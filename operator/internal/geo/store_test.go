// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

const ns = "inkwall-system"

func secret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: data}
}

func TestStoreLoadPrune(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().Build()
	if got, err := Load(ctx, c, ns); got != nil || err != nil {
		t.Fatalf("no Secret: %v, %v", got, err)
	}
	first, _ := compileOK(t, sampleDB(t))
	if err := Store(ctx, c, c, ns, first); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ctx, c, ns)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != first.Hash || got.Size != first.Size || got.BuildEpoch != first.BuildEpoch || got.DatabaseSHA256 != first.DatabaseSHA256 ||
		got.DatabaseType != first.DatabaseType || got.Ranges != first.Ranges || !bytes.Equal(got.Compressed, first.Compressed) {
		t.Errorf("loaded %+v, stored %+v", got, first)
	}
	var m corev1.Secret
	_ = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo"}, &m)
	man, err := Format.ParseManifest(m.Data[bundlesecret.ManifestKey])
	if err != nil || man.SHA256 != hex.EncodeToString(first.Hash[:]) || man.Chunks[0] != "inkwall-geo-a-0" {
		t.Fatalf("manifest %+v: %v", man, err)
	}
	rv := m.ResourceVersion
	// The same table again writes nothing.
	if err := Store(ctx, c, c, ns, first); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo"}, &m)
	if m.ResourceVersion != rv {
		t.Error("storing the same table wrote the manifest")
	}
	// A new table goes to the other slot; the old chunks stay until Prune.
	second, _ := compileOK(t, sampleDB(t, mmdbtest.MaxMindAliases...))
	if err := Store(ctx, c, c, ns, second); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(ctx, c, ns); got == nil || got.Hash != second.Hash {
		t.Fatal("the second table isn't loaded")
	}
	var old corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo-a-0"}, &old); err != nil {
		t.Fatalf("the first table's chunk is gone before Prune: %v", err)
	}
	if err := Prune(ctx, c, c, ns); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo-a-0"}, &old); err == nil {
		t.Error("Prune kept the first table's chunk")
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo-b-0"}, &old); err != nil {
		t.Errorf("Prune deleted the current chunk: %v", err)
	}
}

func TestLoadRefuses(t *testing.T) {
	ctx := context.Background()
	tb, _ := compileOK(t, sampleDB(t))
	for name, edit := range map[string]func(c client.Client){
		"chunk overwritten": func(c client.Client) {
			_ = c.Update(ctx, secret("inkwall-geo-a-0", map[string][]byte{bundlesecret.ChunkKey: []byte("other")}))
		},
		"chunk missing": func(c client.Client) {
			_ = c.Delete(ctx, secret("inkwall-geo-a-0", nil))
		},
		"size wrong": func(c client.Client) {
			var s corev1.Secret
			_ = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo"}, &s)
			s.Annotations[SizeAnnotation] = "12"
			_ = c.Update(ctx, &s)
		},
		"manifest broken": func(c client.Client) {
			var s corev1.Secret
			_ = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "inkwall-geo"}, &s)
			s.Data[bundlesecret.ManifestKey] = []byte("{")
			_ = c.Update(ctx, &s)
		},
	} {
		c := fake.NewClientBuilder().Build()
		if err := Store(ctx, c, c, ns, tb); err != nil {
			t.Fatal(err)
		}
		edit(c)
		if got, err := Load(ctx, c, ns); err == nil || got != nil {
			t.Errorf("%s: loaded %v", name, got)
		}
	}
}

func TestReadSecret(t *testing.T) {
	ctx := context.Background()
	db := sampleDB(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(db)
	_ = zw.Close()
	var bomb bytes.Buffer
	zw = gzip.NewWriter(&bomb)
	_, _ = zw.Write(make([]byte, MaxSecretBytes+1))
	_ = zw.Close()
	c := fake.NewClientBuilder().WithObjects(secret("geo-db", map[string][]byte{
		"raw": db, "gz": gz.Bytes(), "bomb": bomb.Bytes(), "big": make([]byte, MaxSecretBytes+1), "badgz": {0x1f, 0x8b, 1},
	})).Build()
	for key, want := range map[string]string{"raw": "", "gz": "", "bomb": ReasonTooLarge, "big": ReasonTooLarge, "badgz": ReasonInvalid, "none": ReasonNotFound} {
		src, err := ReadSecret(ctx, c, ns, "geo-db", key)
		switch {
		case want == "" && (err != nil || !bytes.Equal(src.Data, db)):
			t.Errorf("%s: %v", key, err)
		case want != "" && ReasonOf(err) != want:
			t.Errorf("%s: %v, want %s", key, err, want)
		}
	}
	if _, err := ReadSecret(ctx, c, ns, "missing", "raw"); ReasonOf(err) != ReasonNotFound {
		t.Errorf("missing Secret: %v", err)
	}
}

func TestReadFile(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	db := sampleDB(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, "country.mmdb"), db, 0o600))
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("operator token"), 0o600))
	must(os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")))
	must(os.Mkdir(filepath.Join(root, "dir"), 0o700))
	must(os.WriteFile(filepath.Join(root, "empty"), nil, 0o600))
	big, err := os.Create(filepath.Join(root, "big"))
	must(err)
	must(big.Truncate(MaxFileBytes + 1)) // sparse
	_ = big.Close()

	src, err := ReadFile(root, root+"/country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src.Data, db) || src.Size != int64(len(db)) || src.ModTime.IsZero() {
		t.Error("the mapped file differs")
	}
	if tb, err := Compile(context.Background(), src.Data, nil); err != nil || tb == nil {
		t.Errorf("compiling the mapped file: %v", err)
	}
	must(src.Close())
	if size, mtime, err := StatFile(root, root+"/country.mmdb"); err != nil || size != int64(len(db)) || mtime.IsZero() {
		t.Errorf("StatFile: %d %v %v", size, mtime, err)
	}
	for name, want := range map[string]string{
		root + "/missing":          ReasonNotFound,
		root + "/escape":           ReasonInvalid,
		root + "/../etc/passwd":    ReasonInvalid,
		root + "/dir":              ReasonInvalid,
		root + "/empty":            ReasonInvalid,
		root + "/big":              ReasonTooLarge,
		root:                       ReasonInvalid,
		"country.mmdb":             ReasonInvalid,
		outside + "/secret":        ReasonInvalid,
		root + "/./country.mmdb":   ReasonInvalid,
		root + "x/country.mmdb":    ReasonInvalid,
		root + "/dir/../escape":    ReasonInvalid,
		"/var/lib/inkwall/geo/../": ReasonInvalid,
	} {
		src, err := ReadFile(root, name)
		if ReasonOf(err) != want || err == nil {
			t.Errorf("%s: %v, want %s", name, err, want)
		}
		_ = src.Close()
	}
}

// TestTruncatedMapping: a mapped file truncated under the compiler faults;
// the fault is recovered as Invalid, not a crashed operator.
func TestTruncatedMapping(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mmap faults on Linux")
	}
	root := t.TempDir()
	// Large enough that the tree spans pages past the truncation.
	var nets []mmdbtest.Network
	for i := range 4096 {
		nets = append(nets, nw(netipPrefix4(i), cc("AU")))
	}
	db := must(mmdbtest.DB{Networks: nets}.Bytes())
	path := filepath.Join(root, "country.mmdb")
	if err := os.WriteFile(path, db, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := ReadFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	_, err = Compile(context.Background(), src.Data, nil)
	var e *Error
	if !errors.As(err, &e) || e.Reason != ReasonInvalid || !strings.Contains(err.Error(), "failed") {
		t.Errorf("%v, want a recovered fault", err)
	}
}

func netipPrefix4(i int) string {
	return "10." + itoa(i>>8) + "." + itoa(i&0xff) + ".0/24"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
