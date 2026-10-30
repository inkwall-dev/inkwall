// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// fakeAPI serves the bundle Secret as the Kubernetes API does.
type fakeAPI struct {
	srv    *httptest.Server
	caFile string

	mu     sync.Mutex
	signed *bundlev1.SignedBundle // nil: 404
	// chunked serves the bundle in chunks; missing is a chunk not found,
	// stale one of another bundle.
	chunked        bool
	missing, stale string
	// gz is signed compressed, computed once: under the race detector,
	// compressing a large bundle on every read takes seconds.
	gz     []byte
	tokens []string
	reads  atomic.Int32
}

const secretsPath = "/api/v1/namespaces/inkwall-system/secrets/"

func newFakeAPI(t *testing.T, dir string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reads.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		name, ok := strings.CutPrefix(r.URL.Path, secretsPath)
		if !ok {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		data := f.secrets(t)[name]
		if data == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"secrets \"` + name + `\" not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Secret", "data": data})
	}))
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(dir, "kube-ca.crt")
	writeFile(t, f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
	writeFile(t, filepath.Join(dir, "kube-token"), []byte("kube-token-1\n"))
	return f
}

// secrets returns the Secrets' data by name, as the operator writes them.
func (f *fakeAPI) secrets(t *testing.T) map[string]map[string][]byte {
	if f.signed == nil {
		return nil
	}
	if f.gz == nil {
		raw, _ := proto.Marshal(f.signed)
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		f.gz = gz.Bytes()
	}
	if !f.chunked {
		return map[string]map[string][]byte{"inkwall-bundle": {SecretBundleKey: f.gz, "ed25519.pub": []byte("ignored")}}
	}
	m, chunks, err := bundlesecret.Split("inkwall-bundle", "a", f.gz)
	if err != nil {
		t.Error(err)
	}
	manifest, _ := m.Marshal()
	out := map[string]map[string][]byte{"inkwall-bundle": {bundlesecret.ManifestKey: manifest, "ed25519.pub": []byte("ignored")}}
	for i, c := range chunks {
		if m.Chunks[i] == f.stale {
			c = bytes.Clone(c)
			c[len(c)/2] ^= 1
		}
		if m.Chunks[i] != f.missing {
			out[m.Chunks[i]] = map[string][]byte{bundlesecret.ChunkKey: c}
		}
	}
	return out
}

func (f *fakeAPI) set(signed *bundlev1.SignedBundle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signed, f.gz = signed, nil
}

func (f *fakeAPI) source(dir string) *SecretSource {
	return &SecretSource{
		Namespace: "inkwall-system", Name: "inkwall-bundle",
		APIServer: f.srv.URL, CAFile: f.caFile, TokenFile: filepath.Join(dir, "kube-token"),
	}
}

// A new engine, no cache, the operator down: it enforces the Secret's
// bundle, and caches it.
func TestSecretColdStart(t *testing.T) {
	e := newEnv(t)
	api := newFakeAPI(t, e.dir)
	api.set(bundle(t, e.priv, 4, time.Now(), blockAttack))
	a, holder, _ := e.agent(t, func(c *Config) {
		c.Addr = "127.0.0.1:1"
		c.Secret = api.source(e.dir)
	})
	run(t, a)
	select {
	case <-a.Applied():
	case <-time.After(5 * time.Second):
		t.Fatal("the Secret's bundle was not applied")
	}
	if a.Version() != 4 || !blocks(holder) {
		t.Fatalf("the Secret's bundle is not enforced (version %d)", a.Version())
	}
	api.mu.Lock()
	token := api.tokens[0]
	api.mu.Unlock()
	if token != "Bearer kube-token-1" {
		t.Errorf("token %q, want the API server's", token)
	}
	waitFor(t, "the cache file", func() bool { _, err := os.Stat(filepath.Join(e.dir, "bundle.pb")); return err == nil })

	// Once it has a bundle, the engine waits for the operator and doesn't
	// read the Secret again.
	reads := api.reads.Load()
	time.Sleep(300 * time.Millisecond)
	if api.reads.Load() != reads {
		t.Error("the Secret is read again after a bundle is applied")
	}
}

// largeBundle is a bundle just over one Secret, compressed: random bytes
// don't compress.
func largeBundle(t *testing.T, key ed25519.PrivateKey, version uint64) *bundlev1.SignedBundle {
	t.Helper()
	signed := bundle(t, key, version, time.Now(), blockAttack)
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		t.Fatal(err)
	}
	noise := make([]byte, bundlesecret.ChunkBytes)
	_, _ = rand.Read(noise)
	b.ContentHash = append(b.ContentHash, noise...)
	raw, err := proto.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	signed.Bundle, signed.Signature = raw, ed25519.Sign(key, raw)
	return signed
}

// A bundle too large for one Secret is read from its chunks.
func TestSecretColdStartChunks(t *testing.T) {
	e := newEnv(t)
	api := newFakeAPI(t, e.dir)
	api.set(largeBundle(t, e.priv, 6))
	api.mu.Lock()
	api.chunked = true
	api.mu.Unlock()
	a, holder, _ := e.agent(t, func(c *Config) {
		c.Addr = "127.0.0.1:1"
		c.Secret = api.source(e.dir)
	})
	run(t, a)
	waitFor(t, "the chunked bundle", func() bool { return a.Version() == 6 })
	if !blocks(holder) {
		t.Fatal("the chunked bundle is not enforced")
	}
	if n := api.reads.Load(); n != 3 {
		t.Errorf("%d reads, want the Secret and its 2 chunks", n)
	}
}

// A chunk missing, or of another bundle (the operator writing the next
// one), is never joined into a bundle; once complete, it is.
func TestSecretChunksIncomplete(t *testing.T) {
	e := newEnv(t)
	api := newFakeAPI(t, e.dir)
	api.set(largeBundle(t, e.priv, 6))
	src := api.source(e.dir)
	for _, tc := range []struct{ name, missing, stale string }{
		{name: "missing", missing: "inkwall-bundle-a-1"},
		{name: "stale", stale: "inkwall-bundle-a-0"},
	} {
		api.mu.Lock()
		api.chunked, api.missing, api.stale = true, tc.missing, tc.stale
		api.mu.Unlock()
		if _, err := src.fetch(t.Context()); !errors.Is(err, bundlesecret.ErrIncomplete) {
			t.Errorf("%s chunk: %v, want ErrIncomplete", tc.name, err)
		}
	}
	api.mu.Lock()
	api.missing, api.stale = "", ""
	api.mu.Unlock()
	if signed, err := src.fetch(t.Context()); err != nil || len(signed.GetBundle()) < bundlesecret.ChunkBytes {
		t.Fatalf("complete: %v", err)
	}
}

// The Secret isn't there yet (the operator never ran): the engine retries
// while the operator is unreachable.
func TestSecretRetried(t *testing.T) {
	e := newEnv(t)
	api := newFakeAPI(t, e.dir)
	a, holder, _ := e.agent(t, func(c *Config) {
		c.Addr = "127.0.0.1:1"
		c.Secret = api.source(e.dir)
	})
	run(t, a)
	waitFor(t, "a first read", func() bool { return api.reads.Load() >= 1 })
	if a.Version() != 0 || blocks(holder) {
		t.Fatal("a bundle without a Secret")
	}
	api.set(bundle(t, e.priv, 2, time.Now(), blockAttack))
	waitFor(t, "the bundle", func() bool { return a.Version() == 2 })
	if !blocks(holder) {
		t.Fatal("not enforced")
	}
}

// A bundle in the Secret is verified like the operator's: one signed with
// another key is refused.
func TestSecretBadSignature(t *testing.T) {
	e := newEnv(t)
	api := newFakeAPI(t, e.dir)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	api.set(bundle(t, other, 9, time.Now(), blockAttack))
	a, holder, _ := e.agent(t, func(c *Config) {
		c.Addr = "127.0.0.1:1"
		c.Secret = api.source(e.dir)
	})
	run(t, a)
	waitFor(t, "two reads", func() bool { return api.reads.Load() >= 2 })
	if a.Version() != 0 || blocks(holder) {
		t.Fatal("a bundle signed with another key was applied")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "bundle.pb")); err == nil {
		t.Error("a refused bundle was cached")
	}
}

// A usable cache comes first: the Secret isn't read.
func TestSecretAfterCache(t *testing.T) {
	e := newEnv(t)
	writeCacheFile(t, filepath.Join(e.dir, "bundle.pb"), bundle(t, e.priv, 3, time.Now(), blockAttack))
	api := newFakeAPI(t, e.dir)
	api.set(bundle(t, e.priv, 5, time.Now(), blockAttack))
	a, _, _ := e.agent(t, func(c *Config) {
		c.Addr = "127.0.0.1:1"
		c.Secret = api.source(e.dir)
	})
	run(t, a)
	waitFor(t, "the cached bundle", func() bool { return a.Version() == 3 })
	time.Sleep(200 * time.Millisecond)
	if n := api.reads.Load(); n != 0 {
		t.Errorf("the Secret was read %d times with a usable cache", n)
	}
}

func TestSecretErrors(t *testing.T) {
	dir := t.TempDir()
	api := newFakeAPI(t, dir)
	src := api.source(dir)
	if _, err := src.fetch(t.Context()); err == nil || !bytes.Contains([]byte(err.Error()), []byte("not found")) {
		t.Errorf("missing Secret: %v", err)
	}
	if _, err := decodeSecretBundle([]byte("not gzip")); err == nil {
		t.Error("garbage decoded")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := (&SecretSource{}).server(); err == nil {
		t.Error("an API server outside a cluster")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if s, err := (&SecretSource{}).server(); err != nil || s != "https://10.0.0.1:443" {
		t.Errorf("in-cluster address %q, %v", s, err)
	}
}

func writeCacheFile(t *testing.T, name string, signed *bundlev1.SignedBundle) {
	t.Helper()
	if err := writeCache(name, signed); err != nil {
		t.Fatal(err)
	}
}
