// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/test/fakeengine"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// rejections counts the agent's "bundle rejected" logs.
type rejections struct{ n atomic.Int32 }

func (r *rejections) Enabled(context.Context, slog.Level) bool { return true }
func (r *rejections) Handle(_ context.Context, rec slog.Record) error {
	if rec.Message == "bundle rejected" {
		r.n.Add(1)
	}
	return nil
}
func (r *rejections) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *rejections) WithGroup(string) slog.Handler      { return r }

// testKeyRotation rotates the signing key with two engines connected: the
// engine's own client, whose key file a stand-in for the kubelet keeps in
// sync with the signing key Secret, and a fake engine that gets the new key
// late. The operator keeps signing with the old key until both trust the
// new one, then switches, retires the old key once both run a bundle the
// new key signed, and no engine ever rejects a bundle.
func testKeyRotation(ctx context.Context, t *testing.T, c client.Client) {
	secret := func(name string) *corev1.Secret {
		t.Helper()
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &s); err != nil {
			return nil
		}
		return &s
	}
	trusted := func() []ed25519.PublicKey {
		t.Helper()
		s := secret(bundle.SigningKeySecret)
		if s == nil {
			return nil
		}
		keys, err := bundlekey.Parse(s.Data[bundle.TrustedKeysKey])
		if err != nil {
			t.Fatalf("trusted keys: %v", err)
		}
		return keys
	}
	signedWith := func() (string, uint64) {
		s := secret(bundle.BundleSecret)
		if s == nil {
			return "", 0
		}
		v, _ := strconv.ParseUint(s.Annotations[bundle.VersionAnnotation], 10, 64)
		return s.Annotations[bundle.KeyIDAnnotation], v
	}
	// A schedule shorter than an hour is refused.
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Spec.SigningKey.RotationInterval = &metav1.Duration{Duration: 30 * time.Minute}
	if err := c.Update(ctx, cfg); err == nil || !strings.Contains(err.Error(), "rotationInterval must be at least 1h") {
		t.Fatalf("a 30m rotation interval: got %v", err)
	}

	oldKeys := trusted()
	if len(oldKeys) != 1 {
		t.Fatalf("%d trusted keys before the rotation, want 1", len(oldKeys))
	}
	oldID := bundlekey.ID(oldKeys[0])
	if id, _ := signedWith(); id != oldID {
		t.Fatalf("the bundle is signed with %q, the signing key is %q", id, oldID)
	}

	// The engine, with the trust files of its pod.
	certs := secret("inkwall-operator-webhook-tls")
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "trusted-keys.pub")
	for name, data := range map[string][]byte{
		"ca.crt":           certs.Data["ca.crt"],
		"token":            []byte(token(ctx, t, "edge", "traefik")),
		"trusted-keys.pub": bundlekey.Format(oldKeys...),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The kubelet updates the pod's mounted trust ConfigMap with a rename.
	kubelet := func(keys []ed25519.PublicKey) {
		tmp := keyFile + ".tmp"
		if err := os.WriteFile(tmp, bundlekey.Format(keys...), 0o600); err == nil {
			_ = os.Rename(tmp, keyFile)
		}
	}
	syncing := make(chan struct{})
	syncCtx, stopSync := context.WithCancel(ctx)
	go func() {
		defer close(syncing)
		for syncCtx.Err() == nil {
			if keys := trusted(); len(keys) > 0 {
				kubelet(keys)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	defer func() { stopSync(); <-syncing }()

	adm := pipeline.NewAdmission(4)
	rejected := &rejections{}
	_, port, _ := net.SplitHostPort(distAddr)
	a, err := agent.New(agent.Config{
		Addr:          "localhost:" + port,
		CAFile:        filepath.Join(dir, "ca.crt"),
		TokenFile:     filepath.Join(dir, "token"),
		PublicKeyFile: keyFile,
		CacheFile:     filepath.Join(dir, "bundle.pb"),
		EngineID:      "rotating-engine",
		PodNamespace:  "edge",
		PodName:       "rotating-engine",
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			return policy.Compile(b, policy.Options{Admission: adm, BodyLimit: 65536})
		},
		Holder:    &policy.Holder{},
		Admission: adm,
		Logger:    slog.New(rejected),
		Heartbeat: 200 * time.Millisecond,
		KeyReload: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(actx); close(done) }()
	defer func() { cancel(); <-done }()

	// The fake engine, whose keys only the test changes.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certs.Data["ca.crt"])
	late := &fakeengine.Engine{
		ID:         "late-engine",
		Addr:       "localhost:" + port,
		TLS:        &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		Token:      token(ctx, t, "edge", "traefik"),
		PublicKeys: oldKeys,
		Heartbeat:  200 * time.Millisecond,
	}
	lctx, stopLate := context.WithCancel(ctx)
	defer stopLate()
	go func() { _ = late.Run(lctx) }()

	_, version := signedWith()
	runs := func(v uint64) func() string {
		return func() string {
			if got := a.Version(); got < v {
				return "the engine runs bundle " + strconv.FormatUint(got, 10)
			}
			if got := late.Applied().GetVersion(); got < v {
				return "the fake engine runs bundle " + strconv.FormatUint(got, 10)
			}
			return ""
		}
	}
	eventually(t, "both engines run the bundle", runs(version))

	update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) {
		if cfg.Annotations == nil {
			cfg.Annotations = map[string]string{}
		}
		cfg.Annotations[wafv1alpha1.RotateSigningKeyAnnotation] = "envtest-1"
	})
	var newKey ed25519.PublicKey
	eventually(t, "the new key published", func() string {
		keys := trusted()
		if len(keys) != 2 || !keys[0].Equal(oldKeys[0]) {
			return "trusted keys: " + strconv.Itoa(len(keys))
		}
		newKey = keys[1]
		return ""
	})
	newID := bundlekey.ID(newKey)
	if s := secret(bundle.SigningKeySecret); s.Annotations[bundle.RotationPhaseAnnotation] != string(bundle.PhasePublishing) {
		t.Errorf("phase %q, want Publishing", s.Annotations[bundle.RotationPhaseAnnotation])
	}
	eventually(t, "the engine reports the new key", func() string {
		engines, err := distribution.ReadEngines(ctx, c, "default", time.Minute, time.Now())
		if err != nil {
			return err.Error()
		}
		for _, e := range engines {
			if e.ID == "rotating-engine" && slices.Contains(e.TrustedKeys, newID) {
				return ""
			}
		}
		return "not reported"
	})

	// The fake engine doesn't have the new key: the old one keeps signing,
	// past the grace.
	time.Sleep(3 * time.Second)
	if id, _ := signedWith(); id != oldID {
		t.Fatalf("signed with %q while an engine doesn't trust it", id)
	}
	late.SetPublicKeys(oldKeys[0], newKey)
	eventually(t, "the bundle signed with the new key", func() string {
		if id, _ := signedWith(); id != newID {
			return "signed with " + id
		}
		return ""
	})
	_, switched := signedWith()
	if switched <= version {
		t.Fatalf("re-signed as version %d, want a version after %d", switched, version)
	}
	eventually(t, "both engines run the bundle signed with the new key", runs(switched))
	eventually(t, "the old key retired", func() string {
		s := secret(bundle.SigningKeySecret)
		if keys := trusted(); len(keys) != 1 || !keys[0].Equal(newKey) || s.Annotations[bundle.RotationPhaseAnnotation] != "" {
			return "trusted keys: " + strconv.Itoa(len(keys)) + ", phase " + s.Annotations[bundle.RotationPhaseAnnotation]
		}
		return ""
	})
	eventually(t, "the engine trusts only the new key", func() string {
		if got := a.TrustedKeys(); !slices.Equal(got, []string{newID}) {
			return "trusts " + strings.Join(got, ", ")
		}
		return ""
	})
	late.SetPublicKeys(newKey)

	if n := rejected.n.Load(); n != 0 {
		t.Errorf("the engine rejected %d bundles during the rotation", n)
	}
	if n := late.Nacks(); n != 0 {
		t.Errorf("the fake engine rejected %d bundles during the rotation", n)
	}

	// A deleted signing key Secret comes back with the key engines trust.
	if err := c.Delete(ctx, secret(bundle.SigningKeySecret)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the signing key Secret recreated", func() string {
		if keys := trusted(); len(keys) != 1 || !keys[0].Equal(newKey) {
			return "trusted keys: " + strconv.Itoa(len(keys))
		}
		return ""
	})
}
