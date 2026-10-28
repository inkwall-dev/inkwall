// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
)

func TestKeyringSecret(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if k, s, err := LoadKeyring(ctx, c, "inkwall-system"); k != nil || s != nil || err != nil {
		t.Fatalf("no Secret yet: %v %v %v", k, s, err)
	}
	k, err := NewKeyring(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyring(ctx, c, "inkwall-system", k, nil); err != nil {
		t.Fatal(err)
	}
	got, s, err := LoadKeyring(ctx, c, "inkwall-system")
	if err != nil || got.Active.KeyID() != k.Active.KeyID() || len(got.Active.KeyID()) != 16 || got.Phase() != PhaseIdle || !got.ActiveSince.Equal(now) {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	if !ed25519.PublicKey(s.Data[PublicKeyKey]).Equal(k.Active.Public()) || string(s.Data[TrustedKeysKey]) != string(k.Active.Public()) {
		t.Errorf("Secret data: %v", s.Data)
	}

	// Each phase survives a save and a load: publishing, then retiring.
	next, _ := GenerateSigner()
	pub := *got
	pub.Next, pub.PhaseSince, pub.Request = next, now.Add(time.Minute), "r1"
	if err := SaveKeyring(ctx, c, "inkwall-system", &pub, s); err != nil {
		t.Fatal(err)
	}
	got, s, err = LoadKeyring(ctx, c, "inkwall-system")
	if err != nil || got.Phase() != PhasePublishing || got.Next.KeyID() != next.KeyID() || got.Request != "r1" ||
		!got.PhaseSince.Equal(now.Add(time.Minute)) || s.Annotations[RotationPhaseAnnotation] != "Publishing" {
		t.Fatalf("publishing: %+v, %v", got, err)
	}
	if keys, _ := bundlekey.Parse(s.Data[TrustedKeysKey]); len(keys) != 2 || !keys[0].Equal(k.Active.Public()) || !keys[1].Equal(next.Public()) {
		t.Errorf("trusted keys while publishing: %d", len(keys))
	}
	ret := Keyring{Active: next, Previous: k.Active.Public(), PhaseSince: now, ActiveSince: now, SwitchVersion: 7, Request: "r1"}
	s.Annotations["example.com/mine"] = "kept"
	if err := SaveKeyring(ctx, c, "inkwall-system", &ret, s); err != nil {
		t.Fatal(err)
	}
	got, s, err = LoadKeyring(ctx, c, "inkwall-system")
	if err != nil || got.Phase() != PhaseRetiring || got.SwitchVersion != 7 || !got.Previous.Equal(k.Active.Public()) ||
		s.Annotations["example.com/mine"] != "kept" || !slices.Equal(got.TrustedIDs(), []string{next.KeyID(), k.Active.KeyID()}) {
		t.Fatalf("retiring: %+v, %v (annotations %v)", got, err, s.Annotations)
	}

	// A stale copy can't overwrite a newer keyring.
	stale := s.DeepCopy()
	idle := Keyring{Active: next, ActiveSince: now, Request: "r1"}
	if err := SaveKeyring(ctx, c, "inkwall-system", &idle, s); err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyring(ctx, c, "inkwall-system", &ret, stale); !apierrors.IsConflict(err) {
		t.Fatalf("stale write: got %v, want a conflict", err)
	}
	got, s, _ = LoadKeyring(ctx, c, "inkwall-system")
	if got.Phase() != PhaseIdle || s.Annotations[RotationPhaseAnnotation] != "" || s.Annotations[switchVersionAnnotation] != "" {
		t.Errorf("idle again: %+v %v", got, s.Annotations)
	}

	// Corrupt Secrets are refused, not replaced.
	for name, mutate := range map[string]func(*corev1.Secret){
		"short seed":      func(s *corev1.Secret) { s.Data[privateKeyKey] = []byte("short") },
		"short next seed": func(s *corev1.Secret) { s.Data[nextPrivateKeyKey] = []byte("short") },
		"short previous":  func(s *corev1.Secret) { s.Data[previousPublicKeyKey] = []byte("short") },
		"next and previous": func(s *corev1.Secret) {
			s.Data[nextPrivateKeyKey], s.Data[previousPublicKeyKey] = next.key.Seed(), []byte(k.Active.Public())
		},
		"bad time": func(s *corev1.Secret) { s.Annotations[activeSinceAnnotation] = "yesterday" },
	} {
		bad := s.DeepCopy()
		mutate(bad)
		if err := c.Update(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadKeyring(ctx, c, "inkwall-system"); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// Back to the good keyring for the next case.
		if err := c.Delete(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if err := SaveKeyring(ctx, c, "inkwall-system", &idle, nil); err != nil {
			t.Fatal(err)
		}
		if _, s, err = LoadKeyring(ctx, c, "inkwall-system"); err != nil {
			t.Fatal(err)
		}
	}
}

// A Secret written before key rotation: one key, no annotations.
func TestKeyringLegacySecret(t *testing.T) {
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(priv)
	created := metav1.NewTime(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	c := newClient(t)
	if err := c.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: SigningKeySecret, CreationTimestamp: created},
		Data:       map[string][]byte{privateKeyKey: priv.Seed(), PublicKeyKey: signer.Public(), keyIDKey: []byte(signer.KeyID())},
	}); err != nil {
		t.Fatal(err)
	}
	k, _, err := LoadKeyring(ctx, c, "inkwall-system")
	if err != nil || k.Active.KeyID() != signer.KeyID() || k.Phase() != PhaseIdle || k.ActiveSince.IsZero() {
		t.Fatalf("legacy Secret: %+v, %v", k, err)
	}
}

type engines []EngineKeys

// TestRotate drives the rotation state machine through a rotation with two
// engines, one slow to get the new key, and checks it never signs with a
// key an engine doesn't trust.
func TestRotate(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	k, _ := NewKeyring(t0)
	old := k.Active
	in := RotationInput{Now: t0, Grace: time.Minute, EnginesKnown: true, BundleVersion: 5, BundleKeyID: old.KeyID()}
	step := func(in RotationInput) Step {
		t.Helper()
		st, err := Rotate(k, in)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Changed && st.Keyring != k {
			t.Fatal("an unchanged step returned another keyring")
		}
		k = st.Keyring
		return st
	}

	// Nothing requested, nothing due.
	if st := step(in); st.Changed || st.Waiting != "" {
		t.Fatalf("idle: %+v", st)
	}
	// A request starts a rotation, once.
	in.Request = "2026-10-28"
	st := step(in)
	if st.Event != "started" || k.Phase() != PhasePublishing || k.Active != old || k.Request != "2026-10-28" {
		t.Fatalf("request: %+v", st)
	}
	next := k.Next
	if st := step(in); st.Changed {
		t.Fatalf("the same request again: %+v", st)
	}

	// Publishing: the old key signs until the grace is over and every
	// engine trusts the new key.
	in.Engines = engines{
		{Name: "edge/traefik-1", TrustedKeys: []string{old.KeyID(), next.KeyID()}, Applied: 5},
		{Name: "edge/traefik-2", TrustedKeys: []string{old.KeyID()}, Applied: 5},
	}
	in.Now = t0.Add(30 * time.Second)
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "at the earliest") {
		t.Fatalf("within the grace: %+v", st)
	}
	in.Now = t0.Add(2 * time.Minute)
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "1/2 engines don't trust it yet: edge/traefik-2") {
		t.Fatalf("an engine without the key: %+v", st)
	}
	in.Engines[1].TrustedKeys = nil
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "older than key rotation") {
		t.Fatalf("an engine that reports no keys: %+v", st)
	}
	in.Engines[1].TrustedKeys = []string{next.KeyID(), old.KeyID()}
	in.EnginesKnown = false
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "engine report") {
		t.Fatalf("a new leader: %+v", st)
	}
	in.EnginesKnown = true
	st = step(in)
	if st.Event != "switched" || k.Active != next || !k.Previous.Equal(old.Public()) || k.Phase() != PhaseRetiring || !k.ActiveSince.Equal(in.Now) {
		t.Fatalf("switch: %+v", st)
	}
	if !slices.Equal(k.TrustedIDs(), []string{next.KeyID(), old.KeyID()}) {
		t.Fatalf("trusted after the switch: %q", k.TrustedIDs())
	}

	// Retiring: first the bundle signed with the new key, as version 6.
	switched := in.Now
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "waiting for the bundle signed with it") {
		t.Fatalf("before the new bundle: %+v", st)
	}
	in.BundleVersion, in.BundleKeyID = 6, next.KeyID()
	if st := step(in); !st.Changed || k.SwitchVersion != 6 || st.Event != "" {
		t.Fatalf("the new bundle: %+v", st)
	}
	// A later bundle doesn't move the switch version.
	in.BundleVersion = 7
	in.Now = switched.Add(30 * time.Second)
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "at the earliest") || k.SwitchVersion != 6 {
		t.Fatalf("within the grace: %+v", st)
	}
	in.Now = switched.Add(2 * time.Minute)
	in.Engines[0].Applied = 6
	if st := step(in); st.Changed || !strings.Contains(st.Waiting, "1/2 engines don't run a bundle signed with it (6) yet: edge/traefik-2") {
		t.Fatalf("an engine behind: %+v", st)
	}
	in.Engines[1].Applied = 7
	st = step(in)
	if st.Event != "retired" || k.Phase() != PhaseIdle || k.Active != next || k.Previous != nil || k.SwitchVersion != 0 {
		t.Fatalf("retire: %+v", st)
	}
	if st := step(in); st.Changed {
		t.Fatalf("the handled request started another rotation: %+v", st)
	}

	// A request made during a rotation starts another one after it.
	in.Request = "again"
	if st := step(in); st.Event != "started" || k.Request != "again" {
		t.Fatalf("the next request: %+v", st)
	}
	in.Request = "third"
	in.Now = in.Now.Add(time.Minute)
	in.Engines = nil
	if st := step(in); st.Event != "switched" || k.Request != "again" {
		t.Fatalf("a request while publishing: %+v", st)
	}
	in.BundleVersion, in.BundleKeyID = 8, k.Active.KeyID()
	step(in) // records the switch version
	in.Now = in.Now.Add(time.Minute)
	if st := step(in); st.Event != "retired" {
		t.Fatalf("retiring: %+v", st)
	}
	if st := step(in); st.Event != "started" || k.Request != "third" {
		t.Fatalf("the request made during the rotation: %+v", st)
	}
	// Back to one key, for the schedule.
	k = &Keyring{Active: k.Active, ActiveSince: k.ActiveSince, Request: k.Request}

	// A schedule: due once the key has signed for the interval.
	in.Interval = time.Hour
	if st := step(in); st.Changed {
		t.Fatalf("not due yet: %+v", st)
	}
	in.Now = k.ActiveSince.Add(time.Hour)
	if st := step(in); st.Event != "started" || k.Request != "third" {
		t.Fatalf("due: %+v", st)
	}

	// With no engines connected, the grace alone gates each phase.
	in.Engines = nil
	in.Now = in.Now.Add(time.Minute)
	if st := step(in); st.Event != "switched" {
		t.Fatalf("no engines: %+v", st)
	}
}
