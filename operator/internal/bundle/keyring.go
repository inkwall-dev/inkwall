// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
)

// Keys of the signing key Secret. ed25519.key, ed25519.pub (PublicKeyKey)
// and key-id are the active key, as before key rotation.
const (
	privateKeyKey = "ed25519.key"
	keyIDKey      = "key-id"
	// nextPrivateKeyKey holds the next key's seed while it is published but
	// doesn't sign yet.
	nextPrivateKeyKey = "next.ed25519.key"
	// previousPublicKeyKey holds the key that signed before the active one,
	// trusted until every engine runs a bundle signed by its successor.
	previousPublicKeyKey = "previous.ed25519.pub"
	// TrustedKeysKey holds every public key engines must accept now, in the
	// bundlekey format: the active key and, during a rotation, the next or
	// the previous one. The trust ConfigMaps carry it.
	TrustedKeysKey = "trusted-keys.pub"
)

// Annotations on the signing key Secret.
const (
	// RotationPhaseAnnotation is the rotation's phase, for people and
	// tools: Publishing or Retiring, absent between rotations.
	RotationPhaseAnnotation = "waf.inkwall.dev/rotation-phase"
	phaseSinceAnnotation    = "waf.inkwall.dev/rotation-phase-since"
	switchVersionAnnotation = "waf.inkwall.dev/rotation-switch-version"
	activeSinceAnnotation   = "waf.inkwall.dev/key-active-since"
	// requestAnnotation is the last rotation request handled (the
	// InkwallConfig's waf.inkwall.dev/rotate-signing-key).
	requestAnnotation = "waf.inkwall.dev/rotation-request"
)

// Phase is where a key rotation is.
type Phase string

// The phases of a rotation (0004 §4.6).
const (
	// PhaseIdle: one key, which signs.
	PhaseIdle Phase = ""
	// PhasePublishing: the next key is published to the engines; the active
	// one still signs.
	PhasePublishing Phase = "Publishing"
	// PhaseRetiring: the new key signs; the previous one stays trusted
	// until every engine runs a bundle signed by the new one.
	PhaseRetiring Phase = "Retiring"
)

// Keyring is the cluster's bundle signing keys, kept in the signing key
// Secret.
type Keyring struct {
	// Active signs bundles.
	Active *Signer
	// Next is published and will sign (PhasePublishing).
	Next *Signer
	// Previous signed before Active and is still trusted (PhaseRetiring).
	Previous ed25519.PublicKey
	// PhaseSince is when the phase began; zero when idle.
	PhaseSince time.Time
	// SwitchVersion is the first bundle signed by Active, once it is
	// published (PhaseRetiring).
	SwitchVersion uint64
	// ActiveSince is when Active began to sign.
	ActiveSince time.Time
	// Request is the last rotation request handled.
	Request string
}

// NewKeyring generates a keyring with one key.
func NewKeyring(now time.Time) (*Keyring, error) {
	s, err := GenerateSigner()
	if err != nil {
		return nil, err
	}
	return &Keyring{Active: s, ActiveSince: now}, nil
}

// Phase returns the rotation's phase.
func (k *Keyring) Phase() Phase {
	switch {
	case k.Next != nil:
		return PhasePublishing
	case k.Previous != nil:
		return PhaseRetiring
	}
	return PhaseIdle
}

// Trusted returns the public keys engines must accept now: the active one
// first.
func (k *Keyring) Trusted() []ed25519.PublicKey {
	keys := []ed25519.PublicKey{k.Active.Public()}
	if k.Next != nil {
		keys = append(keys, k.Next.Public())
	}
	if k.Previous != nil {
		keys = append(keys, k.Previous)
	}
	return keys
}

// TrustedIDs returns the IDs of the trusted keys, as Trusted orders them.
func (k *Keyring) TrustedIDs() []string {
	var ids []string
	for _, pub := range k.Trusted() {
		ids = append(ids, bundlekey.ID(pub))
	}
	return ids
}

func seedSigner(seed []byte, what string) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not an ed25519 seed", what)
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed)), nil
}

func parseTime(s *corev1.Secret, annotation string) (time.Time, error) {
	v, ok := s.Annotations[annotation]
	if !ok {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("annotation %s: %w", annotation, err)
	}
	return t, nil
}

// LoadKeyring reads the keyring from the signing key Secret, and returns
// the Secret to pass to SaveKeyring; nil, nil if there is none.
func LoadKeyring(ctx context.Context, c client.Reader, namespace string) (*Keyring, *corev1.Secret, error) {
	key := types.NamespacedName{Namespace: namespace, Name: SigningKeySecret}
	var s corev1.Secret
	err := c.Get(ctx, key, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read the signing key Secret: %w", err)
	}
	k, err := parseKeyring(&s)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key Secret %s: %w", key, err)
	}
	return k, &s, nil
}

func parseKeyring(s *corev1.Secret) (*Keyring, error) {
	var (
		k   Keyring
		err error
	)
	if k.Active, err = seedSigner(s.Data[privateKeyKey], privateKeyKey); err != nil {
		return nil, err
	}
	if seed, ok := s.Data[nextPrivateKeyKey]; ok {
		if k.Next, err = seedSigner(seed, nextPrivateKeyKey); err != nil {
			return nil, err
		}
	}
	if pub, ok := s.Data[previousPublicKeyKey]; ok {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s is not an ed25519 public key", previousPublicKeyKey)
		}
		k.Previous = ed25519.PublicKey(pub)
	}
	if k.Next != nil && k.Previous != nil {
		return nil, fmt.Errorf("both %s and %s: one rotation at a time", nextPrivateKeyKey, previousPublicKeyKey)
	}
	if k.PhaseSince, err = parseTime(s, phaseSinceAnnotation); err != nil {
		return nil, err
	}
	if k.ActiveSince, err = parseTime(s, activeSinceAnnotation); err != nil {
		return nil, err
	}
	if k.ActiveSince.IsZero() {
		// Created before key rotation: the key has signed since then.
		k.ActiveSince = s.CreationTimestamp.Time
	}
	if v, ok := s.Annotations[switchVersionAnnotation]; ok {
		if k.SwitchVersion, err = strconv.ParseUint(v, 10, 64); err != nil {
			return nil, fmt.Errorf("annotation %s: %w", switchVersionAnnotation, err)
		}
	}
	k.Request = s.Annotations[requestAnnotation]
	return &k, nil
}

// SaveKeyring writes k to the signing key Secret: a new one if s is nil,
// else s, read by LoadKeyring, whose resourceVersion makes a concurrent
// write fail rather than be lost.
func SaveKeyring(ctx context.Context, c client.Client, namespace string, k *Keyring, s *corev1.Secret) error {
	data := map[string][]byte{
		privateKeyKey:  k.Active.key.Seed(),
		PublicKeyKey:   k.Active.Public(),
		keyIDKey:       []byte(k.Active.KeyID()),
		TrustedKeysKey: bundlekey.Format(k.Trusted()...),
	}
	if k.Next != nil {
		data[nextPrivateKeyKey] = k.Next.key.Seed()
	}
	if k.Previous != nil {
		data[previousPublicKeyKey] = k.Previous
	}
	annotations := map[string]string{activeSinceAnnotation: k.ActiveSince.UTC().Format(time.RFC3339)}
	if k.Request != "" {
		annotations[requestAnnotation] = k.Request
	}
	if phase := k.Phase(); phase != PhaseIdle {
		annotations[RotationPhaseAnnotation] = string(phase)
		annotations[phaseSinceAnnotation] = k.PhaseSince.UTC().Format(time.RFC3339)
	}
	if k.SwitchVersion != 0 {
		annotations[switchVersionAnnotation] = strconv.FormatUint(k.SwitchVersion, 10)
	}

	if s == nil {
		return c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: SigningKeySecret, Labels: managedLabels(), Annotations: annotations},
			Data:       data,
		})
	}
	s = s.DeepCopy()
	// Keep annotations that aren't the keyring's.
	maps.DeleteFunc(s.Annotations, func(name, _ string) bool {
		return name == RotationPhaseAnnotation || name == phaseSinceAnnotation || name == switchVersionAnnotation ||
			name == activeSinceAnnotation || name == requestAnnotation
	})
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	maps.Copy(s.Annotations, annotations)
	s.Data = data
	return c.Update(ctx, s)
}

// EngineKeys is what a rotation needs to know of a connected engine.
type EngineKeys struct {
	// Name identifies the engine to people (its pod).
	Name string
	// TrustedKeys are the key IDs the engine reported.
	TrustedKeys []string
	// Applied is the bundle version the engine runs.
	Applied uint64
}

// RotationInput is what a rotation step decides on.
type RotationInput struct {
	Now time.Time
	// Request is the InkwallConfig's waf.inkwall.dev/rotate-signing-key: a
	// value not handled yet starts a rotation.
	Request string
	// Interval, if not 0, rotates a key that has signed this long.
	Interval time.Duration
	// Grace is the least time each phase lasts: the kubelet takes a minute
	// or two to update a mounted ConfigMap, and an engine that isn't
	// connected now isn't in Engines.
	Grace time.Duration
	// Engines are the connected engines. EnginesKnown is false while the
	// list may be incomplete (a new leader, before the replicas' reports
	// are all in).
	Engines      []EngineKeys
	EnginesKnown bool
	// BundleVersion and BundleKeyID describe the published bundle.
	BundleVersion uint64
	BundleKeyID   string
}

// Step is the outcome of a rotation step.
type Step struct {
	// Keyring is the new keyring; the same one when nothing changed.
	Keyring *Keyring
	Changed bool
	// Event names a change of phase: "started", "switched" or "retired".
	Event string
	// Waiting says what the rotation waits for; "" when nothing.
	Waiting string
}

// Rotate takes the next step of a key rotation (0004 §4.6): it starts one
// on request or when the key is due; publishes the next key and keeps
// signing with the active one until every connected engine trusts the
// next; then switches to it, keeping the previous key trusted until every
// connected engine runs a bundle signed by the new one; and retires the
// previous key. Each phase lasts at least in.Grace.
func Rotate(k *Keyring, in RotationInput) (Step, error) {
	wait := func(format string, args ...any) (Step, error) {
		return Step{Keyring: k, Waiting: fmt.Sprintf(format, args...)}, nil
	}
	nk := *k
	switch k.Phase() {
	case PhaseIdle:
		requested := in.Request != "" && in.Request != k.Request
		due := in.Interval > 0 && in.Now.Sub(k.ActiveSince) >= in.Interval
		if !requested && !due {
			return Step{Keyring: k}, nil
		}
		next, err := GenerateSigner()
		if err != nil {
			return Step{}, err
		}
		nk.Next, nk.PhaseSince = next, in.Now
		if requested {
			nk.Request = in.Request
		}
		return Step{Keyring: &nk, Changed: true, Event: "started"}, nil

	case PhasePublishing:
		if until := k.PhaseSince.Add(in.Grace); in.Now.Before(until) {
			return wait("key %s published; it signs at %s at the earliest, once mounted trust ConfigMaps are updated", k.Next.KeyID(), until.UTC().Format(time.RFC3339))
		}
		if !in.EnginesKnown {
			return wait("key %s published; waiting for every replica's engine report", k.Next.KeyID())
		}
		var missing []string
		for _, e := range in.Engines {
			if !slices.Contains(e.TrustedKeys, k.Next.KeyID()) {
				name := e.Name
				if len(e.TrustedKeys) == 0 {
					name += " (reports no keys: an engine older than key rotation, restart it with a current image)"
				}
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return wait("key %s published; %d/%d engines don't trust it yet: %s", k.Next.KeyID(), len(missing), len(in.Engines), names(missing))
		}
		nk.Previous, nk.Active, nk.Next = k.Active.Public(), k.Next, nil
		nk.PhaseSince, nk.ActiveSince, nk.SwitchVersion = in.Now, in.Now, 0
		return Step{Keyring: &nk, Changed: true, Event: "switched"}, nil

	default: // PhaseRetiring
		old := bundlekey.ID(k.Previous)
		if k.SwitchVersion == 0 {
			if in.BundleKeyID != k.Active.KeyID() {
				return wait("key %s signs; waiting for the bundle signed with it", k.Active.KeyID())
			}
			nk.SwitchVersion = in.BundleVersion
			return Step{Keyring: &nk, Changed: true, Waiting: fmt.Sprintf("key %s signs bundle %d", k.Active.KeyID(), in.BundleVersion)}, nil
		}
		if until := k.PhaseSince.Add(in.Grace); in.Now.Before(until) {
			return wait("key %s signs; the previous key %s is retired at %s at the earliest", k.Active.KeyID(), old, until.UTC().Format(time.RFC3339))
		}
		if !in.EnginesKnown {
			return wait("key %s signs; waiting for every replica's engine report to retire %s", k.Active.KeyID(), old)
		}
		var behind []string
		for _, e := range in.Engines {
			if e.Applied < k.SwitchVersion {
				behind = append(behind, e.Name)
			}
		}
		if len(behind) > 0 {
			return wait("key %s signs; %d/%d engines don't run a bundle signed with it (%d) yet: %s", k.Active.KeyID(), len(behind), len(in.Engines), k.SwitchVersion, names(behind))
		}
		nk.Previous, nk.PhaseSince, nk.SwitchVersion = nil, time.Time{}, 0
		return Step{Keyring: &nk, Changed: true, Event: "retired"}, nil
	}
}

// names lists the first few of many.
func names(list []string) string {
	const n = 3
	if len(list) > n {
		return strings.Join(list[:n], ", ") + fmt.Sprintf(" and %d more", len(list)-n)
	}
	return strings.Join(list, ", ")
}
