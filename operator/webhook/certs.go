// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// The rotator reads and writes its Secret, and injects the CA into the
// webhook configuration.
//
// +kubebuilder:rbac:groups="",namespace=inkwall-system,resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;update;patch

// CertOptions configures the webhook's serving certificate.
type CertOptions struct {
	// Secret holds the CA and the serving certificate, shared by every
	// replica.
	Secret types.NamespacedName
	// CertDir is where the certificate files are written for the webhook
	// server.
	CertDir string
	// DNSNames are the names the certificate is valid for: the webhook
	// Service's, and the distribution Service's.
	DNSNames []string
	// InjectWebhooks injects the CA into the validating webhook
	// configuration; off when the webhook is disabled.
	InjectWebhooks bool
}

// ServiceDNSNames returns the names of a Service, for CertOptions.DNSNames.
func ServiceDNSNames(service, namespace string) []string {
	return []string{
		service + "." + namespace + ".svc",
		service + "." + namespace + ".svc.cluster.local",
		service + "." + namespace,
		service,
	}
}

// EnsureCertSecret creates the empty certificate Secret if it doesn't
// exist; the rotator only fills an existing one. It runs before the
// manager starts, so it uses a direct client.
func EnsureCertSecret(ctx context.Context, c client.Client, key types.NamespacedName) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"},
		},
	}
	if err := c.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the webhook certificate Secret %s: %w", key, err)
	}
	return nil
}

// AddCertRotator keeps a self-signed CA and serving certificate in the
// Secret, writes the certificate to CertDir and injects the CA into the
// validating webhook configuration, renewing them before they expire. ready
// is closed once the certificate files are in place and the CA is
// injected. It runs on every replica, so each one can serve; the replicas
// share the Secret. The Secret must exist (EnsureCertSecret).
func AddCertRotator(mgr manager.Manager, o CertOptions, ready chan struct{}) error {
	// The rotator only writes the Secret and expects it mounted at CertDir.
	// Copying it instead means no volume to configure, and no wait for the
	// kubelet to update the mount, which takes up to a minute or more.
	if err := mgr.Add(&certFileSync{reader: mgr.GetAPIReader(), secret: o.Secret, dir: o.CertDir}); err != nil {
		return err
	}
	var webhooks []rotator.WebhookInfo
	if o.InjectWebhooks {
		webhooks = []rotator.WebhookInfo{{Name: ValidatingConfigName, Type: rotator.Validating}}
	}
	return rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey:             o.Secret,
		CertDir:               o.CertDir,
		CAName:                "inkwall-operator-webhook-ca",
		CAOrganization:        "Inkwall",
		DNSName:               o.DNSNames[0],
		ExtraDNSNames:         o.DNSNames[1:],
		IsReady:               ready,
		Webhooks:              webhooks,
		FieldOwner:            "inkwall-operator",
		RequireLeaderElection: false,
		// Renew well before expiry, and check often enough to notice.
		CaCertDuration:         10 * 365 * 24 * time.Hour,
		ServerCertDuration:     365 * 24 * time.Hour,
		LookaheadInterval:      90 * 24 * time.Hour,
		RotationCheckFrequency: 12 * time.Hour,
	})
}

// certFileSync copies the serving certificate from the Secret to the
// directory the webhook server reads it from, which reloads it on change.
type certFileSync struct {
	reader  client.Reader
	secret  types.NamespacedName
	dir     string
	written []byte
}

// The certificate changes once a year or less: check often until it is
// there, then rarely.
const (
	certPollUntilWritten = 500 * time.Millisecond
	certPollAfter        = time.Minute
)

func (s *certFileSync) Start(ctx context.Context) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	for {
		if err := s.sync(ctx); err != nil {
			return err
		}
		wait := certPollUntilWritten
		if s.written != nil {
			wait = certPollAfter
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (*certFileSync) NeedLeaderElection() bool { return false }

func (s *certFileSync) sync(ctx context.Context) error {
	var secret corev1.Secret
	if err := s.reader.Get(ctx, s.secret, &secret); err != nil {
		// Not there yet, or the API server is briefly unavailable: the
		// webhook keeps its current certificate until the next check.
		return nil
	}
	crt, key := secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]
	if len(crt) == 0 || len(key) == 0 || bytes.Equal(crt, s.written) {
		return nil
	}
	// The key first: the server reloads when the certificate changes and
	// then needs the matching key.
	if err := writeFile(filepath.Join(s.dir, corev1.TLSPrivateKeyKey), key); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(s.dir, corev1.TLSCertKey), crt); err != nil {
		return err
	}
	s.written = crt
	return nil
}

// writeFile replaces a file atomically, so a reader never sees half of it.
func writeFile(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
