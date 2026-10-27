// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IdentitySecret holds the cluster's client certificate and key, in the
// operator's namespace: every replica reads it (their events streams use
// it), the leader writes it.
const IdentitySecret = "inkwall-control-plane-identity" // #nosec G101 -- the Secret's name, not a credential

// Keys of the identity Secret, besides tls.crt (the chain, PEM) and tls.key.
const (
	clusterIDKey = "cluster-id"
	// tokenAnnotation is the SHA-256 of the token the identity came from: a
	// rejected certificate waits for a different token.
	tokenAnnotation = "waf.inkwall.dev/enrollment-token-sha256" // #nosec G101 -- an annotation name, not a credential
)

// identity is the cluster's client certificate.
type identity struct {
	clusterID string
	cert      tls.Certificate
	notBefore time.Time
	notAfter  time.Time
	tokenHash string
}

// newKey generates the cluster's key: ECDSA P-256, as the contract allows.
func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// newCSR is a PKCS #10 request for key, DER; the control plane decides the
// identity, so the subject is empty.
func newCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

// newIdentity builds an identity from the certificates the control plane
// returned (DER, leaf first) and key, checking they match.
func newIdentity(clusterID string, certs [][]byte, key *ecdsa.PrivateKey, tokenHash string) (*identity, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the certificate is not for our key")
	}
	return &identity{
		clusterID: clusterID,
		cert:      tls.Certificate{Certificate: certs, PrivateKey: key, Leaf: leaf},
		notBefore: leaf.NotBefore,
		notAfter:  leaf.NotAfter,
		tokenHash: tokenHash,
	}, nil
}

// renewAt is when to renew: two thirds into the certificate's lifetime.
func (id *identity) renewAt() time.Time {
	return id.notBefore.Add(id.notAfter.Sub(id.notBefore) * 2 / 3)
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// loadIdentity reads the identity Secret; nil without one, or with one that
// can't be used.
func loadIdentity(ctx context.Context, c client.Reader, namespace string) (*identity, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: IdentitySecret}, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, fmt.Errorf("identity Secret: %w", err)
	}
	return &identity{
		clusterID: string(s.Data[clusterIDKey]),
		cert:      cert,
		notBefore: cert.Leaf.NotBefore,
		notAfter:  cert.Leaf.NotAfter,
		tokenHash: s.Annotations[tokenAnnotation],
	}, nil
}

// storeIdentity creates or replaces the identity Secret.
func storeIdentity(ctx context.Context, c client.Client, namespace string, id *identity) error {
	var chain []byte
	for _, der := range id.cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.cert.PrivateKey)
	if err != nil {
		return err
	}
	data := map[string][]byte{
		corev1.TLSCertKey:       chain,
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		clusterIDKey:            []byte(id.clusterID),
	}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: IdentitySecret}}
	err = c.Get(ctx, client.ObjectKeyFromObject(s), s)
	switch {
	case apierrors.IsNotFound(err):
		s.Type = corev1.SecretTypeTLS
		s.Labels = map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
		s.Annotations = map[string]string{tokenAnnotation: id.tokenHash}
		s.Data = data
		return c.Create(ctx, s)
	case err != nil:
		return err
	}
	s.Data = data
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[tokenAnnotation] = id.tokenHash
	return c.Update(ctx, s)
}

// deleteIdentity removes a certificate the control plane rejected.
func deleteIdentity(ctx context.Context, c client.Client, namespace string) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: IdentitySecret}}
	return client.IgnoreNotFound(c.Delete(ctx, s))
}
