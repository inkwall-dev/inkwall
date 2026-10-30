// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

// SecretBundleKey is the key of the bundle Secret that holds the
// gzip-compressed, serialized SignedBundle (the operator writes it), when
// it fits in one Secret.
const SecretBundleKey = bundlesecret.BundleKey

// Limits on what is read from the API server: the operator keeps each
// Secret under 1 MiB, so these are generous.
const (
	maxSecretBytes = 4 << 20
	maxBundleBytes = bundlesecret.MaxBundleBytes
	secretTimeout  = 10 * time.Second
)

// SecretSource reads the operator's bundle Secret through the Kubernetes API
// (0004 §4.6). The engine uses it when it has no bundle: a new pod with no
// cache, while the operator is unreachable. The bundle's signature is checked
// like any other's, so the Secret is no more trusted than the operator's
// stream. Reading it takes get on the Secret, the permission the operator
// already authorizes engines by, and on its chunks, for a bundle too large
// for one Secret (bundlesecret).
type SecretSource struct {
	Namespace string
	Name      string
	// APIServer is the API server's URL; empty: the in-cluster address,
	// from KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT.
	APIServer string
	// CAFile verifies the API server's certificate.
	CAFile string
	// TokenFile holds a ServiceAccount token for the API server's own
	// audience (not the operator's), re-read on every request.
	TokenFile string
}

func (s *SecretSource) server() (string, error) {
	if s.APIServer != "" {
		return strings.TrimSuffix(s.APIServer, "/"), nil
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", errors.New("not in a cluster: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// fetch reads the signed bundle from the Secret, and its chunks.
func (s *SecretSource) fetch(ctx context.Context) (*bundlev1.SignedBundle, error) {
	server, err := s.server()
	if err != nil {
		return nil, err
	}
	token, err := os.ReadFile(filepath.Clean(s.TokenFile))
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	ca, err := os.ReadFile(filepath.Clean(s.CAFile))
	if err != nil {
		return nil, fmt.Errorf("API server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("API server CA %s: no PEM certificate", s.CAFile)
	}
	client := &http.Client{
		Timeout: secretTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
	defer client.CloseIdleConnections()
	get := func(name string) (map[string][]byte, int, error) {
		return getSecret(ctx, client, server, string(bytes.TrimSpace(token)), s.Namespace, name)
	}

	data, _, err := get(s.Name)
	if err != nil {
		return nil, err
	}
	gz := data[SecretBundleKey]
	if len(gz) == 0 && len(data[bundlesecret.ManifestKey]) > 0 {
		m, err := bundlesecret.ParseManifest(s.Name, data[bundlesecret.ManifestKey])
		if err != nil {
			return nil, fmt.Errorf("secret %s/%s: %w", s.Namespace, s.Name, err)
		}
		gz, err = bundlesecret.Join(m, func(name string) ([]byte, error) {
			chunk, status, err := get(name)
			if status == http.StatusNotFound {
				// Replaced since the manifest was read.
				return nil, fmt.Errorf("%w: %w", bundlesecret.ErrIncomplete, err)
			}
			return chunk[bundlesecret.ChunkKey], err
		})
		if err != nil {
			return nil, fmt.Errorf("secret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	if len(gz) == 0 {
		return nil, fmt.Errorf("secret %s/%s has no %s yet", s.Namespace, s.Name, SecretBundleKey)
	}
	return decodeSecretBundle(gz)
}

// getSecret reads a Secret's data, and the response status.
func getSecret(ctx context.Context, client *http.Client, server, token, namespace, name string) (map[string][]byte, int, error) {
	u := server + "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("secret %s/%s: %s: %s", namespace, name, resp.Status, apiMessage(body))
	}
	if len(body) > maxSecretBytes {
		return nil, resp.StatusCode, fmt.Errorf("secret %s/%s: over %d bytes", namespace, name, maxSecretBytes)
	}
	var secret struct {
		// encoding/json decodes the base64 of the API's data fields.
		Data map[string][]byte `json:"data"`
	}
	if err := json.Unmarshal(body, &secret); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("secret %s/%s: %w", namespace, name, err)
	}
	return secret.Data, resp.StatusCode, nil
}

func decodeSecretBundle(data []byte) (*bundlev1.SignedBundle, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompress the bundle: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompress the bundle: %w", err)
	}
	if len(raw) > maxBundleBytes {
		return nil, fmt.Errorf("bundle over %d bytes decompressed", maxBundleBytes)
	}
	var signed bundlev1.SignedBundle
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return nil, fmt.Errorf("decode the bundle: %w", err)
	}
	return &signed, nil
}

// apiMessage returns the message of a Kubernetes Status response, or the
// start of the body.
func apiMessage(body []byte) string {
	var status struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &status) == nil && status.Message != "" {
		return status.Message
	}
	const n = 200
	if len(body) > n {
		body = body[:n]
	}
	return strings.TrimSpace(string(body))
}
