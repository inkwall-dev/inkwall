// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// certReloadInterval is how often the listener's certificate files are
// checked for a renewal (cert-manager, a Secret's volume).
const certReloadInterval = 10 * time.Second

// certificate is the proxy listener's certificate (--tls-cert, --tls-key),
// read again when the files change, so a renewed certificate is served
// without a restart. One that can't be read keeps the last.
type certificate struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
	mod     [2]time.Time
}

func loadCertificate(certFile, keyFile string) (*certificate, error) {
	c := &certificate{certFile: filepath.Clean(certFile), keyFile: filepath.Clean(keyFile)}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *certificate) load() error {
	var mod [2]time.Time
	for i, f := range []string{c.certFile, c.keyFile} {
		fi, err := os.Stat(f)
		if err != nil {
			return err
		}
		mod[i] = fi.ModTime()
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("--tls-cert, --tls-key: %w", err)
	}
	c.cert, c.mod = &cert, mod
	return nil
}

// get is tls.Config.GetCertificate.
func (c *certificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := time.Now(); now.Sub(c.checked) >= certReloadInterval {
		c.checked = now
		changed := false
		for i, f := range []string{c.certFile, c.keyFile} {
			if fi, err := os.Stat(f); err == nil && !fi.ModTime().Equal(c.mod[i]) {
				changed = true
			}
		}
		if changed {
			_ = c.load() // on an error, the last certificate stays
		}
	}
	return c.cert, nil
}

// tlsServer serves HTTP over TLS, with ALPN for HTTP/2 and HTTP/1.1.
type tlsServer struct{ *http.Server }

func (s tlsServer) Serve(l net.Listener) error { return s.ServeTLS(l, "", "") }

func (s tlsServer) Shutdown(ctx context.Context) error { return s.Server.Shutdown(ctx) }

// readCAs reads PEM certificates for --upstream-ca.
func readCAs(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("--upstream-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("--upstream-ca: no PEM certificate in " + path)
	}
	return pool, nil
}
