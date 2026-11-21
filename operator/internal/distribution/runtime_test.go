// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

// orderExporter records when it starts and stops, and whether the gRPC
// server still listened when it was stopped.
type orderExporter struct {
	addr                 string
	mu                   sync.Mutex
	started, stopped     bool
	listeningWhenStopped bool
}

func (o *orderExporter) Start() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.started = true
	return nil
}

func (o *orderExporter) Stop() {
	conn, err := net.DialTimeout("tcp", o.addr, time.Second)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = true
	if err == nil {
		o.listeningWhenStopped = true
		_ = conn.Close()
	}
}

func writeCert(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The server starts the exporter, and stops it only once the gRPC server
// has stopped: no event can arrive after the export's flush (design 0010
// §2.4).
func TestGRPCServerStopsTheExporterLast(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()
	ready := make(chan struct{})
	close(ready)
	exp := &orderExporter{addr: lis.Addr().String()}
	srv := &GRPCServer{Port: port, CertDir: dir, Ready: ready, Service: NewServer(NewStore(), NewTable(), fakeAuth{}, "r", logr.Discard()), Exporter: exp}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for srv.Check(nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the server didn't start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	exp.mu.Lock()
	if !exp.started || exp.stopped {
		t.Errorf("started %t, stopped %t while serving", exp.started, exp.stopped)
	}
	exp.mu.Unlock()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()
	if !exp.stopped || exp.listeningWhenStopped {
		t.Errorf("stopped %t, the gRPC server still listening when it was: %t", exp.stopped, exp.listeningWhenStopped)
	}
}
