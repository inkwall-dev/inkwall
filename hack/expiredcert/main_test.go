// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The files make a key pair and a CA, both expired.
func TestWrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := write(dir, "webhook.example", now); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "tls.crt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(data)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !c.NotAfter.Before(now) {
			t.Errorf("%s expires %s, want before %s", name, c.NotAfter, now)
		}
	}
}
