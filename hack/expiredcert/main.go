// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command expiredcert writes a webhook certificate Secret's files that
// expired yesterday: ca.crt, ca.key, tls.crt and tls.key, as the
// operator's certificate rotator keeps them. The kind failure-mode suite
// (hack/kind/chaos.sh, #379) puts them in the Secret to check that the
// operator renews an expired certificate.
//
//	go run ./hack/expiredcert -dns inkwall-operator-webhook.inkwall-system.svc DIR
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dns := flag.String("dns", "localhost", "the serving certificate's DNS name")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: expiredcert [-dns NAME] DIR")
		os.Exit(2)
	}
	if err := write(flag.Arg(0), *dns, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// write writes the files into dir: a CA and a serving certificate, both
// valid from two days before now to one day before.
func write(dir, dns string, now time.Time) error {
	notBefore, notAfter := now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inkwall-operator-webhook-ca", Organization: []string{"Inkwall"}},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	for name, block := range map[string]*pem.Block{
		"ca.crt":  {Type: "CERTIFICATE", Bytes: caDER},
		"ca.key":  {Type: "EC PRIVATE KEY", Bytes: caKeyDER},
		"tls.crt": {Type: "CERTIFICATE", Bytes: leafDER},
		"tls.key": {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
	}
	return nil
}
