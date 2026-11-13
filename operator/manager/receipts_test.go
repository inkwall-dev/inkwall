// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/test/fakeengine"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// observeProbes runs the pods ("namespace/name") as Envoy in observability
// mode for the test's prober (#475): each one's engine keeps the receipts
// of the probes it gets, and an engine connected to the operator as that
// pod reports them with its heartbeats, as the engine's agent does. stop
// (also run at the end of the test) disconnects them and lets the prober
// answer as in Block mode again.
func observeProbes(ctx context.Context, t *testing.T, c client.Client, pods ...string) (stop func()) {
	t.Helper()
	var certs, keys corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "inkwall-operator-webhook-tls"}, &certs); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certs.Data["ca.crt"]) {
		t.Fatal("no CA in the certificate Secret")
	}
	_, port, _ := net.SplitHostPort(distAddr)
	// The ServiceAccount testDistribution grants the bundle Secret to.
	tok := token(ctx, t, "edge", "traefik")
	ectx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, pod := range pods {
		receipts := &haproxyprobe.Receipts{}
		observedPods.Store(pod, receipts)
		ns, name, _ := strings.Cut(pod, "/")
		e := &fakeengine.Engine{
			ID: name + "-engine", PodNamespace: ns, PodName: name,
			Addr:          "localhost:" + port,
			TLS:           &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			Token:         tok,
			PublicKeys:    []ed25519.PublicKey{keys.Data[bundle.PublicKeyKey]},
			Heartbeat:     200 * time.Millisecond,
			ProbeReceipts: receipts.Recent,
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = e.Run(ectx) }()
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
			for _, pod := range pods {
				observedPods.Delete(pod)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}
