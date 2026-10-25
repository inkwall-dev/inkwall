// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// fakeOperator serves BundleService: it sends what the test puts in bundles
// and records what engines send.
type fakeOperator struct {
	agentv1.UnimplementedBundleServiceServer
	bundles chan *bundlev1.SignedBundle
	// closeStream ends the current stream, to test reconnecting.
	closeStream chan struct{}

	mu       sync.Mutex
	hellos   []*agentv1.Hello
	tokens   []string
	acks     []uint64
	nacks    []*agentv1.Nack
	beats    int
	sawHello chan struct{}
}

func newFakeOperator() *fakeOperator {
	return &fakeOperator{
		bundles:     make(chan *bundlev1.SignedBundle, 10),
		closeStream: make(chan struct{}, 1),
		sawHello:    make(chan struct{}, 10),
	}
}

func (f *fakeOperator) Watch(stream agentv1.BundleService_WatchServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.hellos = append(f.hellos, first.GetHello())
	f.tokens = append(f.tokens, strings.Join(md.Get("authorization"), ","))
	f.mu.Unlock()
	f.sawHello <- struct{}{}
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			f.mu.Lock()
			switch x := m.GetMsg().(type) {
			case *agentv1.WatchRequest_Ack:
				f.acks = append(f.acks, x.Ack.GetBundleVersion())
			case *agentv1.WatchRequest_Nack:
				f.nacks = append(f.nacks, x.Nack)
			case *agentv1.WatchRequest_Heartbeat:
				f.beats++
			}
			f.mu.Unlock()
		}
	}()
	for {
		select {
		case b := <-f.bundles:
			if err := stream.Send(&agentv1.WatchResponse{Msg: &agentv1.WatchResponse_Bundle{Bundle: b}}); err != nil {
				return err
			}
		case <-f.closeStream:
			return errors.New("closed by the test")
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (f *fakeOperator) snapshot() (acks []uint64, nacks []*agentv1.Nack, hellos []*agentv1.Hello, tokens []string, beats int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.acks...), append([]*agentv1.Nack(nil), f.nacks...),
		append([]*agentv1.Hello(nil), f.hellos...), append([]string(nil), f.tokens...), f.beats
}

// env is a fake operator over TLS and the files an engine reads.
type env struct {
	op     *fakeOperator
	addr   string
	dir    string
	priv   ed25519.PrivateKey
	caFile string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := selfSigned(t)
	caFile := filepath.Join(dir, "ca.crt")
	writeFile(t, caFile, certPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	op := newFakeOperator()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	agentv1.RegisterBundleServiceServer(srv, op)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	writeFile(t, filepath.Join(dir, "ed25519.pub"), pub)
	writeFile(t, filepath.Join(dir, "token"), []byte("token-1\n"))
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	return &env{op: op, addr: "localhost:" + port, dir: dir, priv: priv, caFile: caFile}
}

func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// bundle returns a bundle with one policy blocking "attack" in any
// argument on shop.example.com, signed with key.
func bundle(t *testing.T, key ed25519.PrivateKey, version uint64, created time.Time, rule string) *bundlev1.SignedBundle {
	t.Helper()
	b := &bundlev1.Bundle{
		Version:     version,
		CreatedAt:   timestamppb.New(created),
		ContentHash: []byte(rule),
		Policies: []*bundlev1.Policy{{
			Id:       "shop/shop",
			Mode:     bundlev1.Mode_MODE_BLOCK,
			Routes:   []*bundlev1.RouteMatch{{Host: "shop.example.com", Path: &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}}},
			RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: "WAFRuleSet/shop/rules"}},
		}},
		RuleSets: []*bundlev1.RuleSet{{Id: "WAFRuleSet/shop/rules", Source: &bundlev1.RuleSet_Seclang{Seclang: rule}}},
	}
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return &bundlev1.SignedBundle{Bundle: raw, Signature: ed25519.Sign(key, raw), KeyId: "k1"}
}

const blockAttack = `SecRule ARGS "@contains attack" "id:100001,phase:2,deny,status:403,log"`

type counting struct{ n atomic.Int32 }

func (e *env) agent(t *testing.T, mutate func(*Config)) (*Agent, *policy.Holder, *counting) {
	t.Helper()
	holder := &policy.Holder{}
	compiles := &counting{}
	cfg := Config{
		Addr:          e.addr,
		CAFile:        e.caFile,
		TokenFile:     filepath.Join(e.dir, "token"),
		PublicKeyFile: filepath.Join(e.dir, "ed25519.pub"),
		CacheFile:     filepath.Join(e.dir, "bundle.pb"),
		EngineID:      "traefik-1",
		PodName:       "traefik-1",
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			compiles.n.Add(1)
			return policy.Compile(b, policy.Options{})
		},
		Holder:     holder,
		Admission:  pipeline.NewAdmission(4),
		Logger:     slog.New(slog.DiscardHandler),
		Heartbeat:  50 * time.Millisecond,
		MinBackoff: 20 * time.Millisecond,
		MaxBackoff: 100 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a, holder, compiles
}

func run(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func blocks(h *policy.Holder) bool {
	r := &request.Request{Method: "GET", Host: "shop.example.com", RawURI: "/?q=attack", Proto: "HTTP/1.1", Headers: http.Header{}}
	return h.Check(context.Background(), r).Action == pipeline.ActionDeny
}

func TestApplyAndAck(t *testing.T) {
	e := newEnv(t)
	a, holder, _ := e.agent(t, nil)
	run(t, a)
	<-e.op.sawHello
	if blocks(holder) {
		t.Fatal("blocking before any bundle")
	}
	e.op.bundles <- bundle(t, e.priv, 1, time.Now(), blockAttack)
	waitFor(t, "the ack", func() bool { acks, _, _, _, _ := e.op.snapshot(); return len(acks) == 1 && acks[0] == 1 })
	if !blocks(holder) || a.Version() != 1 {
		t.Fatalf("bundle not enforced (version %d)", a.Version())
	}
	_, _, hellos, tokens, _ := e.op.snapshot()
	if hellos[0].GetEngineId() != "traefik-1" || tokens[0] != "Bearer token-1" {
		t.Errorf("hello %v, token %q", hellos[0], tokens[0])
	}
	waitFor(t, "heartbeats", func() bool { _, _, _, _, beats := e.op.snapshot(); return beats >= 2 })
}

func TestRejections(t *testing.T) {
	e := newEnv(t)
	a, holder, compiles := e.agent(t, nil)
	run(t, a)
	<-e.op.sawHello
	now := time.Now()
	e.op.bundles <- bundle(t, e.priv, 5, now, blockAttack)
	waitFor(t, "v5", func() bool { return a.Version() == 5 })

	// A bad signature, an older bundle, rules that don't compile: each is
	// nacked, and v5 stays enforced.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	e.op.bundles <- bundle(t, other, 6, now, "SecMarker A")
	e.op.bundles <- bundle(t, e.priv, 4, now.Add(-time.Minute), "SecMarker B")
	e.op.bundles <- bundle(t, e.priv, 7, now, `SecRule ARGS "@nosuchop a" "id:100002,phase:1,deny"`)
	waitFor(t, "three nacks", func() bool { _, nacks, _, _, _ := e.op.snapshot(); return len(nacks) == 3 })
	_, nacks, _, _, _ := e.op.snapshot()
	for i, want := range []string{"bad signature", "older than the applied 5", "nosuchop"} {
		if !strings.Contains(nacks[i].GetError(), want) {
			t.Errorf("nack %d: %q, want %q", i, nacks[i].GetError(), want)
		}
	}
	if nacks[0].GetBundleVersion() != 0 {
		t.Error("the version of an unverified bundle was trusted")
	}
	if a.Version() != 5 || !blocks(holder) {
		t.Fatalf("a rejected bundle replaced v5 (now %d)", a.Version())
	}

	// The same content again, with a new version: adopted without
	// recompiling.
	before := compiles.n.Load()
	e.op.bundles <- bundle(t, e.priv, 8, now, blockAttack)
	waitFor(t, "v8", func() bool { return a.Version() == 8 })
	if compiles.n.Load() != before {
		t.Error("unchanged rules were recompiled")
	}

	// An older version created later: the operator started its sequence
	// again, and the bundle is applied.
	e.op.bundles <- bundle(t, e.priv, 1, now.Add(time.Minute), "SecMarker RESET")
	waitFor(t, "the restarted sequence", func() bool { return a.Version() == 1 })
	if blocks(holder) {
		t.Error("the new bundle's rules are not enforced")
	}
}

func TestCache(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, nil)
	run(t, a)
	<-e.op.sawHello
	e.op.bundles <- bundle(t, e.priv, 3, time.Now(), blockAttack)
	waitFor(t, "v3", func() bool { return a.Version() == 3 })
	waitFor(t, "the cache file", func() bool { _, err := os.Stat(filepath.Join(e.dir, "bundle.pb")); return err == nil })

	// A restarted engine, with the operator unreachable, enforces the
	// cached bundle at once.
	b, holder, _ := e.agent(t, func(c *Config) { c.Addr = "127.0.0.1:1" })
	run(t, b)
	waitFor(t, "the cached bundle", func() bool { return b.Version() == 3 })
	if !blocks(holder) {
		t.Fatal("the cached bundle is not enforced")
	}

	// A corrupt cache is ignored.
	writeFile(t, filepath.Join(e.dir, "bundle.pb"), []byte("garbage"))
	c, _, _ := e.agent(t, func(c *Config) { c.Addr = "127.0.0.1:1" })
	c.loadCache()
	if c.Version() != 0 {
		t.Fatal("a corrupt cache was applied")
	}
}

func TestReconnect(t *testing.T) {
	e := newEnv(t)
	a, _, _ := e.agent(t, nil)
	run(t, a)
	<-e.op.sawHello
	e.op.bundles <- bundle(t, e.priv, 2, time.Now(), blockAttack)
	waitFor(t, "v2", func() bool { return a.Version() == 2 })

	// The token rotates; the stream breaks; the engine reconnects with the
	// new token and says which bundle it runs.
	writeFile(t, filepath.Join(e.dir, "token"), []byte("token-2"))
	e.op.closeStream <- struct{}{}
	<-e.op.sawHello
	_, _, hellos, tokens, _ := e.op.snapshot()
	if len(hellos) != 2 || hellos[1].GetBundleVersion() != 2 || tokens[1] != "Bearer token-2" {
		t.Fatalf("reconnect: hellos %v, tokens %v", hellos, tokens)
	}
}

func TestNewErrors(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"no address", func(c *Config) { c.Addr = "" }},
		{"no engine ID", func(c *Config) { c.EngineID = "" }},
		{"missing key", func(c *Config) { c.PublicKeyFile = filepath.Join(e.dir, "nope") }},
		{"not a raw key", func(c *Config) { c.PublicKeyFile = e.caFile }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Addr: e.addr, CAFile: e.caFile, TokenFile: filepath.Join(e.dir, "token"),
				PublicKeyFile: filepath.Join(e.dir, "ed25519.pub"), EngineID: "e",
				Compile: func(*bundlev1.Bundle) (*policy.Set, error) { return nil, nil }, Holder: &policy.Holder{},
			}
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
