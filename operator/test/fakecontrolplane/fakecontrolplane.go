// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package fakecontrolplane is a control plane that implements
// api/controlplane/v1 for tests: enrollment with one-time tokens, client
// certificates from its own CA, and the Connect stream. It records what the
// operator sends and can be told to fail. It is not a control plane: no
// storage, no tenants.
package fakecontrolplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // the operator compresses
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// Server is a fake control plane.
type Server struct {
	controlplanev1.UnimplementedControlPlaneServiceServer

	// CertLifetime is the lifetime of the client certificates it issues.
	CertLifetime time.Duration
	// HeartbeatInterval is sent in Welcome.
	HeartbeatInterval time.Duration
	// AcceptEvents is sent in Welcome: whether replicas send events.
	AcceptEvents bool

	ca     *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
	server tls.Certificate
	grpc   *grpc.Server
	addr   string
	hosts  []string

	mu sync.Mutex
	// tokens: unused (false) or burned (true).
	tokens map[string]bool
	// enrolled remembers the certificate issued for a token, by the
	// public key's hash, for idempotent retries.
	enrolled map[string]enrollment
	// connectErr, when set, ends every Connect with it.
	connectErr error
	// dropEnrollResponses drops the response of the next n Enroll calls
	// after issuing the certificate, as a lost response would.
	dropEnrollResponses int

	enrollCalls  int
	connectCalls int
	hellos       []*controlplanev1.Hello
	states       []*controlplanev1.ClusterState
	// events are the security events stored, by ID (resends dedup);
	// uploads, the (buffer, sequence) pairs seen, so dropped counts once.
	events        map[string]*eventsv1.SecurityEvent
	uploads       map[string]bool
	eventsDropped uint64
	eventUploads  int
	// primary sends on the open primary stream, for Resync; primaryID
	// tells which stream that is.
	primary    func(*controlplanev1.ConnectResponse) error
	primaryID  uint64
	heartbeats int
	renewals   int
	clusters   int
}

type enrollment struct {
	keyHash [32]byte
	resp    *controlplanev1.EnrollResponse
}

// Options configure a server.
type Options struct {
	// Addr to listen on; default a random local port.
	Addr string
	// Hosts its server certificate is valid for, the first one in
	// Endpoint; default localhost and 127.0.0.1.
	Hosts []string
}

// Start serves on a random local port until Stop.
func Start() (*Server, error) { return StartWith(Options{}) }

// StartWith serves as configured until Stop.
func StartWith(o Options) (*Server, error) {
	if o.Addr == "" {
		o.Addr = "127.0.0.1:0"
	}
	if len(o.Hosts) == 0 {
		o.Hosts = []string{"localhost", "127.0.0.1"}
	}
	s := &Server{
		hosts:             o.Hosts,
		CertLifetime:      24 * time.Hour,
		HeartbeatInterval: time.Second,
		tokens:            map[string]bool{},
		enrolled:          map[string]enrollment{},
		events:            map[string]*eventsv1.SecurityEvent{},
		uploads:           map[string]bool{},
	}
	if err := s.newCA(); err != nil {
		return nil, err
	}
	lis, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	s.addr = lis.Addr().String()
	s.grpc = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{s.server},
		// The certificate is checked in the RPC, not in the handshake, so a
		// bad one gets UNAUTHENTICATED (the contract); Enroll has none.
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	})))
	controlplanev1.RegisterControlPlaneServiceServer(s.grpc, s)
	go func() { _ = s.grpc.Serve(lis) }()
	return s, nil
}

// Stop stops serving.
func (s *Server) Stop() { s.grpc.Stop() }

// Endpoint is the address for InkwallConfig.spec.controlPlane.endpoint.
func (s *Server) Endpoint() string {
	return "grpcs://" + net.JoinHostPort(s.hosts[0], portOf(s.addr))
}

// CAPEM is the CA that signs the server and client certificates.
func (s *Server) CAPEM() []byte { return s.caPEM }

// AddToken makes a one-time enrollment token valid.
func (s *Server) AddToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = false
}

// FailConnect ends every Connect with err (a gRPC status), or stops
// failing with nil.
func (s *Server) FailConnect(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectErr = err
}

// DropEnrollResponses drops the responses of the next n Enroll calls.
func (s *Server) DropEnrollResponses(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropEnrollResponses = n
}

// Stats is what the server saw.
type Stats struct {
	EnrollCalls  int
	ConnectCalls int
	Hellos       []*controlplanev1.Hello
	// States are the ClusterStates received, oldest first.
	States     []*controlplanev1.ClusterState
	Heartbeats int
	// Events counts the distinct events stored; EventUploads the uploads
	// received (resends included); EventsDropped what replicas reported
	// dropping, once per buffer and sequence.
	Events        int
	EventUploads  int
	EventsDropped uint64
	Renewals      int
	// Clusters is how many distinct clusters enrolled.
	Clusters int
}

// Stats returns what the server saw so far.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{EnrollCalls: s.enrollCalls, ConnectCalls: s.connectCalls, Hellos: append([]*controlplanev1.Hello(nil), s.hellos...),
		States: append([]*controlplanev1.ClusterState(nil), s.states...),
		Events: len(s.events), EventUploads: s.eventUploads, EventsDropped: s.eventsDropped, Heartbeats: s.heartbeats, Renewals: s.renewals, Clusters: s.clusters}
}

// Resync asks the cluster on the open primary stream for a full
// ClusterState, and reports whether one was open.
func (s *Server) Resync() (bool, error) {
	s.mu.Lock()
	send := s.primary
	s.mu.Unlock()
	if send == nil {
		return false, nil
	}
	return true, send(&controlplanev1.ConnectResponse{Msg: &controlplanev1.ConnectResponse_Directive{Directive: &controlplanev1.Directive{
		Action: &controlplanev1.Directive_Resync{Resync: &controlplanev1.Resync{}},
	}}})
}

// Events returns the distinct events stored, in no order.
func (s *Server) Events() []*eventsv1.SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*eventsv1.SecurityEvent, 0, len(s.events))
	for _, ev := range s.events {
		out = append(out, ev)
	}
	return out
}

// SetAcceptEvents changes what the next Welcome says.
func (s *Server) SetAcceptEvents(accept bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AcceptEvents = accept
}

// Enroll implements the contract: the first call burns the token; a retry
// with the same token and public key gets the same certificate.
func (s *Server) Enroll(_ context.Context, req *controlplanev1.EnrollRequest) (*controlplanev1.EnrollResponse, error) {
	csr, keyHash, err := parseCSR(req.GetCsr())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollCalls++
	burned, known := s.tokens[req.GetToken()]
	if !known {
		return nil, status.Error(codes.PermissionDenied, "unknown enrollment token")
	}
	if burned {
		e, ok := s.enrolled[req.GetToken()]
		if !ok || e.keyHash != keyHash {
			return nil, status.Error(codes.PermissionDenied, "enrollment token already used")
		}
		return e.resp, nil
	}
	s.tokens[req.GetToken()] = true
	s.clusters++
	clusterID := fmt.Sprintf("cluster-%d", s.clusters)
	resp, err := s.issue(clusterID, csr)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.enrolled[req.GetToken()] = enrollment{keyHash: keyHash, resp: resp}
	if s.dropEnrollResponses > 0 {
		s.dropEnrollResponses--
		return nil, status.Error(codes.Unavailable, "response lost")
	}
	return resp, nil
}

// Connect implements the stream: Hello first, then Welcome; ClusterState,
// heartbeats and certificate renewal.
func (s *Server) Connect(stream controlplanev1.ControlPlaneService_ConnectServer) error {
	clusterID, err := s.clusterOf(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	s.mu.Lock()
	s.connectCalls++
	failure := s.connectErr
	s.mu.Unlock()
	if failure != nil {
		return failure
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "Hello must come first")
	}
	// Sends come from this goroutine and from Resync.
	var sendMu sync.Mutex
	send := func(m *controlplanev1.ConnectResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}
	s.mu.Lock()
	s.hellos = append(s.hellos, hello)
	accept := s.AcceptEvents
	if hello.GetRole() == controlplanev1.StreamRole_STREAM_ROLE_PRIMARY {
		// The newer primary stream wins.
		s.primaryID++
		id := s.primaryID
		s.primary = send
		defer func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.primaryID == id {
				s.primary = nil
			}
		}()
	}
	s.mu.Unlock()
	if err := send(&controlplanev1.ConnectResponse{Msg: &controlplanev1.ConnectResponse_Welcome{Welcome: &controlplanev1.Welcome{
		HeartbeatInterval: durationpb.New(s.HeartbeatInterval), AcceptEvents: accept,
	}}}); err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *controlplanev1.ConnectRequest_ClusterState:
			if hello.GetRole() != controlplanev1.StreamRole_STREAM_ROLE_PRIMARY {
				return status.Error(codes.FailedPrecondition, "ClusterState on a non-primary stream")
			}
			s.mu.Lock()
			s.states = append(s.states, m.ClusterState)
			s.mu.Unlock()
		case *controlplanev1.ConnectRequest_Events:
			if hello.GetRole() != controlplanev1.StreamRole_STREAM_ROLE_EVENTS {
				return status.Error(codes.FailedPrecondition, "EventUpload on a non-events stream")
			}
			up := m.Events
			s.mu.Lock()
			if !s.AcceptEvents {
				s.mu.Unlock()
				return status.Error(codes.FailedPrecondition, "events are not accepted")
			}
			s.eventUploads++
			key := fmt.Sprintf("%s/%d", up.GetBufferId(), up.GetSequence())
			if !s.uploads[key] {
				s.uploads[key] = true
				s.eventsDropped += up.GetBatch().GetDropped()
			}
			for _, ev := range up.GetBatch().GetEvents() {
				s.events[ev.GetEventId()] = ev
			}
			s.mu.Unlock()
			if err := send(&controlplanev1.ConnectResponse{Msg: &controlplanev1.ConnectResponse_EventsAck{EventsAck: &controlplanev1.EventsAck{
				BufferId: up.GetBufferId(), Sequence: up.GetSequence(),
			}}}); err != nil {
				return err
			}
		case *controlplanev1.ConnectRequest_Heartbeat:
			s.mu.Lock()
			s.heartbeats++
			s.mu.Unlock()
		case *controlplanev1.ConnectRequest_RenewCertificate:
			if hello.GetRole() != controlplanev1.StreamRole_STREAM_ROLE_PRIMARY {
				return status.Error(codes.FailedPrecondition, "renewal on a non-primary stream")
			}
			csr, _, err := parseCSR(m.RenewCertificate.GetCsr())
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
			s.mu.Lock()
			resp, err := s.issue(clusterID, csr)
			s.renewals++
			s.mu.Unlock()
			if err != nil {
				return status.Error(codes.Internal, err.Error())
			}
			if err := send(&controlplanev1.ConnectResponse{Msg: &controlplanev1.ConnectResponse_Certificate{Certificate: &controlplanev1.Certificate{
				Certificates: resp.GetCertificates(), NotAfter: resp.GetNotAfter(),
			}}}); err != nil {
				return err
			}
		}
	}
}

// issue signs a client certificate for csr, with the cluster ID as its
// common name.
func (s *Server) issue(clusterID string, csr *x509.CertificateRequest) (*controlplanev1.EnrollResponse, error) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clusterID},
		NotBefore:    now.Add(-time.Second),
		NotAfter:     now.Add(s.CertLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	return &controlplanev1.EnrollResponse{
		ClusterId:    clusterID,
		Certificates: [][]byte{der},
		NotAfter:     timestamppb.New(tmpl.NotAfter),
	}, nil
}

func parseCSR(der []byte) (*x509.CertificateRequest, [32]byte, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, [32]byte{}, fmt.Errorf("CSR signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, [32]byte{}, errors.New("ECDSA keys must be P-256")
		}
	case ed25519.PublicKey:
	default:
		return nil, [32]byte{}, fmt.Errorf("key type %T: want ECDSA P-256 or Ed25519", k)
	}
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return csr, sha256.Sum256(pub), nil
}

// clusterOf verifies the client certificate against the CA, and returns
// the cluster it names.
func (s *Server) clusterOf(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.ca)
	inter := x509.NewCertPool()
	for _, c := range info.State.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	leaf := info.State.PeerCertificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("client certificate: %w", err)
	}
	return leaf.Subject.CommonName, nil
}

func (s *Server) newCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake control plane CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	s.ca, _ = x509.ParseCertificate(der)
	s.caKey = key
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	skey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var dns []string
	var ips []net.IP
	for _, h := range s.hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	stmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: s.hosts[0]},
		DNSNames:     dns,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	sder, err := x509.CreateCertificate(rand.Reader, stmpl, s.ca, &skey.PublicKey, key)
	if err != nil {
		return err
	}
	s.server = tls.Certificate{Certificate: [][]byte{sder}, PrivateKey: skey}
	return nil
}

func portOf(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}
