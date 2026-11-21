// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command eventsink is a small HTTP intake for exported security events,
// for the export's end-to-end test on kind (hack/kind/export-e2e.sh), in
// the style of stubcontrolplane: it records each POST's events (JSON
// Lines or a JSON array, gzip or not) with the headers the test checks,
// and can be told how to answer. Not for production.
//
// The intake listens on --addr (POST any path). An admin listener on
// --admin-addr serves what it saw (GET /stats, JSON: the requests, each
// with its path, its headers of interest and its events) and takes the
// next answers: POST /mode?status=503, ?status=429&retryAfter=2, ?hang=1
// (requests wait until the next mode), ?fail=0.5 (that share of the
// requests, at random, answered 503), or ?status=200 (the default).
// POST /reset forgets what it saw. It keeps the newest --keep requests, of
// --keep-bytes of bodies at most, and
// counts them all (accepted, acceptedEvents: those answered 2xx), so a
// soak can run it for a day.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("event sink", slog.Any("error", err))
		os.Exit(1)
	}
}

// request is one POST the sink took.
type request struct {
	Path        string            `json:"path"`
	ContentType string            `json:"contentType"`
	Encoding    string            `json:"encoding"`
	Headers     map[string]string `json:"headers"`
	Events      []map[string]any  `json:"events"`
	size        int
	Status      int `json:"status"`
}

type sink struct {
	mu         sync.Mutex
	requests   []request
	keep       int
	keepBytes  int
	kept       int // the bytes of the bodies kept
	received   int
	accepted   int
	acceptedEv int
	failRatio  float64
	status     int
	retryAfter string
	hang       chan struct{} // non-nil: requests wait for it to close
	// headers are the request headers recorded.
	headers []string
}

const maxBody = 16 << 20

func (s *sink) intake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	hang, status, retryAfter := s.hang, s.status, s.retryAfter
	s.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
		s.mu.Lock()
		status, retryAfter = s.status, s.retryAfter
		s.mu.Unlock()
	}
	body := io.LimitReader(r.Body, maxBody)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		body = io.LimitReader(zr, maxBody)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	req := request{Path: r.URL.Path, ContentType: r.Header.Get("Content-Type"), Encoding: r.Header.Get("Content-Encoding"), Headers: map[string]string{}, Status: status}
	for _, h := range s.headers {
		if v := r.Header.Get(h); v != "" {
			req.Headers[h] = v
		}
	}
	if req.ContentType == "application/json" {
		if err := json.Unmarshal(raw, &req.Events); err != nil {
			http.Error(w, "not a JSON array", http.StatusBadRequest)
			return
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(nil, maxBody)
		for sc.Scan() {
			var ev map[string]any
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				http.Error(w, "a line isn't JSON", http.StatusBadRequest)
				return
			}
			req.Events = append(req.Events, ev)
		}
	}
	s.mu.Lock()
	if s.failRatio > 0 && mrand.Float64() < s.failRatio { // #nosec G404 -- a test's coin
		status, req.Status = http.StatusServiceUnavailable, http.StatusServiceUnavailable
	}
	s.received++
	if status >= 200 && status < 300 {
		s.accepted++
		s.acceptedEv += len(req.Events)
	}
	s.requests = append(s.requests, req)
	req.size = len(raw)
	s.kept += req.size
	for len(s.requests) > s.keep || (s.kept > s.keepBytes && len(s.requests) > 1) {
		s.kept -= s.requests[0].size
		s.requests = s.requests[1:]
	}
	s.mu.Unlock()
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(status)
}

func (s *sink) admin() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"requests": s.requests, "received": s.received, "accepted": s.accepted, "acceptedEvents": s.acceptedEv})
	})
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.requests, s.kept, s.received, s.accepted, s.acceptedEv = nil, 0, 0, 0, 0
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /mode", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		status := http.StatusOK
		if v := q.Get("status"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 200 || n > 599 {
				http.Error(w, "bad status", http.StatusBadRequest)
				return
			}
			status = n
		}
		s.mu.Lock()
		if s.hang != nil {
			close(s.hang)
			s.hang = nil
		}
		s.status, s.retryAfter, s.failRatio = status, q.Get("retryAfter"), 0
		if v := q.Get("fail"); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || f > 1 {
				s.mu.Unlock()
				http.Error(w, "bad fail ratio", http.StatusBadRequest)
				return
			}
			s.failRatio = f
		}
		if q.Get("hang") == "1" {
			s.hang = make(chan struct{})
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// newCertificate makes a CA and a serving certificate for names from it.
func newCertificate(names []string) (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "eventsink CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "eventsink"}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

type list []string

func (l *list) String() string     { return "" }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func run() error {
	addr := flag.String("addr", ":8080", "the intake's address (plain HTTP)")
	tlsAddr := flag.String("tls-addr", ":8443", "the intake's address over TLS, with a certificate for --dns-name from the sink's own CA (served on the admin listener at /ca.crt)")
	adminAddr := flag.String("admin-addr", ":8081", "the admin listener's address")
	var headers, names list
	flag.Var(&headers, "header", "a request header to record (repeatable)")
	flag.Var(&names, "dns-name", "a name of the TLS certificate (repeatable)")
	keep := flag.Int("keep", 1000, "the newest requests kept for /stats")
	keepBytes := flag.Int("keep-bytes", 32<<20, "the most bytes of request bodies kept for /stats")
	flag.Parse()
	s := &sink{status: http.StatusOK, headers: headers, keep: max(*keep, 1), keepBytes: max(*keepBytes, 1)}
	cert, caPEM, err := newCertificate(names)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	admin := s.admin()
	adminMux := http.NewServeMux()
	adminMux.Handle("/", admin)
	adminMux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(caPEM) })
	plain := &http.Server{Addr: *addr, Handler: http.HandlerFunc(s.intake), ReadHeaderTimeout: 10 * time.Second}
	secure := &http.Server{Addr: *tlsAddr, Handler: http.HandlerFunc(s.intake), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	adminSrv := &http.Server{Addr: *adminAddr, Handler: adminMux, ReadHeaderTimeout: 10 * time.Second}
	servers := []*http.Server{plain, secure, adminSrv}
	errc := make(chan error, len(servers))
	go func() { errc <- plain.ListenAndServe() }()
	go func() { errc <- secure.ListenAndServeTLS("", "") }()
	go func() { errc <- adminSrv.ListenAndServe() }()
	slog.Info("event sink listening", slog.String("addr", *addr), slog.String("admin", *adminAddr))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var errs []error
	for _, srv := range servers {
		errs = append(errs, srv.Shutdown(sctx))
	}
	return errors.Join(errs...)
}
