// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command stubcontrolplane runs the fake control plane (fakecontrolplane)
// as a server, for the end-to-end test on kind: it implements
// api/controlplane/v1 with its own CA, so this repository's tests never need
// a real control plane. Not for production.
//
// An admin listener serves the CA (/ca.crt), for the operator's trust
// bundle, and what the stub saw (/stats, JSON), for the test's checks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/inkwall-dev/inkwall/operator/test/fakecontrolplane"
)

func main() {
	if err := run(); err != nil {
		slog.Error("stub control plane", slog.Any("error", err))
		os.Exit(1)
	}
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// stats is /stats: what the stub saw.
type stats struct {
	EnrollCalls  int      `json:"enrollCalls"`
	ConnectCalls int      `json:"connectCalls"`
	Clusters     int      `json:"clusters"`
	Heartbeats   int      `json:"heartbeats"`
	Renewals     int      `json:"renewals"`
	Hellos       []string `json:"hellos"`
}

func run() error {
	var hosts, tokens list
	listen := flag.String("listen", ":8443", "gRPC address (TLS)")
	admin := flag.String("admin-listen", ":8080", "address for /ca.crt and /stats")
	flag.Var(&hosts, "host", "a host name the server certificate is valid for (repeatable; the first is the endpoint)")
	flag.Var(&tokens, "token", "a valid one-time enrollment token (repeatable)")
	lifetime := flag.Duration("cert-lifetime", 24*time.Hour, "lifetime of the client certificates it issues")
	flag.Parse()

	srv, err := fakecontrolplane.StartWith(fakecontrolplane.Options{Addr: *listen, Hosts: hosts})
	if err != nil {
		return err
	}
	defer srv.Stop()
	srv.CertLifetime = *lifetime
	for _, t := range tokens {
		srv.AddToken(t)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(srv.CAPEM())
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		st := srv.Stats()
		out := stats{EnrollCalls: st.EnrollCalls, ConnectCalls: st.ConnectCalls, Clusters: st.Clusters,
			Heartbeats: st.Heartbeats, Renewals: st.Renewals}
		for _, h := range st.Hellos {
			out.Hellos = append(out.Hellos, fmt.Sprintf("%s %s %s", h.GetRole(), h.GetMode(), h.GetClusterUid()))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	hs := &http.Server{Addr: *admin, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	slog.Info("stub control plane started", slog.String("endpoint", srv.Endpoint()), slog.String("admin", *admin))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}
