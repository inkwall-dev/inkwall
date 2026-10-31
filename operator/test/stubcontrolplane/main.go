// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command stubcontrolplane runs the fake control plane (fakecontrolplane)
// as a server, for the end-to-end test on kind: it implements
// api/controlplane/v1 with its own CA, so this repository's tests never need
// a real control plane. Not for production.
//
// An admin listener serves the CA (/ca.crt), for the operator's trust
// bundle, and what the stub saw (/stats, JSON: calls, Hellos, heartbeats,
// policy acks and nacks, request counts per policy, and a summary of the
// newest ClusterState), for the
// test's checks. POST /snapshot sends a PolicySnapshot (Managed mode): the
// body is a YAML or JSON list of WAFPolicy, WAFRuleSet and
// ClusterWAFRuleSet objects ([] for none), and ?version=N its version
// (default: one more than the last).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
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
	States       int      `json:"states"`
	// Events counts the distinct security events received; EventUploads
	// the uploads (resends included).
	Events       int    `json:"events"`
	EventUploads int    `json:"eventUploads"`
	EventsDrop   uint64 `json:"eventsDropped"`
	// Acks are the snapshot versions applied; Nacks, those refused, as
	// "version: error; Kind namespace/name: error...".
	Acks  []uint64 `json:"acks"`
	Nacks []string `json:"nacks"`
	// Requests are the cluster's request counts, by policy.
	Requests map[string]requests `json:"requests"`
	// LastState summarizes the newest ClusterState.
	LastState *state `json:"lastState,omitempty"`
}

type requests struct {
	Allowed  uint64 `json:"allowed"`
	Denied   uint64 `json:"denied"`
	Detected uint64 `json:"detected"`
	// Timed counts the requests in the latency histogram.
	Timed uint64 `json:"timed"`
}

type state struct {
	// Objects are "Kind namespace/name"; Enforced, those whose Enforced
	// condition is True.
	Objects  []string `json:"objects"`
	Enforced []string `json:"enforced"`
	// Pods and PodsWithEngine are Traefik's.
	Pods           uint32 `json:"pods"`
	PodsWithEngine uint32 `json:"podsWithEngine"`
	Engines        int    `json:"engines"`
	BundleVersion  uint64 `json:"bundleVersion"`
}

func run() error {
	var hosts, tokens list
	listen := flag.String("listen", ":8443", "gRPC address (TLS)")
	admin := flag.String("admin-listen", ":8080", "address for /ca.crt and /stats")
	flag.Var(&hosts, "host", "a host name the server certificate is valid for (repeatable; the first is the endpoint)")
	flag.Var(&tokens, "token", "a valid one-time enrollment token (repeatable)")
	lifetime := flag.Duration("cert-lifetime", 24*time.Hour, "lifetime of the client certificates it issues")
	acceptEvents := flag.Bool("accept-events", false, "accept security events from the replicas (Welcome.accept_events)")
	acceptStats := flag.Bool("accept-request-stats", false, "accept request counts from the replicas (Welcome.accept_request_stats)")
	flag.Parse()

	srv, err := fakecontrolplane.StartWith(fakecontrolplane.Options{Addr: *listen, Hosts: hosts})
	if err != nil {
		return err
	}
	defer srv.Stop()
	srv.CertLifetime = *lifetime
	srv.SetAcceptEvents(*acceptEvents)
	srv.SetAcceptRequestStats(*acceptStats)
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
		out.States = len(st.States)
		out.Events, out.EventUploads, out.EventsDrop = st.Events, st.EventUploads, st.EventsDropped
		out.Acks, out.Nacks = append([]uint64{}, st.Acks...), []string{}
		for _, n := range st.Nacks {
			msg := fmt.Sprintf("%d: %s", n.GetVersion(), n.GetError())
			for _, o := range n.GetObjects() {
				msg += fmt.Sprintf("; %s %s/%s: %s", o.GetKind(), o.GetNamespace(), o.GetName(), o.GetError())
			}
			out.Nacks = append(out.Nacks, msg)
		}
		out.Requests = map[string]requests{}
		for id, p := range srv.RequestStats() {
			r := requests{Allowed: p.GetAllowed(), Denied: p.GetDenied(), Detected: p.GetDetected()}
			for _, n := range p.GetLatencyCounts() {
				r.Timed += n
			}
			out.Requests[id] = r
		}
		if n := len(st.States); n > 0 {
			last := st.States[n-1]
			ls := &state{Objects: []string{}, Enforced: []string{}, Engines: len(last.GetEngines()), BundleVersion: last.GetBundleVersion()}
			for _, o := range last.GetObjects() {
				name := fmt.Sprintf("%s %s/%s", o.GetKind(), o.GetNamespace(), o.GetName())
				ls.Objects = append(ls.Objects, name)
				for _, c := range o.GetConditions() {
					if c.GetType() == "Enforced" && c.GetStatus() == "True" {
						ls.Enforced = append(ls.Enforced, name)
					}
				}
			}
			for _, in := range last.GetIntegrations() {
				ls.Pods += in.GetPods()
				ls.PodsWithEngine += in.GetPodsWithEngine()
			}
			out.LastState = ls
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /snapshot", func(w http.ResponseWriter, r *http.Request) {
		snap, err := readSnapshot(r, srv.SnapshotVersion()+1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sent, err := srv.SendSnapshot(snap)
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadGateway)
		case !sent:
			http.Error(w, fmt.Sprintf("snapshot %d kept, but no primary stream is open: sent when the cluster connects", snap.GetVersion()), http.StatusAccepted)
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "snapshot "+strconv.FormatUint(snap.GetVersion(), 10)+" sent\n")
		}
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

// readSnapshot reads a PolicySnapshot from a YAML or JSON list of objects,
// with ?version=N or next as its version.
func readSnapshot(r *http.Request, next uint64) (*controlplanev1.PolicySnapshot, error) {
	version := next
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("version: %w", err)
		}
		version = n
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	js, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, err
	}
	var objs []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(js, &objs); err != nil {
		return nil, fmt.Errorf("want a list of objects: %w", err)
	}
	snap := &controlplanev1.PolicySnapshot{Version: version}
	for _, o := range objs {
		snap.Objects = append(snap.Objects, &controlplanev1.Object{
			ApiVersion: o.APIVersion, Kind: o.Kind, Namespace: o.Metadata.Namespace, Name: o.Metadata.Name,
			Labels: o.Metadata.Labels, Spec: o.Spec,
		})
	}
	return snap, nil
}
