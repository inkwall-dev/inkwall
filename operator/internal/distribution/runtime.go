// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
)

// Each replica publishes its engines in a ConfigMap in its namespace.
//
// +kubebuilder:rbac:groups="",namespace=inkwall-system,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// BundleSource loads the bundle Secret into the Store on every replica.
type BundleSource struct {
	Client    client.Client
	Namespace string
	Store     *Store
}

// SetupWithManager registers the source with mgr.
func (b *BundleSource) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("bundle-source").
		For(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetNamespace() == b.Namespace && o.GetName() == bundle.BundleSecret
		}))).
		// Every replica serves engines, not only the leader.
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Complete(b)
}

// Reconcile loads the current bundle.
func (b *BundleSource) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var s corev1.Secret
	if err := b.Client.Get(ctx, req.NamespacedName, &s); err != nil {
		// Deleted: engines keep the bundle they have until the builder
		// writes a new one.
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	signed, err := bundle.Read(ctx, b.Client, &s)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("bundle Secret: %w", err)
	}
	var bun bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &bun); err != nil {
		return reconcile.Result{}, fmt.Errorf("bundle Secret: %w", err)
	}
	b.Store.Set(signed, bun.GetVersion())
	bundleVersion.Set(float64(bun.GetVersion()))
	bundleBytes.Set(float64(bundle.CompressedSize(&s)))
	log.FromContext(ctx).V(1).Info("serving bundle", "version", bun.GetVersion())
	return reconcile.Result{}, nil
}

// GRPCServer serves the BundleService over TLS, with the certificate in
// CertDir (the webhook's), once Ready is closed.
type GRPCServer struct {
	Port    int
	CertDir string
	Ready   <-chan struct{}
	Service agentv1.BundleServiceServer

	started atomic.Bool
}

// Start implements manager.Runnable.
func (g *GRPCServer) Start(ctx context.Context) error {
	select {
	case <-g.Ready:
	case <-ctx.Done():
		return nil
	}
	cw, err := certwatcher.New(filepath.Join(g.CertDir, corev1.TLSCertKey), filepath.Join(g.CertDir, corev1.TLSPrivateKeyKey))
	if err != nil {
		return fmt.Errorf("distribution server certificate: %w", err)
	}
	go func() { _ = cw.Start(ctx) }()

	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cw.GetCertificate})),
		// Bundles flow out; engines only send small messages.
		grpc.MaxRecvMsgSize(64<<10),
		// Find dead connections, and refuse keepalive floods.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	agentv1.RegisterBundleServiceServer(srv, g.Service)
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%d", g.Port))
	if err != nil {
		return fmt.Errorf("distribution server: %w", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(lis) }()
	g.started.Store(true)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Engines reconnect to another replica; give streams a moment to end.
	done := make(chan struct{})
	go func() { srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		srv.Stop()
	}
	return nil
}

// NeedLeaderElection implements LeaderElectionRunnable: every replica
// serves.
func (*GRPCServer) NeedLeaderElection() bool { return false }

// Check is a readiness check: the server is listening.
func (g *GRPCServer) Check(*http.Request) error {
	if !g.started.Load() {
		return errors.New("distribution server not started")
	}
	return nil
}

// Report labels and keys of the replicas' engine ConfigMaps.
const (
	EnginesLabel     = "waf.inkwall.dev/engines"
	enginesKey       = "engines.json"
	updatedAtKey     = "updatedAt"
	reportNamePrefix = "inkwall-engines-"
)

// Publisher writes a replica's engines to its ConfigMap when they change,
// and at least every Refresh, so the leader can tell a live replica from
// a dead one.
type Publisher struct {
	Client client.Client
	// Reader reads uncached: the manager only caches ConfigMaps of rules.
	Reader    client.Reader
	Namespace string
	Replica   string
	// Owner, if set, is the replica's Pod: its ConfigMap goes with it.
	Owner    *metav1.OwnerReference
	Engines  *Table
	Interval time.Duration
	Refresh  time.Duration
}

// Start implements manager.Runnable.
func (p *Publisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("engine-report")
	var (
		lastGen   uint64
		lastWrite time.Time
		written   bool
	)
	tick := time.NewTicker(p.Interval)
	defer tick.Stop()
	for {
		engines, gen := p.Engines.Snapshot()
		if !written || gen != lastGen || time.Since(lastWrite) >= p.Refresh {
			if err := p.write(ctx, engines); err != nil {
				logger.Error(err, "can't publish the connected engines")
			} else {
				lastGen, lastWrite, written = gen, time.Now(), true
			}
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			// The engines reconnect elsewhere; don't leave them listed here.
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.name()}}
			_ = client.IgnoreNotFound(p.Client.Delete(dctx, cm))
			return nil
		}
	}
}

// NeedLeaderElection implements LeaderElectionRunnable.
func (*Publisher) NeedLeaderElection() bool { return false }

func (p *Publisher) name() string { return reportNamePrefix + p.Replica }

func (p *Publisher) write(ctx context.Context, engines []Engine) error {
	data, err := json.Marshal(engines)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.name()}
	err = p.Reader.Get(ctx, key, cm)
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
			Labels:    map[string]string{EnginesLabel: "true", "app.kubernetes.io/managed-by": "inkwall-operator"},
		}}
		if p.Owner != nil {
			cm.OwnerReferences = []metav1.OwnerReference{*p.Owner}
		}
		cm.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
		return p.Client.Create(ctx, cm)
	}
	if err != nil {
		return err
	}
	cm.Data = map[string]string{enginesKey: string(data), updatedAtKey: time.Now().UTC().Format(time.RFC3339Nano)}
	return p.Client.Update(ctx, cm)
}

// ReadEngines merges the replicas' reports, skipping those not refreshed
// within stale (their replica is gone). An engine listed twice, while it
// moves between replicas, counts once, with its newest connection.
func ReadEngines(ctx context.Context, c client.Reader, namespace string, stale time.Duration, now time.Time) ([]Engine, error) {
	var list corev1.ConfigMapList
	if err := c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{EnginesLabel: "true"}); err != nil {
		return nil, err
	}
	byID := map[string]Engine{}
	for _, cm := range list.Items {
		updated, err := time.Parse(time.RFC3339Nano, cm.Data[updatedAtKey])
		if err != nil || now.Sub(updated) > stale {
			continue
		}
		var engines []Engine
		if err := json.Unmarshal([]byte(cm.Data[enginesKey]), &engines); err != nil {
			continue
		}
		for _, e := range engines {
			if old, ok := byID[e.ID]; !ok || e.ConnectedAt.After(old.ConnectedAt) {
				byID[e.ID] = e
			}
		}
	}
	out := make([]Engine, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	return out, nil
}
