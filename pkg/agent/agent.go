// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent connects the engine to the operator (0002 §5.2): it keeps
// one stream open, verifies and applies every bundle the operator sends, and
// reports what it applied. Without the operator the engine keeps enforcing
// the last bundle it applied, also across restarts through an on-disk cache;
// a new engine with no cache reads the bundle Secret instead.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/bundlekey"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// Defaults of the Agent.
const (
	DefaultHeartbeat  = 5 * time.Second
	DefaultMinBackoff = time.Second
	DefaultMaxBackoff = 30 * time.Second
	// DefaultKeyReload is how often the public key file is checked for
	// changes: the kubelet updates a mounted ConfigMap within a minute or
	// two, and the operator waits for every engine to report a new key
	// before it signs with it.
	DefaultKeyReload = 10 * time.Second
	// eventBatch keeps a batch of events well under gRPC's default 4 MiB
	// message limit at the contract's field limits.
	eventBatch = 256
)

// Config configures an Agent.
type Config struct {
	// Addr is the operator's distribution server, host:port.
	Addr string
	// CAFile verifies the operator's certificate; ServerName overrides the
	// name checked (default: the host of Addr).
	CAFile     string
	ServerName string
	// TokenFile holds the projected ServiceAccount token, re-read on every
	// connection since the kubelet rotates it.
	TokenFile string
	// PublicKeyFile holds the ed25519 public keys bundles may be signed
	// with: one or more raw 32-byte keys, concatenated (the trust
	// ConfigMap's trusted-keys.pub; a single key, as ed25519.pub, works
	// too). It is re-read every KeyReload, so the keys rotate without a
	// restart.
	PublicKeyFile string
	// CacheFile, if set, keeps the last applied bundle, so a restarted
	// engine enforces it before the operator is reachable.
	CacheFile string
	// Secret, if set, is read when the engine has no bundle: at startup
	// without a usable cache, and between attempts to reach the operator
	// until a bundle is applied.
	Secret *SecretSource

	EngineID      string
	PodNamespace  string
	PodName       string
	NodeName      string
	EngineVersion string

	// Compile turns a bundle into a policy set (policy.Compile with the
	// engine's options); Holder serves the applied set.
	Compile func(*bundlev1.Bundle) (*policy.Set, error)
	Holder  *policy.Holder
	// Admission is reported in heartbeats.
	Admission *pipeline.Admission
	// Events holds the security events to send to the operator (nil:
	// none).
	Events *events.Buffer

	Logger     *slog.Logger
	Heartbeat  time.Duration
	MinBackoff time.Duration
	MaxBackoff time.Duration
	KeyReload  time.Duration
}

// errUnknownKey rejects a bundle signed with a key the engine doesn't
// trust (yet): during a key rotation, the key file may lag.
var errUnknownKey = errors.New("signed with a key this engine doesn't trust")

// keySet is the trusted public keys, by key ID.
type keySet struct {
	byID map[string]ed25519.PublicKey
	// ids, sorted, as reported to the operator.
	ids []string
}

func parseKeys(data []byte) (*keySet, error) {
	keys, err := bundlekey.Parse(data)
	if err != nil {
		return nil, err
	}
	ks := &keySet{byID: map[string]ed25519.PublicKey{}}
	for _, k := range keys {
		id := bundlekey.ID(k)
		if _, dup := ks.byID[id]; !dup {
			ks.byID[id] = k
			ks.ids = append(ks.ids, id)
		}
	}
	slices.Sort(ks.ids)
	return ks, nil
}

// verify checks a bundle's signature with the key its key_id names. A
// bundle without a key ID (none is sent today) is checked against every
// trusted key: any of them is as good.
func (ks *keySet) verify(signed *bundlev1.SignedBundle) error {
	if id := signed.GetKeyId(); id != "" {
		key, ok := ks.byID[id]
		if !ok {
			return fmt.Errorf("%w: key %q, trusted %q", errUnknownKey, id, ks.ids)
		}
		if !ed25519.Verify(key, signed.GetBundle(), signed.GetSignature()) {
			return fmt.Errorf("bad signature (key %q)", id)
		}
		return nil
	}
	for _, key := range ks.byID {
		if ed25519.Verify(key, signed.GetBundle(), signed.GetSignature()) {
			return nil
		}
	}
	return errors.New("bad signature (no key ID)")
}

// Agent keeps the engine's policy in sync with the operator.
type Agent struct {
	cfg Config
	log *slog.Logger

	keys atomic.Pointer[keySet]
	// keyFile is the key file's content last read, by the reload loop.
	keyFile []byte
	// unknownKey is set when a bundle was rejected for its key: a reload
	// that changes the keys then reconnects, to be sent it again.
	unknownKey atomic.Bool
	reconnect  chan struct{}

	mu sync.Mutex
	// current is the applied bundle, nil before the first.
	current *bundlev1.Bundle
	// applied is closed when the first bundle is applied.
	applied chan struct{}
	// cacheOnce loads the cache once: LoadCache, or else Run.
	cacheOnce sync.Once

	connected prometheus.Gauge
	version   prometheus.Gauge
	applies   *prometheus.CounterVec
}

// New checks cfg and reads the public keys.
func New(cfg Config) (*Agent, error) {
	if cfg.Addr == "" || cfg.CAFile == "" || cfg.TokenFile == "" || cfg.PublicKeyFile == "" {
		return nil, errors.New("the operator address, CA, token and public key files are all required")
	}
	if cfg.Compile == nil || cfg.Holder == nil || cfg.EngineID == "" {
		return nil, errors.New("the Compile function, Holder and engine ID are required")
	}
	keyFile, err := os.ReadFile(filepath.Clean(cfg.PublicKeyFile))
	if err != nil {
		return nil, fmt.Errorf("bundle public keys: %w", err)
	}
	keys, err := parseKeys(keyFile)
	if err != nil {
		return nil, fmt.Errorf("bundle public keys %s: %w", cfg.PublicKeyFile, err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = DefaultHeartbeat
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = DefaultMinBackoff
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.KeyReload == 0 {
		cfg.KeyReload = DefaultKeyReload
	}
	a := &Agent{
		cfg:       cfg,
		log:       cfg.Logger.With(slog.String("component", "agent")),
		keyFile:   keyFile,
		reconnect: make(chan struct{}, 1),
		applied:   make(chan struct{}),
		connected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "inkwall_operator_connected",
			Help: "1 while the engine has a stream open to the operator.",
		}),
		version: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "inkwall_bundle_version",
			Help: "Version of the bundle the engine enforces; 0 before the first.",
		}),
		applies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "inkwall_bundle_updates_total",
			Help: "Bundles received, by result: applied, or rejected (bad signature, older, doesn't compile).",
		}, []string{"result"}),
	}
	a.keys.Store(keys)
	return a, nil
}

// TrustedKeys returns the IDs of the public keys bundles are verified with.
func (a *Agent) TrustedKeys() []string { return slices.Clone(a.keys.Load().ids) }

// Collectors returns the agent's metrics, to register with the engine's.
func (a *Agent) Collectors() []prometheus.Collector {
	return []prometheus.Collector{a.connected, a.version, a.applies}
}

// Version returns the applied bundle's version, 0 before the first.
func (a *Agent) Version() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current.GetVersion()
}

// Applied is closed once a bundle is applied: the cached one, the
// Secret's or the operator's.
func (a *Agent) Applied() <-chan struct{} { return a.applied }

// LoadCache applies the cached bundle, if there is a valid one, and
// reports whether a bundle is applied. Only the first call (of LoadCache or
// Run) reads the cache. The engine calls it before it serves, so a
// restarted engine never answers before it enforces the cached bundle.
func (a *Agent) LoadCache() bool {
	a.cacheOnce.Do(a.loadCache)
	return a.Version() != 0
}

// Run loads the cached bundle (unless LoadCache did), or else the bundle
// Secret's, then keeps a stream to the operator open until ctx ends,
// reconnecting with backoff.
func (a *Agent) Run(ctx context.Context) error {
	go a.watchKeys(ctx)
	a.LoadCache()
	a.loadSecret(ctx)
	backoff := a.cfg.MinBackoff
	for {
		start := time.Now()
		err := a.stream(ctx)
		a.connected.Set(0)
		if ctx.Err() != nil {
			return nil
		}
		// Still nothing to enforce, and the operator is unreachable: the
		// Secret may be readable by now.
		a.loadSecret(ctx)
		// A stream that lasted resets the backoff.
		if time.Since(start) > a.cfg.MaxBackoff {
			backoff = a.cfg.MinBackoff
		}
		a.log.Warn("operator stream ended; reconnecting", slog.Any("error", err), slog.Duration("in", backoff))
		// Jitter, so engines don't reconnect in lockstep after an outage.
		wait := backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not security
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
		backoff = min(2*backoff, a.cfg.MaxBackoff)
	}
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}

func (bearer) RequireTransportSecurity() bool { return true }

func (a *Agent) dial() (*grpc.ClientConn, error) {
	token, err := os.ReadFile(filepath.Clean(a.cfg.TokenFile))
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	ca, err := os.ReadFile(filepath.Clean(a.cfg.CAFile))
	if err != nil {
		return nil, fmt.Errorf("operator CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("operator CA %s: no PEM certificate", a.cfg.CAFile)
	}
	return grpc.NewClient(a.cfg.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: roots, ServerName: a.cfg.ServerName, MinVersion: tls.VersionTLS12,
		})),
		grpc.WithPerRPCCredentials(bearer(bytes.TrimSpace(token))),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	)
}

func (a *Agent) stream(ctx context.Context) error {
	conn, err := a.dial()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := agentv1.NewBundleServiceClient(conn).Watch(ctx)
	if err != nil {
		return err
	}
	var sendMu sync.Mutex
	send := func(m *agentv1.WatchRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}
	// This stream's Hello gets the current bundle anyway.
	select {
	case <-a.reconnect:
	default:
	}
	if err := sendFirst(stream, &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Hello{Hello: &agentv1.Hello{
		EngineId:      a.cfg.EngineID,
		PodNamespace:  a.cfg.PodNamespace,
		PodName:       a.cfg.PodName,
		NodeName:      a.cfg.NodeName,
		BundleVersion: a.Version(),
		EngineVersion: a.cfg.EngineVersion,
		TrustedKeyIds: a.TrustedKeys(),
	}}}); err != nil {
		return err
	}
	// A bundle was rejected for its key, and the keys changed since: a new
	// stream gets it again (the operator sends a version only once).
	go func() {
		select {
		case <-a.reconnect:
			a.log.Info("bundle keys changed after a bundle was rejected for its key; reconnecting")
			cancel()
		case <-ctx.Done():
		}
	}()

	if buf := a.cfg.Events; buf != nil {
		go func() {
			for {
				batch := buf.Next(ctx, eventBatch)
				if batch == nil {
					return
				}
				if send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Events{Events: batch}}) != nil {
					// Kept for the next stream.
					buf.Return(batch)
					cancel()
					return
				}
			}
		}()
	}

	go func() {
		t := time.NewTicker(a.cfg.Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				hb := &agentv1.Heartbeat{BundleVersion: a.Version(), TrustedKeyIds: a.TrustedKeys()}
				if adm := a.cfg.Admission; adm != nil {
					hb.InFlight, hb.Capacity = uint32(adm.InFlight()), uint32(adm.Capacity()) // #nosec G115 -- small counts
				}
				if send(&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Heartbeat{Heartbeat: hb}}) != nil {
					cancel()
					return
				}
				// The operator sends nothing to an engine that is current:
				// a heartbeat that goes through also shows the stream is up.
				a.connected.Set(1)
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		a.connected.Set(1)
		signed := msg.GetBundle()
		if signed == nil {
			continue
		}
		version, err := a.apply(signed, true)
		reply := &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Ack{Ack: &agentv1.Ack{BundleVersion: version}}}
		if err != nil {
			a.log.Error("bundle rejected", slog.Uint64("version", version), slog.Any("error", err))
			reply = &agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Nack{Nack: &agentv1.Nack{BundleVersion: version, Error: err.Error()}}}
		}
		if err := send(reply); err != nil {
			return err
		}
	}
}

// sendFirst sends a stream's first message. The operator may have ended the
// stream already (it rejected the engine): Send then only says io.EOF, and
// the reason, such as PermissionDenied, comes with Recv.
func sendFirst(stream agentv1.BundleService_WatchClient, m *agentv1.WatchRequest) error {
	err := stream.Send(m)
	if errors.Is(err, io.EOF) {
		_, err = stream.Recv()
	}
	return err
}

// apply verifies, compiles and activates a bundle, returning its version
// (0 if it can't be read) and why it was rejected. The current set stays
// active on any error.
func (a *Agent) apply(signed *bundlev1.SignedBundle, cache bool) (uint64, error) {
	// Verify before decoding: nothing in an unverified bundle, its version
	// included, can be trusted.
	keys := a.keys.Load()
	if err := keys.verify(signed); err != nil {
		a.applies.WithLabelValues("rejected").Inc()
		if errors.Is(err, errUnknownKey) {
			a.unknownKey.Store(true)
			if a.keys.Load() != keys {
				// Reloaded meanwhile: the reload may have missed the flag.
				a.requestReconnect()
			}
		}
		return 0, err
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		a.applies.WithLabelValues("rejected").Inc()
		return 0, fmt.Errorf("decode: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.current
	switch {
	case cur != nil && bytes.Equal(cur.GetContentHash(), b.GetContentHash()) && len(b.GetContentHash()) > 0:
		// Already enforced (e.g. resent after a reconnect, or signed again
		// with a new key): nothing to compile, but report its version from
		// now on, and cache it, so a restart doesn't need the old key.
		a.current = &b
		a.version.Set(float64(b.GetVersion()))
		a.unknownKey.Store(false)
		a.cacheBundle(cache, signed)
		return b.GetVersion(), nil
	case cur != nil && b.GetVersion() < cur.GetVersion() && !b.GetCreatedAt().AsTime().After(cur.GetCreatedAt().AsTime()):
		// Never go back, unless the bundle is newer than ours: the operator
		// then lost its version sequence (bundle Secret deleted and leader
		// restarted) and starts again.
		a.applies.WithLabelValues("rejected").Inc()
		return b.GetVersion(), fmt.Errorf("version %d is older than the applied %d", b.GetVersion(), cur.GetVersion())
	}
	set, err := a.cfg.Compile(&b)
	if err != nil {
		a.applies.WithLabelValues("rejected").Inc()
		return b.GetVersion(), err
	}
	a.cfg.Holder.Store(set)
	if a.current == nil {
		close(a.applied)
	}
	a.current = &b
	a.version.Set(float64(b.GetVersion()))
	a.unknownKey.Store(false)
	a.applies.WithLabelValues("applied").Inc()
	a.log.Info("bundle applied", slog.Uint64("version", b.GetVersion()), slog.Int("policies", set.Policies()), slog.Bool("suspended", b.GetSuspended()))
	a.cacheBundle(cache, signed)
	return b.GetVersion(), nil
}

func (a *Agent) cacheBundle(cache bool, signed *bundlev1.SignedBundle) {
	if !cache || a.cfg.CacheFile == "" {
		return
	}
	if err := writeCache(a.cfg.CacheFile, signed); err != nil {
		// The bundle is applied; only a restart without the operator
		// would miss it.
		a.log.Warn("can't cache the bundle", slog.Any("error", err))
	}
}

// watchKeys reloads the public keys when their file changes, until ctx
// ends.
func (a *Agent) watchKeys(ctx context.Context) {
	t := time.NewTicker(a.cfg.KeyReload)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.reloadKeys()
		case <-ctx.Done():
			return
		}
	}
}

// reloadKeys re-reads the key file. A file that can't be read or parsed
// (the kubelet swaps it atomically, so it shouldn't be) keeps the keys in
// use.
func (a *Agent) reloadKeys() {
	data, err := os.ReadFile(filepath.Clean(a.cfg.PublicKeyFile))
	if err != nil {
		a.log.Warn("can't read the bundle public keys; keeping the current ones", slog.Any("error", err))
		return
	}
	if bytes.Equal(data, a.keyFile) {
		return
	}
	a.keyFile = data
	keys, err := parseKeys(data)
	if err != nil {
		a.log.Warn("bundle public keys not reloaded; keeping the current ones", slog.String("file", a.cfg.PublicKeyFile), slog.Any("error", err))
		return
	}
	a.keys.Store(keys)
	a.log.Info("bundle public keys reloaded", slog.Any("trusted", keys.ids))
	if a.unknownKey.Swap(false) {
		a.requestReconnect()
	}
}

func (a *Agent) requestReconnect() {
	select {
	case a.reconnect <- struct{}{}:
	default:
	}
}

// loadCache applies the cached bundle, if there is a valid one.
func (a *Agent) loadCache() {
	if a.cfg.CacheFile == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Clean(a.cfg.CacheFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var signed bundlev1.SignedBundle
	if err == nil {
		err = proto.Unmarshal(raw, &signed)
	}
	if err == nil {
		var version uint64
		version, err = a.apply(&signed, false)
		if err == nil {
			a.log.Info("cached bundle applied", slog.Uint64("version", version))
			return
		}
	}
	a.log.Warn("cached bundle not usable; waiting for the operator", slog.String("file", a.cfg.CacheFile), slog.Any("error", err))
}

// loadSecret applies the bundle Secret's bundle, if the engine has none.
func (a *Agent) loadSecret(ctx context.Context) {
	if a.cfg.Secret == nil || a.Version() != 0 || ctx.Err() != nil {
		return
	}
	signed, err := a.cfg.Secret.fetch(ctx)
	if err == nil {
		var version uint64
		// Cached, so a restart doesn't need the Secret again.
		version, err = a.apply(signed, true)
		if err == nil {
			a.log.Info("bundle applied from the Secret", slog.String("secret", a.cfg.Secret.Namespace+"/"+a.cfg.Secret.Name), slog.Uint64("version", version))
			return
		}
	}
	if ctx.Err() == nil {
		a.log.Warn("can't read the bundle Secret; waiting for the operator", slog.String("secret", a.cfg.Secret.Namespace+"/"+a.cfg.Secret.Name), slog.Any("error", err))
	}
}

// writeCache replaces the cache file atomically.
func writeCache(name string, signed *bundlev1.SignedBundle) error {
	raw, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".bundle-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
