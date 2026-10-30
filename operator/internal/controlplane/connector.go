// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package controlplane connects the operator to the optional control plane
// (0002 §3.4, §5.3, §7.5; api/controlplane/v1). In GitOps and Managed mode
// the leader enrolls the cluster with a one-time token, keeps its client
// certificate in a Secret, renews it over the primary stream, sends the
// cluster's state (ClusterState) on change, in Managed mode writes the
// control plane's policy snapshots as CRDs, and reports
// ControlPlaneConnected on the InkwallConfig. Standalone runs none of it.
// Enforcement never depends on it.
package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The connector writes the InkwallConfig's status and replaces the identity
// Secret when the control plane rejects it.
//
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=inkwallconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",namespace=inkwall-system,resources=secrets,verbs=delete

// Reasons of the ControlPlaneConnected condition.
const (
	ReasonConnected            = "Connected"
	ReasonInvalidEndpoint      = "InvalidEndpoint"
	ReasonTokenSecretMissing   = "EnrollmentTokenMissing"
	ReasonTokenSecretElsewhere = "EnrollmentTokenNotInOperatorNamespace"
	ReasonTokenRejected        = "EnrollmentTokenRejected"
	ReasonEnrollFailed         = "EnrollFailed"
	ReasonCertificateRejected  = "CertificateRejected"
	ReasonCertificateExpired   = "CertificateExpired"
	ReasonClusterDisabled      = "ClusterDisabled"
	ReasonUnreachable          = "Unreachable"
)

// TokenKey is the key of the enrollment token in its Secret.
const TokenKey = "token" // #nosec G101 -- a data key, not a credential

// Limits of the contract: gzip, and messages up to 16 MiB.
const maxMessage = 16 << 20

// errIdle means nothing to do until the configuration or a Secret changes.
var errIdle = errors.New("idle")

// Connector keeps the cluster connected to the control plane. It runs on
// the leader.
type Connector struct {
	Client client.Client
	// APIReader reads the kube-system Namespace (its UID identifies the
	// cluster), which the manager doesn't cache, and what a policy snapshot
	// changes, as it is now.
	APIReader client.Reader
	// Namespace is the operator's: the identity Secret is there, and so must
	// the enrollment token be.
	Namespace       string
	Replica         string
	OperatorVersion string
	// KubernetesVersion returns the API server's version, for Hello.
	KubernetesVersion func() string
	// CAFile trusts the control plane's server certificate; empty: the
	// system roots.
	CAFile string

	// ProxyPods selects the proxies' pods, for ClusterState (default:
	// Traefik's default labels).
	ProxyPods labels.Selector
	// EngineStale is how old a replica's engine report may be before
	// ClusterState leaves it out (default 30 s).
	EngineStale time.Duration

	// Poll is how often an idle connector looks again (default 5 s);
	// MinBackoff and MaxBackoff bound reconnects (default 1 s and 1 min).
	Poll, MinBackoff, MaxBackoff time.Duration
	// StatePoll is how often the leader looks for a change to send
	// (default 5 s); StateResend, how often it sends ClusterState even
	// unchanged (default 5 min).
	StatePoll, StateResend time.Duration
	// ApplyBackoff paces the retries of a policy snapshot write that
	// failed after its dry run passed (default: about 15 s in all).
	ApplyBackoff wait.Backoff

	clusterUID string
	// enrollKey is kept per token, so a retry after a lost Enroll response
	// sends the same public key and gets the same certificate.
	enrollKey      *ecdsa.PrivateKey
	enrollKeyToken string
	// rejectedToken is a token that can't enroll (used or refused): wait for
	// another.
	rejectedToken string
	// disabled is set when the control plane refused the cluster: wait for
	// the configuration or the identity to change.
	disabled string
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (*Connector) NeedLeaderElection() bool { return true }

func (c *Connector) defaults() {
	if c.Poll == 0 {
		c.Poll = 5 * time.Second
	}
	if c.MinBackoff == 0 {
		c.MinBackoff = time.Second
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = time.Minute
	}
	if c.EngineStale == 0 {
		c.EngineStale = 30 * time.Second
	}
	if c.StatePoll == 0 {
		c.StatePoll = 5 * time.Second
	}
	if c.StateResend == 0 {
		c.StateResend = 5 * time.Minute
	}
	if c.ApplyBackoff.Steps == 0 {
		c.ApplyBackoff = defaultApplyBackoff
	}
}

// Start implements manager.Runnable.
func (c *Connector) Start(ctx context.Context) error {
	c.defaults()
	logger := log.FromContext(ctx).WithName("control-plane")
	backoff := c.MinBackoff
	for {
		connected, err := c.run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			backoff = c.MinBackoff
		}
		wait := c.Poll
		if !errors.Is(err, errIdle) {
			logger.Info("control plane connection ended; retrying", "error", err, "in", backoff)
			// Jitter, so clusters don't reconnect in lockstep after an outage.
			wait = backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not security
			backoff = min(2*backoff, c.MaxBackoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// run does one round: enroll if needed, then hold the primary stream open.
// It reports whether the stream was established.
func (c *Connector) run(ctx context.Context) (bool, error) {
	var cfg wafv1alpha1.InkwallConfig
	err := c.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg)
	if apierrors.IsNotFound(err) {
		return false, errIdle
	}
	if err != nil {
		return false, err
	}
	cp := cfg.Spec.ControlPlane
	if cfg.Spec.Mode == "" || cfg.Spec.Mode == wafv1alpha1.ModeStandalone || cp == nil {
		return false, c.clearCondition(ctx)
	}
	target, host, err := parseEndpoint(cp.Endpoint)
	if err != nil {
		return false, c.idle(ctx, &cfg, ReasonInvalidEndpoint, err.Error())
	}

	id, err := loadIdentity(ctx, c.Client, c.Namespace)
	if err != nil {
		log.FromContext(ctx).Error(err, "the identity Secret can't be used; enrolling again")
	}
	if id != nil && !time.Now().Before(id.notAfter) {
		// Offline longer than the certificate's lifetime: renewal needs a
		// valid certificate, so only a new token helps.
		c.rejectedToken = id.tokenHash
		if err := deleteIdentity(ctx, c.Client, c.Namespace); err != nil {
			return false, err
		}
		ref := cp.EnrollmentSecretRef
		if err := c.setCondition(ctx, &cfg, metav1.ConditionFalse, ReasonCertificateExpired, fmt.Sprintf(
			"the cluster's certificate expired on %s: store a new enrollment token in %s/%s",
			id.notAfter.UTC().Format(time.RFC3339), ref.Namespace, ref.Name)); err != nil {
			return false, err
		}
		id = nil
	}
	if id == nil {
		if id, err = c.enroll(ctx, &cfg, target, host); err != nil {
			return false, err
		}
	}
	if c.disabled == disabledKey(&cfg, id) {
		return false, errIdle
	}
	return c.connect(ctx, &cfg, target, host, id)
}

// enroll exchanges the token for the cluster's certificate.
func (c *Connector) enroll(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, target, host string) (*identity, error) {
	ref := cfg.Spec.ControlPlane.EnrollmentSecretRef
	if ref.Namespace != c.Namespace {
		return nil, c.idle(ctx, cfg, ReasonTokenSecretElsewhere, fmt.Sprintf(
			"the enrollment token Secret must be in the operator's namespace %s, not %s", c.Namespace, ref.Namespace))
	}
	var s corev1.Secret
	err := c.Client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &s)
	if apierrors.IsNotFound(err) || (err == nil && len(s.Data[TokenKey]) == 0) {
		return nil, c.idle(ctx, cfg, ReasonTokenSecretMissing, fmt.Sprintf("Secret %s/%s has no %q key", ref.Namespace, ref.Name, TokenKey))
	}
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(string(s.Data[TokenKey]))
	h := tokenHash(token)
	if h == c.rejectedToken {
		return nil, errIdle // the condition already says why
	}
	if c.enrollKeyToken != h {
		if c.enrollKey, err = newKey(); err != nil {
			return nil, err
		}
		c.enrollKeyToken = h
	}
	csr, err := newCSR(c.enrollKey)
	if err != nil {
		return nil, err
	}
	uid, err := c.uid(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(target, host, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := controlplanev1.NewControlPlaneServiceClient(conn).Enroll(rctx, &controlplanev1.EnrollRequest{
		Token: token, Csr: csr, ClusterUid: uid, OperatorVersion: c.OperatorVersion,
	})
	switch status.Code(err) {
	case codes.OK:
	case codes.PermissionDenied:
		c.rejectedToken = h
		return nil, c.idle(ctx, cfg, ReasonTokenRejected, "the enrollment token was refused (unknown, expired or already used): store a new one in "+ref.Namespace+"/"+ref.Name)
	default:
		_ = c.setCondition(ctx, cfg, metav1.ConditionFalse, ReasonEnrollFailed, "enrolling: "+err.Error())
		return nil, err
	}
	id, err := newIdentity(resp.GetClusterId(), resp.GetCertificates(), c.enrollKey, h)
	if err != nil {
		return nil, fmt.Errorf("enroll response: %w", err)
	}
	if err := storeIdentity(ctx, c.Client, c.Namespace, id); err != nil {
		return nil, err
	}
	c.enrollKey, c.enrollKeyToken = nil, ""
	log.FromContext(ctx).Info("cluster enrolled", "clusterID", id.clusterID, "notAfter", id.notAfter)
	return id, nil
}

// connect holds the primary stream open: Hello, Welcome, ClusterState,
// heartbeats and certificate renewal.
func (c *Connector) connect(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, target, host string, id *identity) (bool, error) {
	conn, err := c.dial(target, host, &id.cert)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := controlplanev1.NewControlPlaneServiceClient(conn).Connect(sctx)
	if err != nil {
		return false, c.streamError(ctx, cfg, id, false, err)
	}
	uid, err := c.uid(ctx)
	if err != nil {
		return false, err
	}
	mode := controlplanev1.ClusterMode_CLUSTER_MODE_GITOPS
	if cfg.Spec.Mode == wafv1alpha1.ModeManaged {
		mode = controlplanev1.ClusterMode_CLUSTER_MODE_MANAGED
	}
	var k8s string
	if c.KubernetesVersion != nil {
		k8s = c.KubernetesVersion()
	}
	if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_Hello{Hello: &controlplanev1.Hello{
		Role:              controlplanev1.StreamRole_STREAM_ROLE_PRIMARY,
		Replica:           c.Replica,
		OperatorVersion:   c.OperatorVersion,
		Mode:              mode,
		ClusterUid:        uid,
		KubernetesVersion: k8s,
		PolicyVersion:     id.policyVersion,
		Capabilities:      []string{wafv1alpha1.GroupVersion.String()},
	}}}); err != nil {
		return false, c.streamError(ctx, cfg, id, false, err)
	}
	first, err := stream.Recv()
	if err != nil {
		return false, c.streamError(ctx, cfg, id, false, err)
	}
	welcome := first.GetWelcome()
	if welcome == nil {
		return false, errors.New("the control plane didn't answer Hello with Welcome")
	}
	if err := c.setCondition(ctx, cfg, metav1.ConditionTrue, ReasonConnected, connectedMessage(id)); err != nil {
		return true, err
	}
	states := &stateSender{resend: c.StateResend}
	if err := c.sendState(ctx, stream, states, true); err != nil {
		return true, c.streamError(ctx, cfg, id, true, err)
	}

	msgs := make(chan *controlplanev1.ConnectResponse)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-sctx.Done():
				return
			}
		}
	}()

	interval := 30 * time.Second
	if d := welcome.GetHeartbeatInterval().AsDuration(); d > 0 {
		interval = d
	}
	heartbeat := time.NewTicker(interval)
	defer heartbeat.Stop()
	// Configuration changes (endpoint, mode) take a new stream.
	reconfigure := time.NewTicker(c.Poll)
	defer reconfigure.Stop()
	renew := time.NewTimer(time.Until(id.renewAt()))
	defer renew.Stop()
	state := time.NewTicker(c.StatePoll)
	defer state.Stop()
	var pending *ecdsa.PrivateKey

	// Policy snapshots are applied beside the stream, which keeps its
	// heartbeats meanwhile; snapshots holds the next one.
	snapshots := make(chan *controlplanev1.PolicySnapshot, 1)
	replies := make(chan reply)
	go (&applier{
		client: c.Client, reader: c.APIReader, namespace: c.Namespace,
		applied: id.policyVersion, backoff: c.ApplyBackoff,
	}).run(sctx, snapshots, replies)

	for {
		select {
		case <-ctx.Done():
			return true, nil
		case err := <-recvErr:
			return true, c.streamError(ctx, cfg, id, true, err)
		case r := <-replies:
			if r.err != nil {
				// Partly written: reconnect, and the control plane sends the
				// snapshot again.
				return true, r.err
			}
			if err := stream.Send(r.msg); err != nil {
				return true, c.streamError(ctx, cfg, id, true, err)
			}
		case <-heartbeat.C:
			if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_Heartbeat{
				Heartbeat: &controlplanev1.Heartbeat{Time: timestamppb.Now()},
			}}); err != nil {
				return true, c.streamError(ctx, cfg, id, true, err)
			}
		case <-state.C:
			if err := c.sendState(ctx, stream, states, false); err != nil {
				return true, c.streamError(ctx, cfg, id, true, err)
			}
		case <-reconfigure.C:
			var now wafv1alpha1.InkwallConfig
			if err := c.Client.Get(ctx, types.NamespacedName{Name: "default"}, &now); err != nil || now.Generation != cfg.Generation {
				return true, errors.New("configuration changed")
			}
		case <-renew.C:
			if pending, err = newKey(); err != nil {
				return true, err
			}
			csr, err := newCSR(pending)
			if err != nil {
				return true, err
			}
			if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_RenewCertificate{
				RenewCertificate: &controlplanev1.RenewCertificate{Csr: csr},
			}}); err != nil {
				return true, c.streamError(ctx, cfg, id, true, err)
			}
			// Ask again if no certificate comes back.
			renew.Reset(time.Minute)
		case m := <-msgs:
			switch msg := m.GetMsg().(type) {
			case *controlplanev1.ConnectResponse_Certificate:
				if pending == nil {
					continue
				}
				next, err := newIdentity(id.clusterID, msg.Certificate.GetCertificates(), pending, id.tokenHash)
				if err != nil {
					return true, fmt.Errorf("renewed certificate: %w", err)
				}
				if err := storeIdentity(ctx, c.Client, c.Namespace, next); err != nil {
					return true, err
				}
				id, pending = next, nil
				renew.Reset(time.Until(id.renewAt()))
				log.FromContext(ctx).Info("control plane certificate renewed", "notAfter", id.notAfter)
				if err := c.setCondition(ctx, cfg, metav1.ConditionTrue, ReasonConnected, connectedMessage(id)); err != nil {
					return true, err
				}
			case *controlplanev1.ConnectResponse_Directive:
				if msg.Directive.GetResync() == nil {
					continue
				}
				if err := c.sendState(ctx, stream, states, true); err != nil {
					return true, c.streamError(ctx, cfg, id, true, err)
				}
			case *controlplanev1.ConnectResponse_PolicySnapshot:
				// A snapshot still waiting is replaced: the newer one has
				// everything.
				select {
				case old := <-snapshots:
					if err := stream.Send(nack(old.GetVersion(), fmt.Sprintf(
						"superseded by snapshot %d before it was applied: nothing was written", msg.PolicySnapshot.GetVersion()))); err != nil {
						return true, c.streamError(ctx, cfg, id, true, err)
					}
				default:
				}
				snapshots <- msg.PolicySnapshot
			}
		}
	}
}

// sendState sends ClusterState when it changed, is due, or force is set.
// A snapshot that can't be built is logged and skipped: the stream stays
// up, and the next tick tries again. Only a failed send ends the stream.
func (c *Connector) sendState(ctx context.Context, stream grpc.BidiStreamingClient[controlplanev1.ConnectRequest, controlplanev1.ConnectResponse], s *stateSender, force bool) error {
	st, err := c.clusterState(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "can't build the cluster state for the control plane")
		return nil
	}
	send, sum := s.changed(st, force)
	if !send {
		return nil
	}
	if err := stream.Send(&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_ClusterState{ClusterState: st}}); err != nil {
		return err
	}
	s.last, s.sentAt = sum, time.Now()
	return nil
}

// streamError reports why the stream ended, and decides what comes next
// from the gRPC status, as the contract says.
func (c *Connector) streamError(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, id *identity, established bool, err error) error {
	if ctx.Err() != nil {
		return err
	}
	switch status.Code(err) {
	case codes.Unauthenticated:
		// The certificate isn't valid any more; its token is used up.
		c.rejectedToken = id.tokenHash
		if derr := deleteIdentity(ctx, c.Client, c.Namespace); derr != nil {
			return derr
		}
		return c.idle(ctx, cfg, ReasonCertificateRejected, "the control plane rejected the cluster's certificate: store a new enrollment token in "+
			cfg.Spec.ControlPlane.EnrollmentSecretRef.Namespace+"/"+cfg.Spec.ControlPlane.EnrollmentSecretRef.Name)
	case codes.PermissionDenied:
		c.disabled = disabledKey(cfg, id)
		return c.idle(ctx, cfg, ReasonClusterDisabled, "the control plane removed or disabled this cluster; change the configuration to try again")
	}
	if !established {
		_ = c.setCondition(ctx, cfg, metav1.ConditionFalse, ReasonUnreachable, err.Error())
	} else {
		_ = c.setCondition(ctx, cfg, metav1.ConditionFalse, ReasonUnreachable, "stream ended: "+err.Error())
	}
	return err
}

func disabledKey(cfg *wafv1alpha1.InkwallConfig, id *identity) string {
	return fmt.Sprintf("%d/%x", cfg.Generation, id.cert.Leaf.SerialNumber)
}

func connectedMessage(id *identity) string {
	return fmt.Sprintf("connected as cluster %s; certificate valid until %s", id.clusterID, id.notAfter.UTC().Format(time.RFC3339))
}

// dial connects to the control plane over TLS, with the cluster's
// certificate when there is one (Connect) and without (Enroll).
func (c *Connector) dial(target, host string, cert *tls.Certificate) (*grpc.ClientConn, error) {
	return dial(c.CAFile, target, host, cert)
}

// dial connects to the control plane at target over TLS, trusting caFile
// (empty: the system roots).
func dial(caFile, target, host string, cert *tls.Certificate) (*grpc.ClientConn, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(filepath.Clean(caFile))
		if err != nil {
			return nil, fmt.Errorf("control plane CA: %w", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("control plane CA %s: no PEM certificate", caFile)
		}
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.WithDefaultCallOptions(
			grpc.UseCompressor(gzip.Name),
			grpc.MaxCallRecvMsgSize(maxMessage),
			grpc.MaxCallSendMsgSize(maxMessage),
		),
	)
}

// parseEndpoint reads grpcs://host:port.
func parseEndpoint(endpoint string) (target, host string, err error) {
	rest, ok := strings.CutPrefix(endpoint, "grpcs://")
	if !ok {
		return "", "", fmt.Errorf("endpoint %q: want grpcs://host:port", endpoint)
	}
	host, _, err = net.SplitHostPort(rest)
	if err != nil || host == "" {
		return "", "", fmt.Errorf("endpoint %q: want grpcs://host:port", endpoint)
	}
	return rest, host, nil
}

// uid is the kube-system Namespace UID, which also identifies the cluster
// in bundles.
func (c *Connector) uid(ctx context.Context) (string, error) {
	if c.clusterUID == "" {
		var ns corev1.Namespace
		if err := c.APIReader.Get(ctx, types.NamespacedName{Name: "kube-system"}, &ns); err != nil {
			return "", fmt.Errorf("read the cluster ID (kube-system UID): %w", err)
		}
		c.clusterUID = string(ns.UID)
	}
	return c.clusterUID, nil
}

// idle reports why the connector waits, and waits.
func (c *Connector) idle(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, reason, message string) error {
	if err := c.setCondition(ctx, cfg, metav1.ConditionFalse, reason, message); err != nil {
		return err
	}
	return errIdle
}

func (c *Connector) setCondition(ctx context.Context, cfg *wafv1alpha1.InkwallConfig, st metav1.ConditionStatus, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur wafv1alpha1.InkwallConfig
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(cfg), &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if !meta.SetStatusCondition(&cur.Status.Conditions, metav1.Condition{
			Type: wafv1alpha1.ConditionControlPlaneConnected, Status: st, Reason: reason, Message: message,
			ObservedGeneration: cur.Generation,
		}) {
			return nil
		}
		return c.Client.Status().Update(ctx, &cur)
	})
}

// clearCondition removes ControlPlaneConnected in Standalone mode.
func (c *Connector) clearCondition(ctx context.Context) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur wafv1alpha1.InkwallConfig
		if err := c.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if !meta.RemoveStatusCondition(&cur.Status.Conditions, wafv1alpha1.ConditionControlPlaneConnected) {
			return nil
		}
		return c.Client.Status().Update(ctx, &cur)
	})
	if err != nil {
		return err
	}
	return errIdle
}
